// Package awsread reads what one reconcile pass needs, read-only: the
// signer's journal and KMS's Sign calls (from the trail's log group), the
// trail's status, the claim table, what the votes site holds, and the
// signer function as deployed.
package awsread

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/reconcile"
	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

// LogsAPI is the CloudWatch Logs call a pass makes.
type LogsAPI interface {
	FilterLogEvents(ctx context.Context, in *cloudwatchlogs.FilterLogEventsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error)
}

// maxEvents bounds a period's read, and maxHistoryEvents the journal's
// whole retention (above the signs_per_hour alarm's 20 an hour for a
// year, with their completions): past either the pass reports itself
// incomplete rather than check part of what it reads.
const (
	maxEvents        = 100000
	maxHistoryEvents = 400000
)

// read is one FilterLogEvents read.
type read struct {
	group        string
	streams      []string // exactly these streams; or
	streamPrefix string   // the streams with this prefix
	pattern      string
	from, to     time.Time
	max          int
}

// event is one log event as a pass sees it: its message, its ingestion
// time (set by CloudWatch Logs; zero when the service didn't say), and
// its stream.
type event struct {
	msg      string
	ingested time.Time
	stream   string
}

func filter(ctx context.Context, c LogsAPI, r read, each func(event) error) error {
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(r.group), StartTime: aws.Int64(r.from.UnixMilli()), EndTime: aws.Int64(r.to.UnixMilli()),
	}
	switch {
	case len(r.streams) > 0:
		in.LogStreamNames = r.streams
	case r.streamPrefix != "":
		in.LogStreamNamePrefix = aws.String(r.streamPrefix)
	}
	if r.pattern != "" {
		in.FilterPattern = aws.String(r.pattern)
	}
	n := 0
	for {
		out, err := c.FilterLogEvents(ctx, in)
		if err != nil {
			return err
		}
		for _, e := range out.Events {
			if n++; n > r.max {
				return fmt.Errorf("more than %d events in %s", r.max, r.group)
			}
			var ingested time.Time
			if e.IngestionTime != nil {
				ingested = time.UnixMilli(*e.IngestionTime)
			}
			if err := each(event{msg: aws.ToString(e.Message), ingested: ingested, stream: aws.ToString(e.LogStreamName)}); err != nil {
				return err
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(in.NextToken) {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

// Entries is what a journal read found.
type Entries struct {
	Signs       []signer.SignEntry
	Completions []signer.CompletionEntry
	Notes       []signer.NoteEntry
	// Ingested is each sign entry's ingestion time (set by CloudWatch
	// Logs, not by the writer), by reconcile.SignKey: the earliest seen.
	Ingested map[string]time.Time
	// Unreadable describes each entry that couldn't be decoded: the read
	// goes on past it, and the pass reports it.
	Unreadable []string
}

func (es *Entries) add(ev event) {
	msg := ev.msg
	var k struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(msg), &k); err != nil {
		es.Unreadable = append(es.Unreadable, "an entry that isn't JSON")
		return
	}
	dec := json.NewDecoder(strings.NewReader(msg))
	switch k.Kind {
	case "sign":
		var e struct {
			Kind string `json:"kind"`
			signer.SignEntry
		}
		if err := dec.Decode(&e); err != nil {
			es.Unreadable = append(es.Unreadable, "a sign entry: "+err.Error())
			return
		}
		es.Signs = append(es.Signs, e.SignEntry)
		if k := reconcile.SignKey(e.SignEntry); !ev.ingested.IsZero() && (es.Ingested[k].IsZero() || ev.ingested.Before(es.Ingested[k])) {
			es.Ingested[k] = ev.ingested
		}
	case "complete":
		var e struct {
			Kind string `json:"kind"`
			signer.CompletionEntry
		}
		if err := dec.Decode(&e); err != nil {
			es.Unreadable = append(es.Unreadable, "a completion entry: "+err.Error())
			return
		}
		es.Completions = append(es.Completions, e.CompletionEntry)
	case "note":
		var e struct {
			Kind string `json:"kind"`
			signer.NoteEntry
		}
		if err := dec.Decode(&e); err != nil {
			es.Unreadable = append(es.Unreadable, "a note: "+err.Error())
			return
		}
		es.Notes = append(es.Notes, e.NoteEntry)
	default:
		es.Unreadable = append(es.Unreadable, fmt.Sprintf("an entry of kind %q", k.Kind))
	}
}

// Journal reads the signer's journal for the period: one JSON event per
// entry, {"kind": "sign" | "note" | "complete", ...}. An entry it can't
// decode is listed in Unreadable, and the read goes on; a failed read is
// an error (the journal not read).
func Journal(ctx context.Context, c LogsAPI, group, stream string, from, to time.Time) (*Entries, error) {
	es := &Entries{Ingested: map[string]time.Time{}}
	err := filter(ctx, c, read{group: group, streams: []string{stream}, from: from, to: to, max: maxEvents},
		func(ev event) error { es.add(ev); return nil })
	return es, err
}

// HistoryPattern selects the journal's sign and completion entries.
const HistoryPattern = `{ ($.kind = "sign") || ($.kind = "complete") }`

// History reads the journal's sign and completion entries over its whole
// retention: a (digest, r) is unique across all of it, a claim's kept
// signature is in it, and a kept sign is checked for publication
// whenever it was made.
func History(ctx context.Context, c LogsAPI, group, stream string, from, to time.Time) (*Entries, error) {
	es := &Entries{Ingested: map[string]time.Time{}}
	err := filter(ctx, c, read{group: group, streams: []string{stream}, pattern: HistoryPattern, from: from, to: to, max: maxHistoryEvents},
		func(ev event) error { es.add(ev); return nil })
	return es, err
}

// SignPattern selects KMS Sign calls in the trail's log group.
const SignPattern = `{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }`

// cloudTrailRecord is the part of a CloudTrail record a pass reads.
type cloudTrailRecord struct {
	EventTime          time.Time `json:"eventTime"`
	EventType          string    `json:"eventType"`
	AWSRegion          string    `json:"awsRegion"`
	RecipientAccountID string    `json:"recipientAccountId"`
	RequestID          string    `json:"requestID"`
	ErrorCode          string    `json:"errorCode"`
	UserIdentity       struct {
		ARN            string `json:"arn"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	RequestParameters struct {
		KeyID            string `json:"keyId"`
		SigningAlgorithm string `json:"signingAlgorithm"`
		MessageType      string `json:"messageType"`
	} `json:"requestParameters"`
	Resources []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

// trailStream is a stream CloudTrail writes to the trail's log group:
// <account>_CloudTrail_<region>, and the same with _<n> once it rolls
// over (as staging shows: _2, _3, …).
var trailStream = regexp.MustCompile(`^([0-9]{12})_CloudTrail_([a-z]{2}(?:-[a-z]+)+-[0-9]+)(?:_[0-9]+)?$`)

// KMSSigns reads every KMS Sign in the period from CloudTrail's own
// streams in the trail's log group (account's), on any key: the account
// holds no other signing key, so a Sign on another is itself a finding.
// A record that isn't CloudTrail's (another stream's form, account or
// region, or not an API call) is returned in refused, never used.
func KMSSigns(ctx context.Context, c LogsAPI, trailGroup, account string, from, to time.Time) (out []reconcile.KMSSign, refused []string, err error) {
	err = filter(ctx, c, read{group: trailGroup, streamPrefix: account + "_CloudTrail_", pattern: SignPattern, from: from, to: to, max: maxEvents},
		func(ev event) error {
			var r cloudTrailRecord
			if err := json.Unmarshal([]byte(ev.msg), &r); err != nil {
				refused = append(refused, "a trail record that isn't JSON, in "+ev.stream)
				return nil
			}
			m := trailStream.FindStringSubmatch(ev.stream)
			switch {
			case m == nil || m[1] != account:
				refused = append(refused, "a Sign record in a stream that isn't CloudTrail's: "+ev.stream)
				return nil
			case m[2] != r.AWSRegion:
				refused = append(refused, "a Sign record for "+r.AWSRegion+" in "+ev.stream)
				return nil
			case r.RecipientAccountID != account:
				refused = append(refused, "a Sign record for account "+r.RecipientAccountID+" (request id "+r.RequestID+")")
				return nil
			case r.EventType != "AwsApiCall":
				refused = append(refused, "a Sign record of type "+r.EventType+" (request id "+r.RequestID+")")
				return nil
			}
			key := ""
			if len(r.Resources) > 0 {
				key = r.Resources[0].ARN
			}
			principal := r.UserIdentity.SessionContext.SessionIssuer.ARN
			if principal == "" {
				principal = r.UserIdentity.ARN
			}
			out = append(out, reconcile.KMSSign{RequestID: r.RequestID, At: r.EventTime, KeyARN: key, Principal: principal,
				Algorithm: r.RequestParameters.SigningAlgorithm, MessageType: r.RequestParameters.MessageType, ErrorCode: r.ErrorCode})
			return nil
		})
	return out, refused, err
}

// CompletePattern selects the reconciler's own end-of-run lines that
// say the run read everything it needs (report's "reconciled").
const CompletePattern = `{ ($.msg = "reconciled") && ($.complete IS TRUE) }`

// LastComplete reads the reconciler's own log group for its last run
// that read everything (its "reconciled" line with complete true), in
// from..to: found false when there was none. The next run's period
// starts there, so a stop doesn't leave Signs unreconciled for good.
func LastComplete(ctx context.Context, c LogsAPI, group string, from, to time.Time) (last time.Time, found bool, err error) {
	err = filter(ctx, c, read{group: group, pattern: CompletePattern, from: from, to: to, max: maxEvents}, func(ev event) error {
		var line struct {
			Time time.Time `json:"time"`
		}
		if json.Unmarshal([]byte(ev.msg), &line) != nil || line.Time.IsZero() {
			return nil
		}
		// The line's own time, bounded by when it reached the log: never
		// later than that.
		t := line.Time
		if !ev.ingested.IsZero() && ev.ingested.Before(t) {
			t = ev.ingested
		}
		if t.After(last) {
			last, found = t, true
		}
		return nil
	})
	return last, found, err
}

// ListAPI lists the site bucket's keys under a prefix.
type ListAPI interface {
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

const bundleSuffix = ".json.sigstore.json"

// slotRe is a slot as the site names it: a proposal id and a document name.
var slotRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}/(proposal|results|extension-[1-9][0-9]?)$`)

// ValidSlot reports whether slot is a site slot (proposal_id/name), before
// it goes into a key.
func ValidSlot(slot string) bool { return slotRe.MatchString(slot) }

// Slots lists every document the site holds a bundle for under v1/p/,
// indexed or not, as proposal_id/name. A bundle key that isn't a slot is
// returned in odd, never dropped.
func Slots(ctx context.Context, list ListAPI, bucket string) (slots, odd []string, err error) {
	in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("v1/p/")}
	for {
		out, err := list.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, nil, fmt.Errorf("listing v1/p/: %w", err)
		}
		for _, o := range out.Contents {
			k := aws.ToString(o.Key)
			slot, ok := strings.CutSuffix(strings.TrimPrefix(k, "v1/p/"), bundleSuffix)
			if !ok {
				continue
			}
			if ValidSlot(slot) {
				slots = append(slots, slot)
			} else {
				odd = append(odd, k)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return slots, odd, nil
		}
		in.ContinuationToken = out.NextContinuationToken
	}
}

// Verifier checks a bundle for a document under the anchor key.
type Verifier interface {
	VerifyTimes(bundleJSON, doc, spki []byte) (site.AnchorTimes, error)
}

// Holding reads what the site holds for one slot: its bundle and
// document, the bundle verified under the anchor key, and its message
// signature. ok is false when it couldn't be read (an error other than a
// missing object).
func Holding(ctx context.Context, store site.Storage, v Verifier, spki []byte, slot string) (reconcile.Published, error) {
	if !ValidSlot(slot) {
		return reconcile.Published{}, fmt.Errorf("%q isn't a slot", slot)
	}
	base := "v1/p/" + slot
	bundle, _, err := store.Get(ctx, base+bundleSuffix)
	if errors.Is(err, site.ErrNotExist) {
		return reconcile.Published{}, nil
	}
	if err != nil {
		return reconcile.Published{}, err
	}
	sig, err := MessageSignature(bundle)
	if err != nil {
		return reconcile.Published{Held: true, VerifyErr: err.Error()}, nil
	}
	doc, _, err := store.Get(ctx, base+".json")
	if err != nil {
		if errors.Is(err, site.ErrNotExist) {
			return reconcile.Published{Held: true, Signature: sig, VerifyErr: "a bundle with no document"}, nil
		}
		return reconcile.Published{}, err
	}
	times, err := v.VerifyTimes(bundle, doc, spki)
	if err != nil {
		return reconcile.Published{Held: true, Signature: sig, VerifyErr: err.Error()}, nil
	}
	return reconcile.Published{Held: true, Signature: sig, AnchoredAt: times.TSA}, nil
}

// errFetch marks a site check that failed to read, not one that refused.
type errFetch struct{ err error }

func (e errFetch) Error() string { return "reading the site: " + e.err.Error() }
func (e errFetch) Unwrap() error { return e.err }

// SiteCheck runs the observer's check of one proposal the site holds
// (site.Check): services.json under the site key, then each document
// through the upload API's checks, its IK signature and its bundle
// included. refused is "" when it passed, else what the check refused;
// err is a read that failed (the proposal not checked). The check's
// listing and partial-upload mismatches are the monitor's, not reported
// here.
func SiteCheck(ctx context.Context, store site.Storage, anchors *site.Anchors, siteKey []byte, id string, now time.Time) (refused string, err error) {
	fetch := func(ctx context.Context, path string) ([]byte, error) {
		b, _, err := store.Get(ctx, path)
		if errors.Is(err, site.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, errFetch{err}
		}
		return b, nil
	}
	if _, err := site.Check(ctx, fetch, anchors, siteKey, id, now, nil); err != nil {
		var f errFetch
		if errors.As(err, &f) {
			return "", err
		}
		return err.Error(), nil
	}
	return "", nil
}

// MessageSignature reads a bundle's message signature (unverified).
func MessageSignature(bundle []byte) ([]byte, error) {
	var b struct {
		MessageSignature *struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || b.MessageSignature == nil {
		return nil, errors.New("the bundle has no message signature")
	}
	sig, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("the bundle's message signature isn't base64")
	}
	return sig, nil
}

// LambdaAPI is the read-only Lambda calls a pass makes.
type LambdaAPI interface {
	GetFunctionConfiguration(ctx context.Context, in *lambda.GetFunctionConfigurationInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error)
	GetPolicy(ctx context.Context, in *lambda.GetPolicyInput, opts ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// Deployed is the signer function as deployed.
type Deployed struct {
	CodeSha256, Policy     string // the policy canonical (compact JSON, its statements' Sid order as AWS returns them)
	Runtime, Handler, Role string
	Architectures          []string
	Layers, EnvNames       []string // the layers' ARNs; the environment's names only, never its values
}

// Function reads the signer function's configuration and its resource
// policy.
func Function(ctx context.Context, c LambdaAPI, fn string) (*Deployed, error) {
	cfg, err := c.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(fn)})
	if err != nil {
		return nil, fmt.Errorf("the function: %w", err)
	}
	p, err := c.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(fn)})
	if err != nil {
		return nil, fmt.Errorf("its policy: %w", err)
	}
	d := &Deployed{CodeSha256: aws.ToString(cfg.CodeSha256), Policy: Canonical(aws.ToString(p.Policy)),
		Runtime: string(cfg.Runtime), Handler: aws.ToString(cfg.Handler), Role: aws.ToString(cfg.Role)}
	for _, a := range cfg.Architectures {
		d.Architectures = append(d.Architectures, string(a))
	}
	for _, l := range cfg.Layers {
		d.Layers = append(d.Layers, aws.ToString(l.Arn))
	}
	if cfg.Environment != nil {
		for name := range cfg.Environment.Variables {
			d.EnvNames = append(d.EnvNames, name)
		}
		sort.Strings(d.EnvNames)
	}
	return d, nil
}

// Canonical compacts a JSON policy so that two copies compare equal
// whatever their spacing; anything not JSON is returned as given.
func Canonical(policy string) string {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(policy)); err != nil {
		return policy
	}
	return b.String()
}

// VersionLister lists the function's published versions and aliases.
type VersionLister interface {
	ListVersionsByFunction(ctx context.Context, in *lambda.ListVersionsByFunctionInput, opts ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error)
	ListAliases(ctx context.Context, in *lambda.ListAliasesInput, opts ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error)
}

// VersionsAndAliases lists the function's versions other than $LATEST,
// and its aliases: a release has none, so each is code (and a resource
// policy) the pass would otherwise not see.
func VersionsAndAliases(ctx context.Context, c VersionLister, fn string) (versions, aliases []string, err error) {
	vin := &lambda.ListVersionsByFunctionInput{FunctionName: aws.String(fn)}
	for {
		out, err := c.ListVersionsByFunction(ctx, vin)
		if err != nil {
			return nil, nil, fmt.Errorf("its versions: %w", err)
		}
		for _, v := range out.Versions {
			if aws.ToString(v.Version) != "$LATEST" {
				versions = append(versions, aws.ToString(v.Version))
			}
		}
		if out.NextMarker == nil {
			break
		}
		vin.Marker = out.NextMarker
	}
	ain := &lambda.ListAliasesInput{FunctionName: aws.String(fn)}
	for {
		out, err := c.ListAliases(ctx, ain)
		if err != nil {
			return nil, nil, fmt.Errorf("its aliases: %w", err)
		}
		for _, a := range out.Aliases {
			aliases = append(aliases, aws.ToString(a.Name))
		}
		if out.NextMarker == nil {
			break
		}
		ain.Marker = out.NextMarker
	}
	return versions, aliases, nil
}

// ClaimsAPI reads one claim (signer/awsio.Claims).
type ClaimsAPI interface {
	Get(ctx context.Context, slot string) (*signer.Claim, error)
}

// Claim reads a slot's claim.
func Claim(ctx context.Context, c ClaimsAPI, slot string) (reconcile.Claim, error) {
	if !ValidSlot(slot) {
		return reconcile.Claim{}, fmt.Errorf("%q isn't a slot", slot)
	}
	cl, err := c.Get(ctx, slot)
	if err != nil || cl == nil {
		return reconcile.Claim{}, err
	}
	return reconcile.Claim{Exists: true, Digest: cl.Digest, Sig: cl.Sig, R: cl.R, RequestID: cl.RequestID, Journaled: cl.Journaled}, nil
}

// TrailAPI reads the trail's status and its event selectors.
type TrailAPI interface {
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	GetEventSelectors(ctx context.Context, in *cloudtrail.GetEventSelectorsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
}

// TrailNames are the names the trail's selectors are built from.
type TrailNames struct {
	Partition, Region, Account string
	Function                   string // the signer function's name
	ClaimsTable                string
}

// WantSelectors are the trail's advanced event selectors as
// AnchorSigner-<env> sets them, each in canonical form (selectorKey):
// every management event, read and write; the signer function's
// invokes; the claim table's writes. Narrowing either data selector would
// hide the invokes or the claim writes that the account's own alarms
// (invoke_other, claims_write_other) watch.
func WantSelectors(n TrailNames) []string {
	f := func(field string, op string, v string) cttypes.AdvancedFieldSelector {
		s := cttypes.AdvancedFieldSelector{Field: aws.String(field)}
		switch op {
		case "Equals":
			s.Equals = []string{v}
		case "StartsWith":
			s.StartsWith = []string{v}
		}
		return s
	}
	arn := func(svc, res string) string {
		return fmt.Sprintf("arn:%s:%s:%s:%s:%s", n.Partition, svc, n.Region, n.Account, res)
	}
	sels := []cttypes.AdvancedEventSelector{
		{FieldSelectors: []cttypes.AdvancedFieldSelector{f("eventCategory", "Equals", "Management")}},
		{FieldSelectors: []cttypes.AdvancedFieldSelector{f("eventCategory", "Equals", "Data"),
			f("resources.ARN", "StartsWith", arn("lambda", "function:"+n.Function)),
			f("resources.type", "Equals", "AWS::Lambda::Function")}},
		{FieldSelectors: []cttypes.AdvancedFieldSelector{f("eventCategory", "Equals", "Data"),
			f("resources.ARN", "Equals", arn("dynamodb", "table/"+n.ClaimsTable)),
			f("readOnly", "Equals", "false"),
			f("resources.type", "Equals", "AWS::DynamoDB::Table")}},
	}
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = selectorKey(s)
	}
	sort.Strings(out)
	return out
}

// selectorKey is a selector's canonical form: its field selectors, each
// with its operators' values sorted, the fields sorted. Its name is left
// out (a label only).
func selectorKey(s cttypes.AdvancedEventSelector) string {
	var fields []string
	for _, f := range s.FieldSelectors {
		var ops []string
		for _, op := range []struct {
			name string
			vs   []string
		}{{"Equals", f.Equals}, {"NotEquals", f.NotEquals}, {"StartsWith", f.StartsWith}, {"NotStartsWith", f.NotStartsWith},
			{"EndsWith", f.EndsWith}, {"NotEndsWith", f.NotEndsWith}} {
			if len(op.vs) > 0 {
				vs := append([]string(nil), op.vs...)
				sort.Strings(vs)
				ops = append(ops, op.name+"="+strings.Join(vs, ","))
			}
		}
		fields = append(fields, aws.ToString(f.Field)+"{"+strings.Join(ops, ";")+"}")
	}
	sort.Strings(fields)
	return strings.Join(fields, " ")
}

// selectorsAreTheStack's reports whether the trail's selectors are
// exactly want: no basic selectors, and the advanced ones, as a set, the
// stack's. Anything else (narrowed, removed or added) is reported.
func selectorsAreTheStacks(out *cloudtrail.GetEventSelectorsOutput, want []string) bool {
	if len(out.EventSelectors) > 0 || len(out.AdvancedEventSelectors) != len(want) {
		return false
	}
	got := make([]string, len(out.AdvancedEventSelectors))
	for i, s := range out.AdvancedEventSelectors {
		got[i] = selectorKey(s)
	}
	sort.Strings(got)
	return slices.Equal(got, want)
}

// TrailDeliveryLimit is how long the trail's log group may go without a
// delivery before the pass reports it. CloudTrail delivers only when
// there are events, and each hourly run's own read calls are management
// events the trail records, so even a quiet account has a delivery at
// least about an hour apart (staging's quiet hour after the deploy: gaps
// of at most 5.4 minutes). A limit under the hour would alarm on a quiet
// account; a trail that stops is also its own alarms' (trail_logs_quiet,
// and IsLogging and the delivery error below at once).
const TrailDeliveryLimit = 90 * time.Minute

// TrailProblem reads the trail's status: "" while it logs, delivers to
// its log group and has the stack's selectors (want, from
// WantSelectors), else what's wrong.
func TrailProblem(ctx context.Context, c TrailAPI, trail string, want []string, now time.Time) (string, error) {
	st, err := c.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(trail)})
	if err != nil {
		return "", fmt.Errorf("the trail's status: %w", err)
	}
	switch {
	case !aws.ToBool(st.IsLogging):
		return "the trail isn't logging", nil
	case aws.ToString(st.LatestCloudWatchLogsDeliveryError) != "":
		return "the trail's delivery to its log group fails: " + aws.ToString(st.LatestCloudWatchLogsDeliveryError), nil
	case st.LatestCloudWatchLogsDeliveryTime == nil || now.Sub(*st.LatestCloudWatchLogsDeliveryTime) > TrailDeliveryLimit:
		return "the trail hasn't delivered to its log group in " + TrailDeliveryLimit.String(), nil
	}
	sel, err := c.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: aws.String(trail)})
	if err != nil {
		return "", fmt.Errorf("the trail's selectors: %w", err)
	}
	if !selectorsAreTheStacks(sel, want) {
		return "the trail's selectors aren't the stack's (narrowed, removed or added)", nil
	}
	return "", nil
}
