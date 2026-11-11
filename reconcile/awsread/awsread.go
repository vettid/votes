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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
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

// maxEvents bounds a read: past it the pass reports itself incomplete
// rather than check part of a period.
const maxEvents = 100000

func filter(ctx context.Context, c LogsAPI, group string, streams []string, pattern string, from, to time.Time, each func(msg string, ingested time.Time) error) error {
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(group), StartTime: aws.Int64(from.UnixMilli()), EndTime: aws.Int64(to.UnixMilli()),
	}
	if len(streams) > 0 {
		in.LogStreamNames = streams
	}
	if pattern != "" {
		in.FilterPattern = aws.String(pattern)
	}
	n := 0
	for {
		out, err := c.FilterLogEvents(ctx, in)
		if err != nil {
			return err
		}
		for _, e := range out.Events {
			if n++; n > maxEvents {
				return fmt.Errorf("more than %d events in the period", maxEvents)
			}
			var ingested time.Time // zero when the service didn't say
			if e.IngestionTime != nil {
				ingested = time.UnixMilli(*e.IngestionTime)
			}
			if err := each(aws.ToString(e.Message), ingested); err != nil {
				return err
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(in.NextToken) {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

// Journal reads the signer's journal for the period: one JSON event per
// entry, {"kind": "sign" | "note" | "complete", ...}. An entry it can't
// read stops the read: a journal the pass can't read whole is incomplete.
// ingested holds each sign entry's ingestion time (set by CloudWatch Logs,
// not by the writer), by reconcile.SignKey.
func Journal(ctx context.Context, c LogsAPI, group, stream string, from, to time.Time) (signs []signer.SignEntry, done []signer.CompletionEntry, notes []signer.NoteEntry, ingested map[string]time.Time, err error) {
	ingested = map[string]time.Time{}
	err = filter(ctx, c, group, []string{stream}, "", from, to, func(msg string, at time.Time) error {
		var k struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(msg), &k); err != nil {
			return errors.New("journal: an entry isn't JSON")
		}
		dec := json.NewDecoder(strings.NewReader(msg))
		switch k.Kind {
		case "sign":
			var e struct {
				Kind string `json:"kind"`
				signer.SignEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a sign entry: %w", err)
			}
			signs = append(signs, e.SignEntry)
			if k := reconcile.SignKey(e.SignEntry); !at.IsZero() && (ingested[k].IsZero() || at.Before(ingested[k])) {
				ingested[k] = at
			}
		case "complete":
			var e struct {
				Kind string `json:"kind"`
				signer.CompletionEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a completion entry: %w", err)
			}
			done = append(done, e.CompletionEntry)
		case "note":
			var e struct {
				Kind string `json:"kind"`
				signer.NoteEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a note: %w", err)
			}
			notes = append(notes, e.NoteEntry)
		default:
			return fmt.Errorf("journal: an entry of kind %q", k.Kind)
		}
		return nil
	})
	return signs, done, notes, ingested, err
}

// SignPattern selects KMS Sign calls in the trail's log group.
const SignPattern = `{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }`

// cloudTrailRecord is the part of a CloudTrail record a pass reads.
type cloudTrailRecord struct {
	EventTime    time.Time `json:"eventTime"`
	RequestID    string    `json:"requestID"`
	ErrorCode    string    `json:"errorCode"`
	UserIdentity struct {
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

// KMSSigns reads every KMS Sign in the period from the trail's log group,
// on any key: the account holds no other signing key, so a Sign on another
// is itself a finding.
func KMSSigns(ctx context.Context, c LogsAPI, trailGroup string, from, to time.Time) ([]reconcile.KMSSign, error) {
	var out []reconcile.KMSSign
	err := filter(ctx, c, trailGroup, nil, SignPattern, from, to, func(msg string, _ time.Time) error {
		var r cloudTrailRecord
		if err := json.Unmarshal([]byte(msg), &r); err != nil {
			return errors.New("trail: a record isn't JSON")
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
	return out, err
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
	if _, err := v.VerifyTimes(bundle, doc, spki); err != nil {
		return reconcile.Published{Held: true, Signature: sig, VerifyErr: err.Error()}, nil
	}
	return reconcile.Published{Held: true, Signature: sig}, nil
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

// Function reads the signer function's CodeSha256 and its resource
// policy, canonical (compact JSON, its statements' Sid order as AWS
// returns them).
func Function(ctx context.Context, c LambdaAPI, fn string) (codeSha256, policy string, err error) {
	cfg, err := c.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(fn)})
	if err != nil {
		return "", "", fmt.Errorf("the function: %w", err)
	}
	p, err := c.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(fn)})
	if err != nil {
		return "", "", fmt.Errorf("its policy: %w", err)
	}
	return aws.ToString(cfg.CodeSha256), Canonical(aws.ToString(p.Policy)), nil
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
	return reconcile.Claim{Exists: true, Digest: cl.Digest, Sig: cl.Sig, R: cl.R, RequestID: cl.RequestID}, nil
}

// TrailAPI reads the trail's status and its event selectors.
type TrailAPI interface {
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	GetEventSelectors(ctx context.Context, in *cloudtrail.GetEventSelectorsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
}

// recordsAllManagement reports whether the trail's selectors record every
// management event, read and write: one advanced selector whose only
// field is eventCategory = Management (as AnchorSigner-<env> sets it).
// Anything narrower (write only, KMS excluded) and the pass's view of the
// Signs is partial.
func recordsAllManagement(out *cloudtrail.GetEventSelectorsOutput) bool {
	for _, sel := range out.AdvancedEventSelectors {
		if len(sel.FieldSelectors) != 1 {
			continue
		}
		f := sel.FieldSelectors[0]
		if aws.ToString(f.Field) == "eventCategory" && len(f.Equals) == 1 && f.Equals[0] == "Management" &&
			len(f.NotEquals) == 0 && len(f.StartsWith) == 0 && len(f.NotStartsWith) == 0 && len(f.EndsWith) == 0 && len(f.NotEndsWith) == 0 {
			return true
		}
	}
	return false
}

// TrailDeliveryLimit is how long the trail's log group may go without a
// delivery before the pass reports it.
const TrailDeliveryLimit = 30 * time.Minute

// TrailProblem reads the trail's status: "" while it logs and delivers to
// its log group, else what's wrong.
func TrailProblem(ctx context.Context, c TrailAPI, trail string, now time.Time) (string, error) {
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
	if !recordsAllManagement(sel) {
		return "the trail doesn't record every management event (its selectors were narrowed)", nil
	}
	return "", nil
}
