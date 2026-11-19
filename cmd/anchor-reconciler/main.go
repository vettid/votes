// Command anchor-reconciler is the AnchorSigner's reconciler (key
// protection, the design of record's §6), in its signer mode: an hourly,
// read-only Lambda in the signer account, deployed only as code the owner
// signed (the signer's CodeSigningConfig). Each run reads the signer's
// journal and KMS's Sign calls (CloudTrail's streams in the trail's log
// group) since the last complete run (at least the last Period), the
// journal's sign entries over its whole retention, the trail's status and
// selectors, the claim table, what the votes site holds (each proposal
// checked as an observer would), the anchor key and the signer function,
// and logs each finding as one JSON line: "alarm": <rule> for an alarm,
// "notice": <rule> for a notice. The account's metric filters alarm on
// them; a run that ends is the heartbeat ("reconciled", with "complete"
// when it read everything it needs).
//
// What it can't read it reports (reconcile_incomplete), never skips.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/lambdaenv"
	"github.com/vettid/votes/lambdahttp"
	"github.com/vettid/votes/reconcile"
	"github.com/vettid/votes/reconcile/awsread"
	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/signer/awsio"
	"github.com/vettid/votes/site"
	"github.com/vettid/votes/site/s3store"
)

// Period is how much of the journal and the trail a run reads at least:
// hourly runs overlap, so each sign is seen by more than one. After a
// stop, a run reads back to the last complete run (less a Period), up to
// MaxCatchUp.
const Period = 3 * time.Hour

// MaxCatchUp bounds how far back a run reads the trail and the journal's
// period. With no complete run inside it, the run reads all of it and
// reports itself incomplete: the Signs before aren't reconciled.
const MaxCatchUp = 7 * 24 * time.Hour

// NoteMargin is read of the journal before the period, so that a Sign
// early in the period finds the sign_intent written just before it (a
// lease is seconds long).
const NoteMargin = time.Hour

// HistoryRetention is the journal's retention (AnchorSigner-<env> keeps
// it a year): the whole-retention read goes back this far.
const HistoryRetention = 365 * 24 * time.Hour

// TrailLag is how long the trail may take to show a KMS call in its log
// group.
const TrailLag = 20 * time.Minute

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), log); err != nil {
		// A start refused or failed: an alarm line too, so that the
		// account's metric filter sees it (not only the missing heartbeat).
		log.Error("anchor-reconciler", "alarm", reconcile.RuleIncomplete, "err", err.Error())
		os.Exit(1)
	}
}

// FunctionAPI is the read-only Lambda calls a run makes.
type FunctionAPI interface {
	awsread.LambdaAPI
	awsread.VersionLister
}

// sources is what a run reads from.
type sources struct {
	logs   awsread.LogsAPI
	kms    KMSAPI
	lambda FunctionAPI
	trail  awsread.TrailAPI
	claims awsread.ClaimsAPI
	store  site.Storage
	list   awsread.ListAPI
	verify awsread.Verifier
	// siteCheck is the observer check of one proposal (awsread.SiteCheck).
	siteCheck func(ctx context.Context, id string, now time.Time) (refused string, err error)
	c         *cfg
	now       func() time.Time
	log       *slog.Logger
}

// KMSAPI is the read-only KMS calls a run makes.
type KMSAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

func run(ctx context.Context, log *slog.Logger) error {
	if err := lambdaenv.Check(os.Environ(), log); err != nil {
		return err
	}
	c, err := compiled()
	if err != nil {
		return err
	}
	c.log(log)
	api := os.Getenv("AWS_LAMBDA_RUNTIME_API")
	if api == "" {
		return errors.New("not on Lambda: AWS_LAMBDA_RUNTIME_API is unset")
	}
	httpc := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) { t.Proxy = nil })
	// No shared config or credentials files: the role's own credentials,
	// from the Lambda environment, and nothing a file could add.
	ac, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region), config.WithHTTPClient(httpc),
		config.WithSharedConfigFiles([]string{}), config.WithSharedCredentialsFiles([]string{}))
	if err != nil {
		return err
	}
	endpoint := func(svc string) *string {
		e := fmt.Sprintf("https://%s.%s.amazonaws.com", svc, c.region)
		return &e
	}
	anchors, err := site.NewAnchors(c.instance)
	if err != nil {
		return err
	}
	s3c := s3.NewFromConfig(ac, func(o *s3.Options) { o.BaseEndpoint = endpoint("s3") })
	store := &s3store.Store{Client: s3c, Bucket: c.bucket}
	src := &sources{
		siteCheck: func(ctx context.Context, id string, now time.Time) (string, error) {
			return awsread.SiteCheck(ctx, store, anchors, c.siteKey, id, now)
		},
		logs:   cloudwatchlogs.NewFromConfig(ac, func(o *cloudwatchlogs.Options) { o.BaseEndpoint = endpoint("logs") }),
		kms:    kms.NewFromConfig(ac, func(o *kms.Options) { o.BaseEndpoint = endpoint("kms") }),
		lambda: lambda.NewFromConfig(ac, func(o *lambda.Options) { o.BaseEndpoint = endpoint("lambda") }),
		trail:  cloudtrail.NewFromConfig(ac, func(o *cloudtrail.Options) { o.BaseEndpoint = endpoint("cloudtrail") }),
		claims: &awsio.Claims{Table: c.claimsTable,
			Client: dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = endpoint("dynamodb") })},
		store: store, list: s3c, verify: anchors,
		c: c, now: time.Now, log: log,
	}
	return lambdahttp.ServeFunc(ctx, api, func(ctx context.Context, _ []byte) ([]byte, error) {
		report(log, src.pass(ctx))
		return []byte(`{}`), nil
	})
}

// anchorKey reads the anchor key, every run, and checks it against the
// compiled ARN and public key: the alias resolving elsewhere, or another
// key behind the ARN, is key drift. It returns the compiled key's SPKI
// only once it matches.
func (s *sources) anchorKey(ctx context.Context) (spki []byte, problem string, err error) {
	d, err := s.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(s.c.keyAlias)})
	if err != nil || d.KeyMetadata == nil {
		return nil, "", fmt.Errorf("the alias: %w", err)
	}
	if got := aws.ToString(d.KeyMetadata.Arn); got != s.c.keyARN {
		problem = "the alias resolves to " + got + ", not the compiled key"
	}
	pk, err := s.kms.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(s.c.keyARN)})
	if err != nil {
		return nil, problem, fmt.Errorf("the public key: %w", err)
	}
	sum := sha256.Sum256(pk.PublicKey)
	if hex.EncodeToString(sum[:]) != s.c.keySPKISHA256 {
		if problem != "" {
			problem += "; "
		}
		return nil, problem + "the key's public key isn't the compiled one", nil
	}
	return pk.PublicKey, problem, nil
}

// period picks the run's period start: Period back, or further back to
// the last complete run (less a Period) after a stop, up to MaxCatchUp.
// problem is set when no complete run was found inside MaxCatchUp.
func (s *sources) period(ctx context.Context, now time.Time) (from time.Time, problem string, err error) {
	floor := now.Add(-MaxCatchUp)
	last, found, err := awsread.LastComplete(ctx, s.logs, s.c.ownLogGroup, floor, now)
	switch {
	case err != nil:
		return floor, "", err
	case !found:
		return floor, "no complete run in the last " + MaxCatchUp.String() + ": Signs before " + floor.UTC().Format(time.RFC3339) +
			" aren't reconciled (expected once, on the first run)", nil
	}
	from = now.Add(-Period)
	if t := last.Add(-Period); t.Before(from) {
		from = t
	}
	if from.Before(floor) {
		from = floor
	}
	return from, "", nil
}

// pass reads one period, and the journal's whole retention, and checks
// them.
func (s *sources) pass(ctx context.Context) []reconcile.Finding {
	now := s.now()
	in := reconcile.Input{Now: now, To: now, TrailLag: TrailLag, KeyARN: s.c.keyARN, SignerRole: s.c.role,
		HistoryFrom: now.Add(-HistoryRetention), Acks: s.c.acks, Claims: map[string]reconcile.Claim{},
		Published: map[string]reconcile.Published{}, SiteChecks: map[string]string{}}
	miss := func(what string, err error) { in.Incomplete = append(in.Incomplete, what+": "+err.Error()) }

	from, problem, err := s.period(ctx, now)
	in.From = from
	if err != nil {
		miss("the last complete run (reading back "+MaxCatchUp.String()+")", err)
	} else if problem != "" {
		in.Incomplete = append(in.Incomplete, problem)
	}
	if in.AnchorSPKI, in.KeyProblem, err = s.anchorKey(ctx); err != nil {
		miss("the anchor key", err)
	}
	want := awsread.WantSelectors(awsread.TrailNames{Partition: s.c.partition, Region: s.c.region, Account: s.c.account,
		Function: s.c.function, ClaimsTable: s.c.claimsTable})
	if in.TrailProblem, err = awsread.TrailProblem(ctx, s.trail, s.c.trailName, want, now); err != nil {
		miss("the trail's status", err)
	}
	if es, err := awsread.Journal(ctx, s.logs, s.c.journalGroup, s.c.journalStream, in.From.Add(-NoteMargin), in.To); err != nil {
		miss("the journal", err)
	} else {
		in.Signs, in.Completions, in.Notes, in.Ingested = es.Signs, es.Completions, es.Notes, es.Ingested
		in.JournalUnreadable = es.Unreadable
	}
	if in.Ingested == nil {
		in.Ingested = map[string]time.Time{}
	}
	if hist, err := awsread.History(ctx, s.logs, s.c.journalGroup, s.c.journalStream, in.HistoryFrom, in.To); err != nil {
		miss("the journal's whole retention", err)
	} else {
		in.History = hist.Signs
		in.Completions = append(in.Completions, hist.Completions...)
		for k, t := range hist.Ingested {
			if cur, ok := in.Ingested[k]; !ok || t.Before(cur) {
				in.Ingested[k] = t
			}
		}
		in.JournalUnreadable = append(in.JournalUnreadable, hist.Unreadable...)
	}
	if in.KMSSigns, in.TrailConflicts, err = awsread.KMSSigns(ctx, s.logs, s.c.trailGroup, s.c.account, in.From, in.To); err != nil {
		miss("the trail", err)
	}

	// Every slot in the journal (the period's and the whole retention's)
	// and every slot the site holds: its claim and its holding.
	slots := map[string]bool{}
	for _, e := range append(append([]signer.SignEntry(nil), in.Signs...), in.History...) {
		slots[e.ProposalID+"/"+e.Name] = true
	}
	// Notes' slots too: a note excuses a Sign only as far as its slot's
	// claim bears it out.
	for _, n := range in.Notes {
		if n.ProposalID != "" {
			slots[n.ProposalID+"/"+n.Name] = true
		}
	}
	held, odd, err := awsread.Slots(ctx, s.list, s.c.bucket)
	if err != nil {
		miss("the site's listing", err)
	}
	for _, k := range odd {
		in.Incomplete = append(in.Incomplete, "a bundle at "+k+", which isn't a slot")
	}
	proposals := map[string]bool{}
	for _, slot := range held {
		slots[slot] = true
		proposals[strings.SplitN(slot, "/", 2)[0]] = true
	}
	names := make([]string, 0, len(slots))
	for slot := range slots {
		names = append(names, slot)
	}
	sort.Strings(names)
	for _, slot := range names {
		// A slot not read is left out of Claims or Published: Run reports it.
		if c, err := awsread.Claim(ctx, s.claims, slot); err != nil {
			miss("the claim of "+slot, err)
		} else {
			in.Claims[slot] = c
		}
		if p, err := awsread.Holding(ctx, s.store, s.verify, in.AnchorSPKI, slot); err != nil {
			miss("the site's "+slot, err)
		} else {
			in.Published[slot] = p
		}
	}
	// The observer check of each proposal the site holds: services.json
	// under the site key, and each document's IK signature and bundle.
	// Its time grows with the site (each proposal read whole, hourly).
	ids := make([]string, 0, len(proposals))
	for id := range proposals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if refused, err := s.siteCheck(ctx, id, now); err != nil {
			miss("the site's check of "+id, err)
		} else {
			in.SiteChecks[id] = refused
		}
	}

	if d, err := awsread.Function(ctx, s.lambda, s.c.function); err != nil {
		miss("the signer function", err)
	} else if versions, aliases, err := awsread.VersionsAndAliases(ctx, s.lambda, s.c.function); err != nil {
		miss("the signer function's versions", err)
	} else {
		in.Release = &reconcile.Release{WantCodeSha256: s.c.codeSha256, GotCodeSha256: d.CodeSha256,
			WantPolicy: awsread.Canonical(s.c.policy), GotPolicy: d.Policy, Versions: versions, Aliases: aliases,
			Runtime: d.Runtime, Handler: d.Handler, Role: d.Role, Architectures: d.Architectures, Layers: d.Layers, EnvNames: d.EnvNames}
	}
	return reconcile.Run(in)
}

// report logs each finding as one line, then the run's end (the
// heartbeat), which says whether the run read everything it needs
// (complete): the next run's period starts at the last complete one.
func report(log *slog.Logger, fs []reconcile.Finding) {
	alarms, notices, complete := 0, 0, true
	for _, f := range fs {
		key := "notice"
		if f.Severity == reconcile.Alarm {
			key, alarms = "alarm", alarms+1
		} else {
			notices++
		}
		if f.Rule == reconcile.RuleIncomplete {
			complete = false
		}
		attrs := []any{key, f.Rule, "detail", f.Detail}
		for _, kv := range [][2]string{{"slot", f.Slot}, {"digest", f.Digest}, {"r", f.R}, {"kms_request_id", f.RequestID}, {"sig_sha256", f.SigSHA256}} {
			if kv[1] != "" {
				attrs = append(attrs, kv[0], kv[1])
			}
		}
		if f.Acknowledged {
			attrs = append(attrs, "acknowledged", true)
		}
		if f.Severity == reconcile.Alarm {
			log.Error("reconcile: "+f.Rule, attrs...)
		} else {
			log.Warn("reconcile: "+f.Rule, attrs...)
		}
	}
	log.Info("reconciled", "alarms", alarms, "notices", notices, "complete", complete)
}
