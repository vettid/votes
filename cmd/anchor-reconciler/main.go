// Command anchor-reconciler is the AnchorSigner's reconciler (key
// protection, the design of record's §6), in its signer mode: an hourly,
// read-only Lambda in the signer account, deployed only as code the owner
// signed (the signer's CodeSigningConfig). Each run reads the last Period
// of the signer's journal and of KMS's Sign calls (the trail's log group),
// the trail's status, the claim table, what the votes site holds, the
// anchor key and the signer function, and logs each finding as one JSON
// line: "alarm": <rule> for an alarm, "notice": <rule> for a notice. The
// account's metric filters alarm on them; a run that ends is the heartbeat
// ("reconciled").
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
	"github.com/vettid/votes/signer/awsio"
	"github.com/vettid/votes/site"
	"github.com/vettid/votes/site/s3store"
)

// Period is how much of the journal and the trail a run reads: hourly runs
// overlap, so each sign is seen by more than one.
const Period = 3 * time.Hour

// TrailLag is how long the trail may take to show a KMS call in its log
// group.
const TrailLag = 20 * time.Minute

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), log); err != nil {
		log.Error("anchor-reconciler", "err", err.Error())
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
	c      *cfg
	now    func() time.Time
	log    *slog.Logger
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
	ac, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region), config.WithHTTPClient(httpc))
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
	src := &sources{
		logs:   cloudwatchlogs.NewFromConfig(ac, func(o *cloudwatchlogs.Options) { o.BaseEndpoint = endpoint("logs") }),
		kms:    kms.NewFromConfig(ac, func(o *kms.Options) { o.BaseEndpoint = endpoint("kms") }),
		lambda: lambda.NewFromConfig(ac, func(o *lambda.Options) { o.BaseEndpoint = endpoint("lambda") }),
		trail:  cloudtrail.NewFromConfig(ac, func(o *cloudtrail.Options) { o.BaseEndpoint = endpoint("cloudtrail") }),
		claims: &awsio.Claims{Table: c.claimsTable,
			Client: dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = endpoint("dynamodb") })},
		store: &s3store.Store{Client: s3c, Bucket: c.bucket}, list: s3c, verify: anchors,
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

// pass reads one period and checks it.
func (s *sources) pass(ctx context.Context) []reconcile.Finding {
	now := s.now()
	in := reconcile.Input{Now: now, From: now.Add(-Period), To: now, TrailLag: TrailLag, KeyARN: s.c.keyARN, SignerRole: s.c.role,
		Acks: s.c.acks, Claims: map[string]reconcile.Claim{}, Published: map[string]reconcile.Published{}}
	miss := func(what string, err error) { in.Incomplete = append(in.Incomplete, what+": "+err.Error()) }

	var err error
	if in.AnchorSPKI, in.KeyProblem, err = s.anchorKey(ctx); err != nil {
		miss("the anchor key", err)
	}
	if in.TrailProblem, err = awsread.TrailProblem(ctx, s.trail, s.c.trailName, now); err != nil {
		miss("the trail's status", err)
	}
	if in.Signs, in.Completions, in.Notes, in.Ingested, err = awsread.Journal(ctx, s.logs, s.c.journalGroup, s.c.journalStream, in.From, in.To); err != nil {
		miss("the journal", err)
	}
	if in.KMSSigns, err = awsread.KMSSigns(ctx, s.logs, s.c.trailGroup, in.From, in.To); err != nil {
		miss("the trail", err)
	}

	// Every slot in the journal and every slot the site holds: its claim
	// and its holding.
	slots := map[string]bool{}
	for _, e := range in.Signs {
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
	for _, slot := range held {
		slots[slot] = true
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

	if code, policy, err := awsread.Function(ctx, s.lambda, s.c.function); err != nil {
		miss("the signer function", err)
	} else if versions, aliases, err := awsread.VersionsAndAliases(ctx, s.lambda, s.c.function); err != nil {
		miss("the signer function's versions", err)
	} else {
		in.Release = &reconcile.Release{WantCodeSha256: s.c.codeSha256, GotCodeSha256: code,
			WantPolicy: awsread.Canonical(s.c.policy), GotPolicy: policy, Versions: versions, Aliases: aliases}
	}
	return reconcile.Run(in)
}

// report logs each finding as one line, then the run's end (the heartbeat).
func report(log *slog.Logger, fs []reconcile.Finding) {
	alarms, notices := 0, 0
	for _, f := range fs {
		key := "notice"
		if f.Severity == reconcile.Alarm {
			key, alarms = "alarm", alarms+1
		} else {
			notices++
		}
		attrs := []any{key, f.Rule, "detail", f.Detail}
		for _, kv := range [][2]string{{"slot", f.Slot}, {"digest", f.Digest}, {"r", f.R}, {"kms_request_id", f.RequestID}} {
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
	log.Info("reconciled", "alarms", alarms, "notices", notices)
}
