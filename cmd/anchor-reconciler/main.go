// Command anchor-reconciler is the AnchorSigner's reconciler (key
// protection, the design of record's §6), in its signer mode: an hourly,
// read-only Lambda in the signer account, deployed only as code the owner
// signed (the signer's CodeSigningConfig). Each run reads the last
// Period of the signer's journal and of KMS's Sign calls (the trail's log
// group), what the votes site holds, the anchor key and the signer
// function, and logs each finding as one JSON line: "alarm": <rule> for an
// alarm, "notice": <rule> for a notice. The account's metric filters alarm
// on them; a run that ends is the heartbeat ("reconciled").
//
// What it can't read it reports (reconcile_incomplete), never skips.
package main

import (
	"context"
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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/lambdaenv"
	"github.com/vettid/votes/lambdahttp"
	"github.com/vettid/votes/reconcile"
	"github.com/vettid/votes/reconcile/awsread"
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

// sources is what a run reads from.
type sources struct {
	logs    awsread.LogsAPI
	kms     KMSAPI
	lambda  awsread.LambdaAPI
	store   site.Storage
	list    awsread.ListAPI
	verify  awsread.Verifier
	c       *cfg
	now     func() time.Time
	log     *slog.Logger
	keyARN  string
	keySPKI []byte
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
		store:  &s3store.Store{Client: s3c, Bucket: c.bucket}, list: s3c, verify: anchors,
		c: c, now: time.Now, log: log,
	}
	return lambdahttp.ServeFunc(ctx, api, func(ctx context.Context, _ []byte) ([]byte, error) {
		report(log, src.pass(ctx))
		return []byte(`{}`), nil
	})
}

// pass reads one period and checks it.
func (s *sources) pass(ctx context.Context) []reconcile.Finding {
	now := s.now()
	in := reconcile.Input{Now: now, From: now.Add(-Period), To: now, TrailLag: TrailLag, SignerRole: s.c.role, Acks: s.c.acks,
		Published: map[string]reconcile.Published{}}
	miss := func(what string, err error) { in.Incomplete = append(in.Incomplete, what+": "+err.Error()) }

	if s.keyARN == "" {
		d, err := s.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(s.c.keyAlias)})
		if err == nil && d.KeyMetadata != nil {
			pk, perr := s.kms.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(s.c.keyAlias)})
			if perr == nil {
				s.keyARN, s.keySPKI = aws.ToString(d.KeyMetadata.Arn), pk.PublicKey
			} else {
				err = perr
			}
		}
		if err != nil {
			miss("the anchor key", err)
		}
	}
	in.AnchorSPKI = s.keySPKI

	var err error
	if in.Signs, in.Completions, in.Notes, err = awsread.Journal(ctx, s.logs, s.c.journalGroup, s.c.journalStream, in.From, in.To); err != nil {
		miss("the journal", err)
	}
	if s.keyARN != "" {
		if in.KMSSigns, err = awsread.KMSSigns(ctx, s.logs, s.c.trailGroup, s.keyARN, in.From, in.To); err != nil {
			miss("the trail", err)
		}
	}

	slots := map[string]bool{}
	for _, e := range in.Signs {
		slots[e.ProposalID+"/"+e.Name] = true
	}
	held, err := awsread.Slots(ctx, s.store, s.list, s.c.bucket)
	if err != nil {
		miss("the site's index", err)
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
		p, err := awsread.Holding(ctx, s.store, s.verify, s.keySPKI, slot)
		if err != nil {
			miss("the site's "+slot, err) // left out of Published: Run reports it for a journaled slot
			continue
		}
		in.Published[slot] = p
	}

	if code, policy, err := awsread.Function(ctx, s.lambda, s.c.function); err != nil {
		miss("the signer function", err)
	} else {
		in.Release = &reconcile.Release{WantCodeSha256: s.c.codeSha256, GotCodeSha256: code,
			WantPolicy: awsread.Canonical(s.c.policy), GotPolicy: policy}
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
		for k, v := range map[string]string{"slot": f.Slot, "digest": f.Digest, "kms_request_id": f.RequestID} {
			if v != "" {
				attrs = append(attrs, k, v)
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
