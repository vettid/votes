// Command anchor-signer is the AnchorSigner function (key protection,
// phase 1, GC #7406 §1, as amended for the signer account: #7606, #7611,
// #7638, #7648): invoked directly by the service vault's task, one
// document per call, it anchors the document under the anchor key in KMS,
// which only this function may use, and publishes it on the votes site.
// Lambda's custom runtime (provided.al2023), in the signer's own account,
// deployed only as code the owner signed.
//
// Its configuration is compiled in (config.go, scripts/build-signer.sh),
// never read from the environment; it refuses to start when a variable
// that could redirect its clients is set, or when the anchor key isn't
// listed for the services it anchors for.
//
// The event is a signer.Request as JSON; the answer a signer.Result. A
// function error means not published: the caller retries, and the claim
// makes the retry a resume.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/votes/lambdahttp"
	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/signer/awsio"
	"github.com/vettid/votes/site"
	"github.com/vettid/votes/site/s3store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), log); err != nil {
		log.Error("anchor-signer", "err", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	if err := checkEnv(os.Environ(), log); err != nil {
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
	// Every AWS client: the compiled region, its fixed endpoint, and no
	// proxy.
	httpc := awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) { t.Proxy = nil })
	ac, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.region), config.WithHTTPClient(httpc))
	if err != nil {
		return err
	}
	endpoint := func(svc string) *string {
		e := fmt.Sprintf("https://%s.%s.amazonaws.com", svc, c.region)
		return &e
	}
	kc := kms.NewFromConfig(ac, func(o *kms.Options) { o.BaseEndpoint = endpoint("kms") })
	key, err := awsio.NewKey(ctx, kc, c.keyAlias)
	if err != nil {
		return err
	}
	anch, err := anchor.NewSigner(c.instance, key)
	if err != nil {
		return err
	}
	anchors, err := site.NewAnchors(c.instance)
	if err != nil {
		return err
	}
	if src := anchors.RootSource(); src != site.RootFromTUF {
		log.Warn("trusted root: the TUF fetch failed; using the embedded root", "source", src)
	}
	store := awsio.ReadOnly{Storage: &s3store.Store{Bucket: c.bucket,
		Client: s3.NewFromConfig(ac, func(o *s3.Options) { o.BaseEndpoint = endpoint("s3") })}}
	st := &site.Site{Store: store, Anchors: anchors, SiteKey: c.siteKey, Now: time.Now, Log: log}
	// The anchor key must be listed for every service compiled in, or
	// nothing is signed (each document is checked again in Prepare).
	if err := listedFor(ctx, store, c, anch.PublicKeyDER()); err != nil {
		return err
	}
	s := &signer.Signer{
		Claims: &awsio.Claims{Table: c.table,
			Client: dynamodb.NewFromConfig(ac, func(o *dynamodb.Options) { o.BaseEndpoint = endpoint("dynamodb") })},
		Journal: &awsio.Journal{Group: c.group, Stream: c.stream, Now: time.Now,
			Client: cloudwatchlogs.NewFromConfig(ac, func(o *cloudwatchlogs.Options) { o.BaseEndpoint = endpoint("logs") })},
		Anchor:     awsio.Anchor{Anchorer: anch},
		Site:       &awsio.Site{Site: st, API: c.api, Client: anchor.Client(signer.DefaultDeadlines.Site), Anchors: anchors},
		Now:        time.Now,
		Log:        log,
		Deadlines:  signer.DefaultDeadlines,
		ServiceIKs: c.serviceIKs,
	}
	return lambdahttp.ServeFunc(ctx, api, func(ctx context.Context, ev []byte) ([]byte, error) {
		return handle(ctx, s, ev)
	})
}

// listedFor checks that the current service list, verified under the
// compiled site key, lists spki as an anchor key of every compiled
// service.
func listedFor(ctx context.Context, store site.Storage, c *cfg, spki []byte) error {
	data, _, err := store.Get(ctx, "v1/services.json")
	if err != nil {
		return fmt.Errorf("the service list: %w", err)
	}
	sig, _, err := store.Get(ctx, "v1/services.json.sig")
	if err != nil {
		return fmt.Errorf("the service list's signature: %w", err)
	}
	l, err := site.ParseServiceList(data, sig, c.siteKey)
	if err != nil {
		return err
	}
	return keyListed(l, c.serviceIKs, spki)
}

// keyListed: every ik's service lists spki among its anchor keys.
func keyListed(l *site.ServiceList, iks [][]byte, spki []byte) error {
	for _, ik := range iks {
		svc := l.ByIK(ik)
		if svc == nil {
			return errors.New("refusing to start: a compiled service isn't on the service list")
		}
		found := false
		for _, k := range svc.AnchorKeys {
			found = found || bytes.Equal(k.Key, spki)
		}
		if !found {
			return errors.New("refusing to start: the anchor key isn't listed for a compiled service")
		}
	}
	return nil
}

// handle decodes one event strictly, runs it, and encodes the answer.
func handle(ctx context.Context, s *signer.Signer, ev []byte) ([]byte, error) {
	var req signer.Request
	dec := json.NewDecoder(bytes.NewReader(ev))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		return json.Marshal(signer.Result{Status: 400, Code: signer.CodeBadRequest})
	}
	res, err := s.Handle(ctx, req)
	if err != nil {
		return nil, &lambdahttp.Failure{Type: "NotPublished", Message: err.Error()}
	}
	return json.Marshal(res)
}
