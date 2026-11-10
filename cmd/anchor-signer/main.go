// Command anchor-signer is the AnchorSigner function (key protection,
// phase 1, GC #7406 §1): invoked directly by the service vault's task,
// one document per call, it anchors the document under the anchor key in
// KMS, which only this function may use, and publishes it on the votes
// site. Lambda's custom runtime (provided.al2023), outside a VPC.
//
// Environment:
//   - SIGNER_KEY_ID: the anchor key in KMS (ECC_NIST_P256, SIGN_VERIFY);
//   - SIGNER_CLAIMS_TABLE: the claim table;
//   - SIGNER_JOURNAL_GROUP, SIGNER_JOURNAL_STREAM: the journal;
//   - VOTES_BUCKET: the site's bucket, read only;
//   - VOTES_API: the site's base URL, https://votes.vettid.org or staging's;
//   - VOTES_SIGSTORE: staging or production;
//   - VOTES_SITE_KEY: the site's Ed25519 public key, base64, which signs the
//     service list.
//
// The event is a signer.Request as JSON; the answer a signer.Result. A
// function error means not published: the caller retries, and the claim
// makes the retry a resume.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

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
	if err := run(context.Background(), os.Getenv, log); err != nil {
		log.Error("anchor-signer", "err", err.Error())
		os.Exit(1)
	}
}

type env struct {
	keyID, table, group, stream, bucket, api, instance string
	siteKey                                            ed25519.PublicKey
}

func readEnv(getenv func(string) string) (*env, error) {
	e := &env{keyID: getenv("SIGNER_KEY_ID"), table: getenv("SIGNER_CLAIMS_TABLE"), group: getenv("SIGNER_JOURNAL_GROUP"),
		stream: getenv("SIGNER_JOURNAL_STREAM"), bucket: getenv("VOTES_BUCKET"), api: strings.TrimSuffix(getenv("VOTES_API"), "/"),
		instance: getenv("VOTES_SIGSTORE")}
	key, err := base64.StdEncoding.Strict().DecodeString(getenv("VOTES_SITE_KEY"))
	switch {
	case e.keyID == "" || e.table == "" || e.group == "" || e.stream == "" || e.bucket == "":
		return nil, errors.New("SIGNER_KEY_ID, SIGNER_CLAIMS_TABLE, SIGNER_JOURNAL_GROUP, SIGNER_JOURNAL_STREAM and VOTES_BUCKET are required")
	case !strings.HasPrefix(e.api, "https://"):
		return nil, errors.New("VOTES_API must be an https:// URL")
	case e.instance != anchor.Staging && e.instance != anchor.Production:
		return nil, errors.New("VOTES_SIGSTORE must be staging or production")
	case err != nil || len(key) != ed25519.PublicKeySize:
		return nil, errors.New("VOTES_SITE_KEY must be a base64 Ed25519 public key")
	}
	e.siteKey = key
	return e, nil
}

func run(ctx context.Context, getenv func(string) string, log *slog.Logger) error {
	e, err := readEnv(getenv)
	if err != nil {
		return err
	}
	api := getenv("AWS_LAMBDA_RUNTIME_API")
	if api == "" {
		return errors.New("not on Lambda: AWS_LAMBDA_RUNTIME_API is unset")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	key, err := awsio.NewKey(ctx, kms.NewFromConfig(cfg), e.keyID)
	if err != nil {
		return err
	}
	anch, err := anchor.NewSigner(e.instance, key)
	if err != nil {
		return err
	}
	anchors, err := site.NewAnchors(e.instance)
	if err != nil {
		return err
	}
	if src := anchors.RootSource(); src != site.RootFromTUF {
		log.Warn("trusted root: the TUF fetch failed; using the embedded root", "source", src)
	}
	st := &site.Site{Store: awsio.ReadOnly{Storage: &s3store.Store{Client: s3.NewFromConfig(cfg), Bucket: e.bucket}},
		Anchors: anchors, SiteKey: e.siteKey, Now: time.Now, Log: log}
	s := &signer.Signer{
		Claims:    &awsio.Claims{Client: dynamodb.NewFromConfig(cfg), Table: e.table},
		Journal:   &awsio.Journal{Client: cloudwatchlogs.NewFromConfig(cfg), Group: e.group, Stream: e.stream, Now: time.Now},
		Anchor:    awsio.Anchor{Anchorer: anch},
		Site:      &awsio.Site{Site: st, API: e.api, Client: anchor.Client(signer.DefaultDeadlines.Site), Anchors: anchors},
		Now:       time.Now,
		Log:       log,
		Deadlines: signer.DefaultDeadlines,
	}
	return lambdahttp.ServeFunc(ctx, api, func(ctx context.Context, ev []byte) ([]byte, error) {
		return handle(ctx, s, ev)
	})
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
