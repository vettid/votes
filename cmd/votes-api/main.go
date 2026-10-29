// Command votes-api is votes.vettid.org's upload API (docs/VOTES-SITE.md
// §4), on Lambda's custom runtime, or on a local port for development.
//
// Environment: VOTES_BUCKET (the site's bucket), VOTES_SIGSTORE (staging
// or production: the instance whose trusted root bundles are checked
// against) and VOTES_SITE_KEY (the site's Ed25519 public key, base64,
// which signs the service list).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/lambdahttp"
	"github.com/vettid/votes/site"
	"github.com/vettid/votes/site/s3store"
)

func main() {
	listen := flag.String("listen", "", "serve on this address instead of Lambda's runtime (development)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), *listen, log); err != nil {
		log.Error("votes-api", "err", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, listen string, log *slog.Logger) error {
	bucket, instance := os.Getenv("VOTES_BUCKET"), os.Getenv("VOTES_SIGSTORE")
	key, err := base64.StdEncoding.Strict().DecodeString(os.Getenv("VOTES_SITE_KEY"))
	if bucket == "" || err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("VOTES_BUCKET and VOTES_SITE_KEY (base64 Ed25519) are required")
	}
	anchors, err := site.NewAnchors(instance)
	if err != nil {
		return err
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	s := &site.Site{Store: &s3store.Store{Client: s3.NewFromConfig(cfg), Bucket: bucket}, Anchors: anchors,
		SiteKey: ed25519.PublicKey(key), Now: time.Now, Log: log}
	if listen != "" {
		srv := &http.Server{Addr: listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
		return srv.ListenAndServe()
	}
	api := os.Getenv("AWS_LAMBDA_RUNTIME_API")
	if api == "" {
		return errors.New("not on Lambda: AWS_LAMBDA_RUNTIME_API is unset (use -listen)")
	}
	return lambdahttp.Serve(ctx, api, s.Handler())
}
