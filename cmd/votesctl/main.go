// Command votesctl is the operator's tool for votes.vettid.org:
//
//	votesctl site-key -secret <arn>
//	    prints the site's Ed25519 public key (base64) from its secret
//	votesctl publish-services -secret <arn> -bucket <name> -in services.json
//	    signs the service list and publishes it, if it extends the one
//	    published: a higher version, the previous one's hash, and every
//	    service, identity key and anchor key it had (BALLOT-PROTOCOL §3.3)
//	votesctl check -site-key <base64> [-site https://votes.vettid.org]
//	        [-sigstore production|staging] [-trusted-root <file>] <proposal_id>
//	    checks a vote from what the site serves, as an observer
//	    (BALLOT-PROTOCOL §8.4): every document is put through the upload
//	    API's own checks, each at its anchor's time, and the results
//	    against the rows; prints a JSON report, or fails
//
// The site's key is derived from its Secrets Manager secret as
// Ed25519(seed = SHA-256(secret string)).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/votes/site"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "site-key":
		fs := flag.NewFlagSet("site-key", flag.ExitOnError)
		secret := fs.String("secret", "", "the site key's Secrets Manager secret")
		_ = fs.Parse(os.Args[2:])
		var k ed25519.PrivateKey
		if k, err = siteKey(ctx, *secret); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		}
	case "publish-services":
		fs := flag.NewFlagSet("publish-services", flag.ExitOnError)
		secret := fs.String("secret", "", "the site key's Secrets Manager secret")
		bucket := fs.String("bucket", "", "the site's bucket")
		in := fs.String("in", "services.json", "the service list")
		_ = fs.Parse(os.Args[2:])
		err = publish(ctx, *secret, *bucket, *in)
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		base := fs.String("site", "https://votes.vettid.org", "the site")
		key := fs.String("site-key", "", "the site's public key (base64), from its release config")
		instance := fs.String("sigstore", site.Production, "the Sigstore instance the votes are anchored in")
		rootFile := fs.String("trusted-root", "", "a Sigstore trusted root file, instead of fetching it")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() != 1 {
			usage()
		}
		var anchors *site.Anchors
		if anchors, err = anchorsFor(*instance, *rootFile); err == nil {
			err = checkVote(ctx, os.Stdout, httpFetcher(*base, noRedirects()), anchors, *key, fs.Arg(0), time.Now())
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "votesctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: votesctl site-key -secret <arn> | publish-services -secret <arn> -bucket <name> -in <file>\n"+
		"       votesctl check -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>] <proposal_id>")
	os.Exit(2)
}

func siteKey(ctx context.Context, secret string) (ed25519.PrivateKey, error) {
	if secret == "" {
		return nil, errors.New("-secret is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secret)})
	if err != nil {
		return nil, err
	}
	s := aws.ToString(out.SecretString)
	if len(s) < 32 {
		return nil, errors.New("the site key's secret is too short")
	}
	seed := sha256.Sum256([]byte(s))
	return ed25519.NewKeyFromSeed(seed[:]), nil
}

func publish(ctx context.Context, secret, bucket, in string) error {
	if bucket == "" {
		return errors.New("-bucket is required")
	}
	key, err := siteKey(ctx, secret)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	return publishList(ctx, s3.NewFromConfig(cfg), bucket, key, raw)
}

// publishList signs raw and publishes it on c's bucket (publish's work,
// apart from the key and the client).
func publishList(ctx context.Context, c *s3.Client, bucket string, key ed25519.PrivateKey, raw []byte) error {
	data, err := vote.Canonicalize(raw)
	if err != nil {
		return err
	}
	sig, err := signList(key, data)
	if err != nil {
		return err
	}
	next, err := site.ParseServiceList(data, sig, key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	cur, err := get(ctx, c, bucket, "v1/services.json")
	if err != nil {
		return err
	}
	curSig, err := get(ctx, c, bucket, "v1/services.json.sig")
	if err != nil {
		return err
	}
	// Both objects are written conditionally, the signature first, so two
	// publishes can't interleave; one that stopped between the two writes
	// is finished by running it again with the same file. Every version
	// is also kept, write-once, as services/<version>.json and .sig, so a
	// vault that missed versions can follow the chain (VOTES-SITE §3). A
	// version's copy is written only once it has been the current list
	// (after the move; the previous one's again before it), so the copies
	// never hold a list that wasn't served.
	resuming := curSig.data != nil && bytes.Equal(curSig.data, sig)
	switch {
	case resuming && bytes.Equal(cur.data, data):
		// Already the current list: only its history is checked, and
		// written if missing (the list published before history was kept).
		if err := keepVersion(ctx, c, bucket, next.Version, data, sig); err != nil {
			return err
		}
		fmt.Printf("service list version %d is already published; its history is kept\n", next.Version)
		return nil
	case cur.data == nil && curSig.data == nil:
		if next.Version != 1 || !bytes.Equal(next.Previous, make([]byte, 32)) {
			return errors.New("the first list is version 1 with an all-zero previous")
		}
	case resuming && (cur.data == nil || bytes.Equal(next.Previous, sum(cur.data))):
		// An interrupted publish of this same list: only the list is left.
	case cur.data == nil || curSig.data == nil:
		return errors.New("the bucket holds a service list or a signature without the other: restore the pair from the bucket's object versions")
	default:
		prev, err := site.ParseServiceList(cur.data, curSig.data, pub)
		if err != nil {
			return fmt.Errorf("the published list doesn't verify (%w): restore the pair from the bucket's object versions", err)
		}
		if err := site.Extends(prev, cur.data, next); err != nil {
			return err
		}
		if next.Version != prev.Version+1 {
			// Consecutive, so a vault's app fetches each version after
			// the one it holds without gaps.
			return fmt.Errorf("the next version is %d", prev.Version+1)
		}
		if err := keepVersion(ctx, c, bucket, prev.Version, cur.data, curSig.data); err != nil {
			return err
		}
	}
	// Nothing else may already sit at this version's copy: checked, not
	// written, before the move.
	if err := checkVersion(ctx, c, bucket, next.Version, data, sig); err != nil {
		return err
	}
	beforeMove()
	if !resuming {
		if err := put(ctx, c, bucket, "v1/services.json.sig", sig, "application/octet-stream", curSig.tag); err != nil {
			return err
		}
	}
	if err := put(ctx, c, bucket, "v1/services.json", data, "application/json", cur.tag); err != nil {
		return err
	}
	// A failure here leaves the list current without its copy: the same
	// command again, or the next publish, writes it.
	if err := keepVersion(ctx, c, bucket, next.Version, data, sig); err != nil {
		return err
	}
	fmt.Printf("published service list version %d (%d services)\n", next.Version, len(next.Services))
	return nil
}

// beforeMove runs just before publishList moves the current list; a
// test sets it to make the move lose a race.
var beforeMove = func() {}

// keepVersion writes a list version's copy, write-once: an object
// already there must hold the same bytes.
func keepVersion(ctx context.Context, c *s3.Client, bucket string, version int64, data, sig []byte) error {
	return versionCopy(ctx, c, bucket, version, data, sig, true)
}

// checkVersion reports whether a version's copy is absent or holds the
// same bytes, writing nothing.
func checkVersion(ctx context.Context, c *s3.Client, bucket string, version int64, data, sig []byte) error {
	return versionCopy(ctx, c, bucket, version, data, sig, false)
}

func versionCopy(ctx context.Context, c *s3.Client, bucket string, version int64, data, sig []byte, write bool) error {
	base := fmt.Sprintf("v1/services/%d.json", version)
	for _, o := range []struct {
		key, ct string
		data    []byte
	}{{base + ".sig", "application/octet-stream", sig}, {base, "application/json", data}} {
		got, err := get(ctx, c, bucket, o.key)
		if err != nil {
			return err
		}
		if got.data != nil {
			if !bytes.Equal(got.data, o.data) {
				return fmt.Errorf("%s holds other bytes: a version is never rewritten", o.key)
			}
			continue
		}
		if !write {
			continue
		}
		in := &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(o.key), Body: bytes.NewReader(o.data),
			ContentType: aws.String(o.ct), CacheControl: aws.String("public, max-age=31536000, immutable"),
			IfNoneMatch: aws.String("*")}
		if _, err := c.PutObject(ctx, in); err != nil {
			return fmt.Errorf("%s: %w", o.key, err)
		}
	}
	return nil
}

type object struct {
	data []byte
	tag  string // its ETag, or "" when absent
}

func get(ctx context.Context, c *s3.Client, bucket, key string) (object, error) {
	o, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		var nf interface{ ErrorCode() string }
		if errors.As(err, &nf) && nf.ErrorCode() == "NoSuchKey" {
			return object{}, nil
		}
		return object{}, err
	}
	defer o.Body.Close()
	var b bytes.Buffer
	if _, err := b.ReadFrom(o.Body); err != nil {
		return object{}, err
	}
	return object{data: b.Bytes(), tag: aws.ToString(o.ETag)}, nil
}

// put replaces an object only if it is still the version read (tag), or
// writes it only if there was none ("").
func put(ctx context.Context, c *s3.Client, bucket, key string, data []byte, ct, tag string) error {
	in := &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data),
		// Short: a reader may meet the new list beside the old signature
		// for this long, and retries.
		ContentType: aws.String(ct), CacheControl: aws.String("public, max-age=10")}
	if tag == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(tag)
	}
	if _, err := c.PutObject(ctx, in); err != nil {
		return fmt.Errorf("%s changed while publishing (another publish?): %w", key, err)
	}
	return nil
}

// signList is the site's signature of a list's bytes (BALLOT-PROTOCOL
// §3.3).
func signList(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	return suite.Sign(key, vote.LabelServiceList, sum(data))
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
