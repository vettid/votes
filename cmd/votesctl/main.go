// Command votesctl is the operator's tool for votes.vettid.org:
//
//	votesctl site-key -kms <key arn> | -secret <arn>
//	    prints the site's Ed25519 public key (base64), from its KMS key or
//	    its secret
//	votesctl publish-services -kms <key arn> -site-key <base64> -watch-topics <arn>,<arn> -bucket <name> -in services.json
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
//	votesctl check -all [-since YYYY-MM] -site-key <base64> [...]
//	    checks the service list's kept versions as a chain, and every
//	    proposal in index.json and the archive; prints one JSON report
//
// check exits 0 when every check held and the report has ok true; 1 when
// a check failed (with -all, the report is printed first and names each);
// 2 for a usage error; 3 when the checks held but the report has ok false:
// a mismatch (docs/VOTES-SITE.md §7).
//
// The site's key is the stack's KMS key (SiteSigningKeyArn), which only
// its publish role may sign with (README "The site's signing keys"); with
// -kms, publish-services signs through KMS, checks every signature under
// -site-key, and first checks that the key watch's emails are confirmed.
// Until the staging flag day it can still be derived from the Secrets
// Manager secret as Ed25519(seed = SHA-256(secret string)) (-secret).
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/vettid/service-vault/vote"
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
		kmsKey := fs.String("kms", "", "the site key's KMS key ARN (the stack's SiteSigningKeyArn)")
		secret := fs.String("secret", "", "the site key's Secrets Manager secret (until the flag day)")
		_ = fs.Parse(os.Args[2:])
		var pub ed25519.PublicKey
		if pub, err = sitePublicKey(ctx, *kmsKey, *secret); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
		}
	case "publish-services":
		fs := flag.NewFlagSet("publish-services", flag.ExitOnError)
		kmsKey := fs.String("kms", "", "the site key's KMS key ARN (the stack's SiteSigningKeyArn)")
		expect := fs.String("site-key", "", "with -kms: the site's public key (base64) the vaults and the site pin")
		watch := fs.String("watch-topics", "", "with -kms: the key watch's topics, comma-separated (KeyWatchTopicArn,KeyWatchTopicBArn)")
		previous := fs.String("previous-site-key", "", "with -kms, on the flag day only: the key (base64) the published list is signed with")
		secret := fs.String("secret", "", "the site key's Secrets Manager secret (until the flag day)")
		bucket := fs.String("bucket", "", "the site's bucket")
		in := fs.String("in", "services.json", "the service list")
		_ = fs.Parse(os.Args[2:])
		err = publish(ctx, publishArgs{kms: *kmsKey, siteKey: *expect, watch: *watch, previous: *previous, secret: *secret, bucket: *bucket, in: *in})
	case "check":
		os.Exit(runCheck(ctx, os.Args[2:], os.Stdout, os.Stderr))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "votesctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: votesctl site-key -kms <key arn> | -secret <arn>\n"+
		"       votesctl publish-services -kms <key arn> -site-key <base64> -watch-topics <arn>,<arn> -bucket <name> -in <file>\n"+
		"       votesctl publish-services -secret <arn> -bucket <name> -in <file>\n"+
		"       votesctl check -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>] <proposal_id>\n"+
		"       votesctl check -all [-since YYYY-MM] -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>]")
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

// sitePublicKey is site-key's work: the public key from KMS (-kms) or
// from the secret (-secret), exactly one of them.
func sitePublicKey(ctx context.Context, kmsKey, secret string) (ed25519.PublicKey, error) {
	if (kmsKey == "") == (secret == "") {
		return nil, errors.New("give exactly one of -kms and -secret")
	}
	if secret != "" {
		k, err := siteKey(ctx, secret)
		if err != nil {
			return nil, err
		}
		return secretSigner(k).Public(), nil
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return kmsPublicKey(ctx, kms.NewFromConfig(cfg), kmsKey)
}

type publishArgs struct {
	kms, siteKey, watch, previous, secret, bucket, in string
}

func publish(ctx context.Context, a publishArgs) error {
	if a.bucket == "" {
		return errors.New("-bucket is required")
	}
	if (a.kms == "") == (a.secret == "") {
		return errors.New("give exactly one of -kms and -secret")
	}
	if a.kms == "" && (a.siteKey != "" || a.watch != "" || a.previous != "") {
		return errors.New("-site-key, -watch-topics and -previous-site-key go with -kms")
	}
	if a.kms != "" && (a.siteKey == "" || a.watch == "") {
		return errors.New("-kms needs -site-key (the site's public key) and -watch-topics (the key watch's two topics)")
	}
	var region string
	if a.kms != "" {
		m := kmsKeyARN.FindStringSubmatch(a.kms)
		if m == nil {
			return errors.New("-kms takes the site key's ARN (arn:aws:kms:<region>:<account>:key/<id>, the stack's SiteSigningKeyArn), not an alias or a key id")
		}
		region = strings.Split(a.kms, ":")[3]
	}
	raw, err := os.ReadFile(a.in)
	if err != nil {
		return err
	}
	// One publish is a few calls: bounded, so that a hung one doesn't
	// leave the operator waiting (and a retry, below, is never made).
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	if a.secret != "" {
		k, err := siteKey(ctx, a.secret)
		if err != nil {
			return err
		}
		return publishList(ctx, s3.NewFromConfig(cfg), a.bucket, secretSigner(k), nil, raw)
	}
	// The key's region, from its ARN (the watch topics are bound to it).
	inRegion := func(o *kms.Options) { o.Region = region }
	signer, err := kmsPublishSigner(ctx, a, kms.NewFromConfig(cfg, inRegion), sns.NewFromConfig(cfg, func(o *sns.Options) { o.Region = region }))
	if err != nil {
		return err
	}
	var previous ed25519.PublicKey
	if a.previous != "" {
		if previous, err = decodeSiteKey(a.previous); err != nil {
			return fmt.Errorf("-previous-site-key: %w", err)
		}
	}
	return publishList(ctx, s3.NewFromConfig(cfg), a.bucket, signer, previous, raw)
}

// publishTimeout bounds one publish.
const publishTimeout = 3 * time.Minute

// kmsPublishSigner checks the key watch, then the KMS key: a publish
// nobody would be told of is refused before anything is signed. The watch
// topics must be in the key's partition, region and account.
func kmsPublishSigner(ctx context.Context, a publishArgs, k kmsAPI, n snsAPI) (listSigner, error) {
	expect, err := decodeSiteKey(a.siteKey)
	if err != nil {
		return nil, err
	}
	if !kmsKeyARN.MatchString(a.kms) {
		return nil, errors.New("-kms takes the site key's ARN, not an alias or a key id")
	}
	topics := strings.Split(a.watch, ",")
	key := strings.Split(a.kms, ":")
	for _, t := range topics {
		if f := strings.Split(t, ":"); len(f) < 6 || f[1] != key[1] || f[3] != key[3] || f[4] != key[4] {
			return nil, fmt.Errorf("-watch-topics: %s is not in the key's partition, region and account", t)
		}
	}
	if err := checkWatch(ctx, n, topics); err != nil {
		return nil, err
	}
	return newKMSSigner(ctx, k, a.kms, expect)
}

// s3API is the part of the S3 client a publish uses.
type s3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// publishList signs raw and publishes it on c's bucket (publish's work,
// apart from the key and the client). Every check that can refuse the
// list runs before it is signed, since a signature with the site key is
// emailed and alarmed (README "The watch"): its shape, the first-list
// rule, and that it extends the published list. A rerun of a list already
// signed (published, or interrupted half-way) uses the signature in the
// bucket and signs nothing. previous, when given, is the key the
// published list is signed with, when it isn't key's (the flag day: the
// last list under the secret's key, the first under KMS's).
func publishList(ctx context.Context, c s3API, bucket string, key listSigner, previous ed25519.PublicKey, raw []byte) error {
	data, err := vote.Canonicalize(raw)
	if err != nil {
		return err
	}
	next, err := site.ParseUnsignedServiceList(data)
	if err != nil {
		return err
	}
	pub := key.Public()
	if previous == nil {
		previous = pub
	}
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
	var sig []byte // this list's signature: the bucket's, on a rerun
	if curSig.data != nil && vote.Verify(pub, vote.LabelServiceList, sum(data), curSig.data) == nil {
		sig = curSig.data
	}
	resuming := sig != nil
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
		prev, err := site.ParseServiceList(cur.data, curSig.data, previous)
		if err != nil {
			return fmt.Errorf("the published list doesn't verify (%w): restore the pair from the bucket's object versions, "+
				"or, on the flag day, give the key it is signed with as -previous-site-key", err)
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
	if sig == nil {
		if sig, err = signList(ctx, key, data); err != nil {
			return err
		}
		if _, err := site.ParseServiceList(data, sig, pub); err != nil {
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
func keepVersion(ctx context.Context, c s3API, bucket string, version int64, data, sig []byte) error {
	return versionCopy(ctx, c, bucket, version, data, sig, true)
}

// checkVersion reports whether a version's copy is absent or holds the
// same bytes, writing nothing.
func checkVersion(ctx context.Context, c s3API, bucket string, version int64, data, sig []byte) error {
	return versionCopy(ctx, c, bucket, version, data, sig, false)
}

func versionCopy(ctx context.Context, c s3API, bucket string, version int64, data, sig []byte, write bool) error {
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

func get(ctx context.Context, c s3API, bucket, key string) (object, error) {
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
func put(ctx context.Context, c s3API, bucket, key string, data []byte, ct, tag string) error {
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

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
