// Command votesctl is the operator's tool for votes.vettid.org:
//
//	votesctl site-key -kms <key arn>
//	    prints the site's Ed25519 public key (base64), from its KMS key
//	votesctl list-anchor-key -kms <key arn>
//	    prints the list anchor key's SubjectPublicKeyInfo (base64), to pin
//	votesctl publish-services -kms <key arn> -site-key <base64> -watch-topics <arn>,<arn>
//	        -list-anchor-key <key arn> -list-anchor-pub <base64> -sigstore staging|production
//	        -bucket <name> -in services.json
//	    signs the service list and publishes it, if it extends the one
//	    published: a higher version, the previous one's hash, and every
//	    service, identity key and anchor key it had (BALLOT-PROTOCOL §3.3);
//	    it first logs the list in Rekor under the list anchor key and
//	    keeps the bundle as v1/services/<version>.bundle
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
// its publish role may sign with (README "The site's signing keys"):
// publish-services signs through KMS, checks every signature under
// -site-key, and first checks that the key watch's emails are confirmed.
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
		_ = fs.Parse(os.Args[2:])
		var pub ed25519.PublicKey
		if pub, err = sitePublicKey(ctx, *kmsKey); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
		}
	case "publish-services":
		fs := flag.NewFlagSet("publish-services", flag.ExitOnError)
		kmsKey := fs.String("kms", "", "the site key's KMS key ARN (the stack's SiteSigningKeyArn)")
		expect := fs.String("site-key", "", "the site's public key (base64) the vaults and the site pin")
		watch := fs.String("watch-topics", "", "the key watch's topics, comma-separated (KeyWatchTopicArn,KeyWatchTopicBArn)")
		listAnchor := fs.String("list-anchor-key", "", "the list anchor key's KMS key ARN (the stack's ListAnchorKeyArn), which logs the list in Rekor")
		listAnchorPub := fs.String("list-anchor-pub", "", "the list anchor key's SubjectPublicKeyInfo (base64), from its independent pin")
		sigstore := fs.String("sigstore", "", "the Sigstore instance the list is logged on, staging or production (the stack's sigstore)")
		bucket := fs.String("bucket", "", "the site's bucket")
		in := fs.String("in", "services.json", "the service list")
		_ = fs.Parse(os.Args[2:])
		err = publish(ctx, publishArgs{kms: *kmsKey, siteKey: *expect, watch: *watch,
			listAnchor: *listAnchor, listAnchorPub: *listAnchorPub, sigstore: *sigstore, bucket: *bucket, in: *in})
	case "list-anchor-key":
		fs := flag.NewFlagSet("list-anchor-key", flag.ExitOnError)
		kmsKey := fs.String("kms", "", "the list anchor key's KMS key ARN (the stack's ListAnchorKeyArn)")
		_ = fs.Parse(os.Args[2:])
		var spki []byte
		if spki, err = listAnchorPublicKey(ctx, *kmsKey); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(spki))
		}
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
	fmt.Fprintln(os.Stderr, "usage: votesctl site-key -kms <key arn>\n"+
		"       votesctl list-anchor-key -kms <key arn>\n"+
		"       votesctl publish-services -kms <key arn> -site-key <base64> -watch-topics <arn>,<arn> -list-anchor-key <key arn> -list-anchor-pub <base64> -sigstore staging|production -bucket <name> -in <file>\n"+
		"       votesctl check -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>] <proposal_id>\n"+
		"       votesctl check -all [-since YYYY-MM] -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>]")
	os.Exit(2)
}

// sitePublicKey is site-key's work: the public key from KMS (-kms).
func sitePublicKey(ctx context.Context, kmsKey string) (ed25519.PublicKey, error) {
	if kmsKey == "" {
		return nil, errors.New("-kms is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return kmsPublicKey(ctx, kms.NewFromConfig(cfg), kmsKey)
}

type publishArgs struct {
	kms, siteKey, watch, listAnchor, listAnchorPub, sigstore, bucket, in string
}

func publish(ctx context.Context, a publishArgs) error {
	if a.bucket == "" {
		return errors.New("-bucket is required")
	}
	if a.kms == "" {
		return errors.New("-kms is required (the stack's SiteSigningKeyArn)")
	}
	if a.siteKey == "" || a.watch == "" || a.listAnchor == "" || a.listAnchorPub == "" || a.sigstore == "" {
		return errors.New("-kms needs -site-key (the site's public key), -watch-topics (the key watch's two topics), -list-anchor-key (the stack's ListAnchorKeyArn), -list-anchor-pub (its pinned public key) and -sigstore (the stack's sigstore)")
	}
	anchorPin, err := base64.StdEncoding.Strict().DecodeString(a.listAnchorPub)
	if err != nil || len(anchorPin) == 0 {
		return errors.New("-list-anchor-pub: the list anchor key's SubjectPublicKeyInfo, base64 (as votesctl list-anchor-key prints it)")
	}
	if !kmsKeyARN.MatchString(a.kms) {
		return errors.New("-kms takes the site key's ARN (arn:aws:kms:<region>:<account>:key/<id>, the stack's SiteSigningKeyArn), not an alias or a key id")
	}
	region := strings.Split(a.kms, ":")[3]
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
	// The key's region, from its ARN (the watch topics are bound to it).
	inRegion := func(o *kms.Options) { o.Region = region }
	kc := kms.NewFromConfig(cfg, inRegion)
	signer, err := kmsPublishSigner(ctx, a, kc, sns.NewFromConfig(cfg, func(o *sns.Options) { o.Region = region }))
	if err != nil {
		return err
	}
	lg, err := newRekorLog(ctx, kc, a.listAnchor, a.kms, a.sigstore, anchorPin)
	if err != nil {
		return err
	}
	return publishList(ctx, s3.NewFromConfig(cfg), a.bucket, signer, lg, raw)
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
// rule, that it extends the published list, and that no other bytes sit
// at its version's copy. A rerun of a list already signed (published,
// interrupted half-way, or with its copy kept) uses the bucket's
// signature and signs nothing. lg logs the list in Rekor before it is
// moved (its bundle kept as services/<version>.bundle); a bundle already
// kept is checked before anything is signed and used, so a rerun anchors
// nothing either. publish always gives one; only tests leave it nil.
func publishList(ctx context.Context, c s3API, bucket string, key listSigner, lg listLog, raw []byte) error {
	data, err := vote.Canonicalize(raw)
	if err != nil {
		return err
	}
	next, err := site.ParseUnsignedServiceList(data)
	if err != nil {
		return err
	}
	pub := key.Public()
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
		// written if missing (after an interrupted publish). Its bundle is
		// written before the list moves, so one is missing here only if it
		// was removed (a servicesRepair): it is logged again now.
		var have []byte
		if lg != nil {
			if have, err = keptBundle(ctx, c, bucket, lg, next.Version, data); err != nil {
				return err
			}
		}
		if err := keepVersion(ctx, c, bucket, next.Version, data, sig); err != nil {
			return err
		}
		if lg != nil && have == nil {
			if err := logList(ctx, c, bucket, lg, next.Version, data, nil); err != nil {
				return err
			}
			fmt.Printf("service list version %d is already published; its history is kept, and it is now logged in Rekor\n", next.Version)
			return nil
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
		// The published list's bundle must verify here: a -sigstore that
		// isn't the stack's (or another list anchor key) is refused before
		// anything is signed or logged. Every list from the first one
		// logged on has one.
		if lg != nil {
			pb, err := keptBundle(ctx, c, bucket, lg, prev.Version, cur.data)
			if err != nil {
				return err
			}
			if pb == nil {
				return fmt.Errorf("version %d is current without its bundle (%s): run publish-services with that version's list first, which logs it", prev.Version, bundleKey(prev.Version))
			}
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
	// Nothing else may already sit at this version's copy (a pair rolled
	// back past it, or a stray): checked before signing. A copy of this
	// list's own signature is used, not signed again.
	base := fmt.Sprintf("v1/services/%d.json", next.Version)
	copyData, err := get(ctx, c, bucket, base)
	if err != nil {
		return err
	}
	copySig, err := get(ctx, c, bucket, base+".sig")
	if err != nil {
		return err
	}
	if copyData.data != nil && !bytes.Equal(copyData.data, data) {
		return fmt.Errorf("%s holds other bytes: a version is never rewritten", base)
	}
	if copySig.data != nil {
		if vote.Verify(pub, vote.LabelServiceList, sum(data), copySig.data) != nil || sig != nil && !bytes.Equal(copySig.data, sig) {
			return fmt.Errorf("%s.sig holds other bytes: a version is never rewritten", base)
		}
		sig = copySig.data
	}
	// So may a bundle, which must anchor this list; one kept is used.
	var have []byte
	if lg != nil {
		if have, err = keptBundle(ctx, c, bucket, lg, next.Version, data); err != nil {
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
	// Logged only once signed, so that no entry is made for a list the
	// site key refused, and kept before the move, so that no list is
	// served without its entry. A failure here leaves the bucket as it
	// was (the signature is made again on a rerun).
	if lg != nil {
		if err := logList(ctx, c, bucket, lg, next.Version, data, have); err != nil {
			return err
		}
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
		if err := writeOnce(ctx, c, bucket, o.key, o.data, o.ct); err != nil {
			return err
		}
	}
	return nil
}

// writeOnce writes a kept object under v1/services/, only if there is none
// (the bucket policy requires the condition there).
func writeOnce(ctx context.Context, c s3API, bucket, key string, data []byte, ct string) error {
	in := &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data),
		ContentType: aws.String(ct), CacheControl: aws.String("public, max-age=31536000, immutable"),
		IfNoneMatch: aws.String("*")}
	if _, err := c.PutObject(ctx, in); err != nil {
		return fmt.Errorf("%s: %w", key, err)
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
