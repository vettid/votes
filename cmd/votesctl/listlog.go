package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/vettid/service-vault/anchor"

	"github.com/vettid/votes/signer/awsio"
	"github.com/vettid/votes/site"
)

// listLog logs each service list in Rekor (VOTES-SITE §3, GC #12646 task
// 3): SHA-256 of the list's bytes, signed with the list anchor key, an
// ECDSA P-256 key in KMS that only the publish role may sign with, in the
// Rekor profile of BALLOT-PROTOCOL §8.5. The site key can't sign its own
// entry: Rekor's hashedrekord takes no pure Ed25519.
type listLog interface {
	// Check reports whether bundle anchors exactly data under the list
	// anchor key: the signature, the Rekor entry and its inclusion proof,
	// and one RFC 3161 timestamp, under the instance's trusted root.
	Check(bundle, data []byte) error
	// Anchor signs data with the list anchor key (one KMS Sign), enters it
	// in Rekor, and returns its bundle, checked as Check checks it. A Rekor
	// entry is public and permanent: Anchor is called only for a list that
	// every check has passed and that the site key has signed.
	Anchor(ctx context.Context, data []byte) ([]byte, error)
}

// rekorLog is the listLog on a Sigstore instance: service-vault's
// anchor.Anchorer makes the entry, site.Anchors checks bundles.
type rekorLog struct {
	a interface {
		Anchor(context.Context, []byte) (json.RawMessage, error)
	}
	v interface {
		Verify(bundle, doc, spki []byte) (time.Time, error)
	}
	spki     []byte
	instance string
}

func (r *rekorLog) Check(bundle, data []byte) error {
	if _, err := r.v.Verify(bundle, data, r.spki); err != nil {
		return fmt.Errorf("on Sigstore %s: %w", r.instance, err)
	}
	return nil
}

func (r *rekorLog) Anchor(ctx context.Context, data []byte) ([]byte, error) {
	b, err := r.a.Anchor(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("logging the list in Rekor: %w", err)
	}
	if err := r.Check(b, data); err != nil {
		return nil, fmt.Errorf("the list's Rekor bundle doesn't verify: nothing written: %w", err)
	}
	return b, nil
}

// sigstoreTag is the list anchor key's tag naming the Sigstore instance
// its environment logs on (the stack's sigstore, cdk/lib/votes-stack.ts).
const sigstoreTag = "vettid:sigstore"

// anchorKeyAPI is the part of the KMS client the list anchor key uses.
type anchorKeyAPI interface {
	kmsAPI
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
}

// anchorPublicKey reads the list anchor key from KMS after the checks the
// site key gets (kmsPublicKey): by ARN only, KMS answered for it, and it
// signs with ECDSA_SHA_256; awsio.NewKeyFrom checks its spec, usage and
// curve. It returns the key and its SubjectPublicKeyInfo.
func anchorPublicKey(ctx context.Context, k kmsAPI, keyARN string) (*awsio.Key, []byte, error) {
	if !kmsKeyARN.MatchString(keyARN) {
		return nil, nil, errors.New("-list-anchor-key takes the list anchor key's ARN (arn:aws:kms:<region>:<account>:key/<id>, the stack's ListAnchorKeyArn), not an alias or a key id")
	}
	out, err := k.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, nil, fmt.Errorf("reading the list anchor key: %w", err)
	}
	if aws.ToString(out.KeyId) != keyARN {
		return nil, nil, fmt.Errorf("KMS answered for key %q, not %q", aws.ToString(out.KeyId), keyARN)
	}
	if !slices.Contains(out.SigningAlgorithms, kmstypes.SigningAlgorithmSpecEcdsaSha256) {
		return nil, nil, errors.New("the list anchor key doesn't sign with ECDSA_SHA_256")
	}
	key, err := awsio.NewKeyFrom(k, keyARN, out)
	if err != nil {
		return nil, nil, fmt.Errorf("the list anchor key: %w", err)
	}
	return key, out.PublicKey, nil
}

// listAnchorPublicKey is list-anchor-key's work: the key's
// SubjectPublicKeyInfo, after anchorPublicKey's checks, for pinning (the
// monitor's configuration, and -list-anchor-pub).
func listAnchorPublicKey(ctx context.Context, keyARN string) ([]byte, error) {
	if !kmsKeyARN.MatchString(keyARN) {
		return nil, errors.New("-kms takes the list anchor key's ARN (the stack's ListAnchorKeyArn), not an alias or a key id")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	region := strings.Split(keyARN, ":")[3]
	_, spki, err := anchorPublicKey(ctx, kms.NewFromConfig(cfg, func(o *kms.Options) { o.Region = region }), keyARN)
	return spki, err
}

// keySigstore is the instance the list anchor key's tag names.
func keySigstore(ctx context.Context, k anchorKeyAPI, keyARN string) (string, error) {
	var marker *string
	for {
		out, err := k.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(keyARN), Marker: marker})
		if err != nil {
			return "", fmt.Errorf("reading the list anchor key's tags: %w", err)
		}
		for _, t := range out.Tags {
			if aws.ToString(t.TagKey) == sigstoreTag {
				return aws.ToString(t.TagValue), nil
			}
		}
		if !out.Truncated || out.NextMarker == nil {
			return "", fmt.Errorf("the list anchor key has no %s tag: deploy the stack (it sets the tag to its sigstore)", sigstoreTag)
		}
		marker = out.NextMarker
	}
}

// newRekorLog checks the list anchor key (an ECDSA P-256 signing key, by
// ARN only, in the site key's partition, region and account, whose
// SubjectPublicKeyInfo is pin, and whose tag names instance) and returns
// the list log on instance, whose trusted root it fetches through TUF.
// Nothing is signed before every check has passed.
func newRekorLog(ctx context.Context, k anchorKeyAPI, keyARN, siteKeyARN, instance string, pin []byte) (*rekorLog, error) {
	if !kmsKeyARN.MatchString(keyARN) {
		return nil, errors.New("-list-anchor-key takes the list anchor key's ARN (arn:aws:kms:<region>:<account>:key/<id>, the stack's ListAnchorKeyArn), not an alias or a key id")
	}
	if keyARN == siteKeyARN {
		return nil, errors.New("-list-anchor-key is -kms: it is the stack's ListAnchorKeyArn, the other key")
	}
	a, s := strings.Split(keyARN, ":"), strings.Split(siteKeyARN, ":")
	if a[1] != s[1] || a[3] != s[3] || a[4] != s[4] {
		return nil, errors.New("-list-anchor-key is not in the site key's partition, region and account")
	}
	if instance != site.Staging && instance != site.Production {
		return nil, fmt.Errorf("-sigstore is %q: give staging or production, the stack's sigstore", instance)
	}
	if len(pin) == 0 {
		return nil, errors.New("-list-anchor-pub (the list anchor key's SubjectPublicKeyInfo, base64) is required with -kms")
	}
	key, spki, err := anchorPublicKey(ctx, k, keyARN)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(spki, pin) {
		return nil, errors.New("the list anchor key's public key is not -list-anchor-pub: refusing to log")
	}
	tagged, err := keySigstore(ctx, k, keyARN)
	if err != nil {
		return nil, err
	}
	if tagged != instance {
		return nil, fmt.Errorf("-sigstore is %s, but the stack's is %s (the list anchor key's %s tag): refusing to log", instance, tagged, sigstoreTag)
	}
	anch, err := anchor.NewSigner(instance, key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(anch.PublicKeyDER(), pin) {
		return nil, errors.New("the list anchor key's public key is not -list-anchor-pub: refusing to log")
	}
	ver, err := site.NewAnchors(instance)
	if err != nil {
		return nil, err
	}
	return &rekorLog{a: anch, v: ver, spki: pin, instance: instance}, nil
}

// bundleKey is a list version's Rekor bundle in the bucket, kept
// write-once beside its copy (VOTES-SITE §3).
func bundleKey(version int64) string { return fmt.Sprintf("v1/services/%d.bundle", version) }

// keptBundle returns the bundle kept for a version, after checking that it
// anchors data: nil if there is none yet. One that anchors anything else
// is refused (a version is never rewritten), before anything is signed.
func keptBundle(ctx context.Context, c s3API, bucket string, lg listLog, version int64, data []byte) ([]byte, error) {
	o, err := get(ctx, c, bucket, bundleKey(version))
	if err != nil || o.data == nil {
		return nil, err
	}
	if err := lg.Check(o.data, data); err != nil {
		return nil, fmt.Errorf("%s holds a bundle that doesn't anchor this list (%v): check that -sigstore and -list-anchor-key are the stack's; otherwise it is a stray, and a version is never rewritten (README \"Clearing a stray version copy\")", bundleKey(version), err)
	}
	return o.data, nil
}

// logList makes sure a version's list is logged: the bundle kept (have,
// from keptBundle), or a new entry, kept write-once before the list is
// moved, so that no list is served without its entry.
func logList(ctx context.Context, c s3API, bucket string, lg listLog, version int64, data, have []byte) error {
	if have != nil {
		return nil
	}
	b, err := lg.Anchor(ctx, data)
	if err != nil {
		return err
	}
	return writeOnce(ctx, c, bucket, bundleKey(version), b, "application/json")
}
