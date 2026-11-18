package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
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

	"github.com/vettid/votes/signer"
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
func newRekorLog(ctx context.Context, k anchorKeyAPI, c s3API, bucket, keyARN, siteKeyARN, instance string, pin []byte) (*rekorLog, error) {
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
		// Not "use the tag's": an administrator could have retagged the key.
		return nil, fmt.Errorf("the list anchor key's %s tag says %s, -sigstore says %s: refusing to log. Don't change -sigstore to match the tag: check the stack's sigstore and the key watch's mail for a TagResource (README)", sigstoreTag, tagged, instance)
	}
	anch, err := anchor.NewSigner(instance, &recordingSigner{key: key, spki: pin, c: c, bucket: bucket})
	if err != nil {
		return nil, err
	}
	// Defense in depth: unreachable while the Anchorer re-marshals the
	// same key, whose KMS bytes were compared above.
	if !bytes.Equal(anch.PublicKeyDER(), pin) {
		return nil, errors.New("the list anchor key's public key is not -list-anchor-pub: refusing to log")
	}
	ver, err := site.NewAnchors(instance)
	if err != nil {
		return nil, err
	}
	return &rekorLog{a: anch, v: ver, spki: pin, instance: instance}, nil
}

// recordingSigner is the list anchor key as the Anchorer signs with it:
// every signature KMS returns is recorded in the bucket, write-once, before
// the Anchorer sees it, so before it is checked, timestamped or entered in
// Rekor (GC #12986). The records are the offline nonce-reuse check's input
// for this key: every signature, a rerun's, a lost race's and an abandoned
// publish's included, not only the published bundles'. A signature whose
// record isn't written is returned to no one, so nothing is logged
// without one.
type recordingSigner struct {
	key    anchor.DigestSigner
	spki   []byte // the key's SubjectPublicKeyInfo, as pinned
	c      s3API
	bucket string
}

// signRecord is one record: which key signed which digest, and the
// signature as KMS returned it (ASN.1 DER).
type signRecord struct {
	V         int    `json:"v"`
	KeySPKI   []byte `json:"key_spki"`
	Digest    []byte `json:"digest"`
	Signature []byte `json:"signature"`
}

// signRecordKey names a record by its digest and r, both lowercase hex,
// r as signer.RFromDER gives it (big-endian, no leading zero bytes). Two
// records under one name would be the same r over the same digest: the
// same signature, since s follows from them.
func signRecordKey(digest, r []byte) string {
	return "v1/services/signs/" + hex.EncodeToString(digest) + "/" + hex.EncodeToString(r) + ".json"
}

// Public implements anchor.DigestSigner.
func (s *recordingSigner) Public() *ecdsa.PublicKey { return s.key.Public() }

// SignDigest implements anchor.DigestSigner: one KMS Sign, then the
// record. On any failure it returns no signature (the Sign was made, and
// its key watch mail has no record: a rerun's).
func (s *recordingSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	sig, err := s.key.SignDigest(ctx, digest)
	if err != nil {
		return nil, err
	}
	r, err := signer.RFromDER(sig)
	if err != nil {
		return nil, fmt.Errorf("the list anchor key's signature: %w", err)
	}
	b, err := json.Marshal(&signRecord{V: 1, KeySPKI: s.spki, Digest: digest, Signature: sig})
	if err != nil {
		return nil, err
	}
	if err := writeOnce(ctx, s.c, s.bucket, signRecordKey(digest, r), b, "application/json"); err != nil {
		var api interface{ ErrorCode() string }
		if errors.As(err, &api) && api.ErrorCode() == "PreconditionFailed" {
			// Not an alarm: that signature is recorded already.
			return nil, fmt.Errorf("recording the list anchor key's signature: an identical one is already recorded; nothing logged, run the publish again: %w", err)
		}
		return nil, fmt.Errorf("recording the list anchor key's signature: nothing logged: %w", err)
	}
	return sig, nil
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
