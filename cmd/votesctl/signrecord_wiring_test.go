package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/vettid/service-vault/anchor"
)

// bucketS3 is fakeS3 that remembers each put's bucket and its attempts.
type bucketS3 struct {
	*fakeS3
	buckets  map[string]string // object key -> bucket
	attempts []int             // RetryMaxAttempts of each put
}

func (b *bucketS3) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	var o s3.Options
	for _, fn := range opts {
		fn(&o)
	}
	b.attempts = append(b.attempts, o.RetryMaxAttempts)
	out, err := b.fakeS3.PutObject(ctx, in, opts...)
	if err == nil {
		b.buckets[aws.ToString(in.Key)] = aws.ToString(in.Bucket)
	}
	return out, err
}

// twoKeys is KMS with the site key (fakeKMS, Ed25519) and the list anchor
// key (anchorFake, P-256), answering for each by its ARN.
type twoKeys struct {
	site   *fakeKMS
	anchor *anchorFake
}

func (k *twoKeys) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, o ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if aws.ToString(in.KeyId) == testAnchorARN {
		return k.anchor.GetPublicKey(ctx, in, o...)
	}
	return k.site.GetPublicKey(ctx, in, o...)
}

func (k *twoKeys) Sign(ctx context.Context, in *kms.SignInput, o ...func(*kms.Options)) (*kms.SignOutput, error) {
	if aws.ToString(in.KeyId) == testAnchorARN {
		return k.anchor.Sign(ctx, in, o...)
	}
	return k.site.Sign(ctx, in, o...)
}

func (k *twoKeys) ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, o ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	return k.anchor.ListResourceTags(ctx, in, o...)
}

type okVerifier struct{}

func (okVerifier) Verify(_, _, _ []byte) (time.Time, error) { return time.Time{}, nil }

// The path publish takes (publishSetup: kmsPublishSigner, then
// newRekorLog) signs with the list anchor key only through the recorder:
// one Anchorer.Sign leaves one record, in the publish's bucket, written
// in a single attempt.
func TestPublishSetupRecords(t *testing.T) {
	ctx := context.Background()
	was := newListAnchors
	newListAnchors = func(string) (listVerifier, error) { return okVerifier{}, nil }
	t.Cleanup(func() { newListAnchors = was })

	site := testKey("site")
	ec := testECKey(t)
	k := &twoKeys{site: newFakeKMS(site), anchor: &anchorFake{fakeKMS: newFakeKMS(site), ec: ec,
		tags: []kmstypes.Tag{{TagKey: aws.String(sigstoreTag), TagValue: aws.String("staging")}}}}
	pin, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	ok := &fakeSNS{pages: map[string][][]snstypes.Subscription{
		topicA: {{sub(topicA, "confirmed", "email")}}, topicB: {{sub(topicB, "confirmed", "email")}}}}
	a := publishArgs{kms: testKeyARN, siteKey: base64Key(pub(site)), watch: topicA + "," + topicB,
		listAnchor: testAnchorARN, listAnchorPub: base64.StdEncoding.EncodeToString(pin), sigstore: "staging", bucket: "the-bucket"}
	b := &bucketS3{fakeS3: newFakeS3(), buckets: map[string]string{}}

	_, lg, err := publishSetup(ctx, a, pin, k, ok, b)
	if err != nil {
		t.Fatal(err)
	}
	an, isAnchorer := lg.a.(*anchor.Anchorer)
	if !isAnchorer {
		t.Fatalf("the list log's anchorer is %T", lg.a)
	}
	digest, sig, err := an.Sign(ctx, []byte("a list"))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := asn1R(t, sig)
	name := signRecordKey(digest, r)
	if len(b.objs) != 1 || b.buckets[name] != "the-bucket" {
		t.Fatalf("want one record %s in the-bucket, have %v (buckets %v)", name, b.objs, b.buckets)
	}
	if len(b.attempts) != 1 || b.attempts[0] != 1 {
		t.Fatalf("the record's put: want one call with one attempt, have %v", b.attempts)
	}
	var rec signRecord
	if err := json.Unmarshal(b.objs[name].data, &rec); err != nil || !bytes.Equal(rec.Signature, sig) || !bytes.Equal(rec.KeySPKI, pin) {
		t.Fatalf("record %+v, %v", rec, err)
	}
	if len(k.anchor.signs) != 1 || len(k.site.signs) != 0 {
		t.Fatalf("want one list anchor key sign and no site key sign, have %d and %d", len(k.anchor.signs), len(k.site.signs))
	}
}

// asn1R is r of a DER signature, minimal big-endian.
func asn1R(t *testing.T, sig []byte) ([]byte, *big.Int) {
	t.Helper()
	var v struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &v); err != nil {
		t.Fatal(err)
	}
	return v.R.Bytes(), v.R
}

// The record's name, pinned by fixed vectors through SignDigest: a short
// r, and an r whose top bit is set (DER pads it with a zero byte, which
// the name drops).
func TestSignRecordNames(t *testing.T) {
	ctx := context.Background()
	d := sha256.Sum256([]byte("fixed"))
	for _, c := range []struct {
		r    int64
		der  string // the signature's DER, for the record
		want string
	}{
		{0x0cff, "300702020cff020101", "0cff"},
		{0x80ff, "30080203" + "0080ff" + "020101", "80ff"},
	} {
		sig, _ := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(c.r), big.NewInt(1)})
		if got := bytesHex(sig); got != c.der {
			t.Fatalf("r %x: DER %s, want %s", c.r, got, c.der)
		}
		f := newFakeS3()
		rs, k := testRecorder(t, f)
		rs.key = fixedSigner{&k.PublicKey, sig}
		if _, err := rs.SignDigest(ctx, d[:]); err != nil {
			t.Fatal(err)
		}
		want := "v1/services/signs/" + bytesHex(d[:]) + "/" + c.want + ".json"
		if _, ok := f.objs[want]; !ok || len(f.objs) != 1 {
			t.Fatalf("r %x: want the record at %s, have %v", c.r, want, f.objs)
		}
	}
}

func bytesHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
