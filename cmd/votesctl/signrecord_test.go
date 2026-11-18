package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/vettid/service-vault/anchor"

	"github.com/vettid/votes/signer"
)

// testRecorder is a recordingSigner over a key in memory, recording in f.
func testRecorder(t *testing.T, f s3API) (*recordingSigner, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingSigner{key: anchor.LocalSigner{Key: k}, spki: spki, c: f, bucket: "bucket"}, k
}

func TestSignRecorded(t *testing.T) {
	f := newFakeS3()
	rs, k := testRecorder(t, f)
	d := sha256.Sum256([]byte("a list"))
	sig, err := rs.SignDigest(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	r, err := signer.RFromDER(sig)
	if err != nil {
		t.Fatal(err)
	}
	key := signRecordKey(d[:], r)
	o, ok := f.objs[key]
	if !ok || len(f.objs) != 1 {
		t.Fatalf("want one record at %s, have %v", key, f.objs)
	}
	var rec signRecord
	if err := json.Unmarshal(o.data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.V != 1 || !bytes.Equal(rec.KeySPKI, rs.spki) || !bytes.Equal(rec.Digest, d[:]) || !bytes.Equal(rec.Signature, sig) {
		t.Fatalf("record %+v doesn't hold the key, the digest and the signature returned", rec)
	}
	if !ecdsa.VerifyASN1(&k.PublicKey, rec.Digest, rec.Signature) {
		t.Fatal("the recorded signature doesn't verify under the key over the digest")
	}
	if !strings.Contains(o.cc, "immutable") {
		t.Fatalf("the record isn't written as a kept object: Cache-Control %q", o.cc)
	}
}

// The record name: under v1/services/, which the bucket policy keeps
// write-once and never deleted for every principal and the publish role
// may write (cdk/test: PublishedWriteOnce, PublishedNeverDeleted,
// ServiceList); lowercase hex; r without leading zero bytes.
func TestSignRecordKey(t *testing.T) {
	d := bytes.Repeat([]byte{0xAB}, 32)
	r := []byte{0x0C, 0xFF}
	want := "v1/services/signs/" + strings.Repeat("ab", 32) + "/0cff.json"
	if got := signRecordKey(d, r); got != want {
		t.Fatalf("signRecordKey = %s, want %s", got, want)
	}
	if !strings.HasPrefix(signRecordKey(d, r), "v1/services/") {
		t.Fatal("a record must be under v1/services/, the write-once prefix")
	}
	// RFromDER drops a leading zero byte (DER pads r whose top bit is set).
	for i := 0; i < 64; i++ {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig, _ := ecdsa.SignASN1(rand.Reader, k, d)
		got, err := signer.RFromDER(sig)
		if err != nil || len(got) == 0 || got[0] == 0 {
			t.Fatalf("r %s: want big-endian bytes without a leading zero byte (%v)", hex.EncodeToString(got), err)
		}
	}
}

// failingS3 fails every put with err.
type failingS3 struct {
	*fakeS3
	err error
}

func (f failingS3) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, f.err
}

func TestRecordFailureNoSignature(t *testing.T) {
	precond := &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold"}
	for _, c := range []struct {
		name, want string
		err        error
	}{
		{"denied", "nothing logged", errors.New("AccessDenied")},
		{"taken, reads as absent", "compare it with this signature", precond},
	} {
		t.Run(c.name, func(t *testing.T) {
			rs, _ := testRecorder(t, failingS3{newFakeS3(), c.err})
			d := sha256.Sum256([]byte("a list"))
			sig, err := rs.SignDigest(context.Background(), d[:])
			if sig != nil || err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("SignDigest = %x, %v: want no signature and an error saying %q", sig, err, c.want)
			}
		})
	}
}

// s3412 answers a put of an existing name with S3's own 412.
type s3412 struct{ *fakeS3 }

func (f s3412) PutObject(ctx context.Context, in *s3.PutObjectInput, o ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if _, ok := f.objs[*in.Key]; ok {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold"}
	}
	return f.fakeS3.PutObject(ctx, in, o...)
}

// fixedSigner answers every sign with sig.
type fixedSigner struct {
	pub *ecdsa.PublicKey
	sig []byte
}

func (f fixedSigner) Public() *ecdsa.PublicKey { return f.pub }

func (f fixedSigner) SignDigest(context.Context, []byte) ([]byte, error) { return f.sig, nil }

// A name taken before the call: the same signature again, or another
// with the same r over the digest, here (r, N-s), is a signer anomaly.
// Neither returns a signature or replaces the record.
func TestRecordTakenName(t *testing.T) {
	ctx := context.Background()
	f := s3412{newFakeS3()}
	rs, k := testRecorder(t, f)
	d := sha256.Sum256([]byte("a list"))
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	rs.key = fixedSigner{&k.PublicKey, sig}
	if got, err := rs.SignDigest(ctx, d[:]); err != nil || !bytes.Equal(got, sig) {
		t.Fatalf("first sign: %x, %v", got, err)
	}
	if got, err := rs.SignDigest(ctx, d[:]); got != nil || err == nil || !strings.Contains(err.Error(), "ANOMALY: KMS returned a signature it had returned before") {
		t.Fatalf("the same signature again: %x, %v", got, err)
	}
	var v struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &v); err != nil {
		t.Fatal(err)
	}
	v.S.Sub(elliptic.P256().Params().N, v.S)
	neg, _ := asn1.Marshal(v)
	if !ecdsa.VerifyASN1(&k.PublicKey, d[:], neg) {
		t.Fatal("(r, N-s) doesn't verify")
	}
	rs.key = fixedSigner{&k.PublicKey, neg}
	if got, err := rs.SignDigest(ctx, d[:]); got != nil || err == nil || !strings.Contains(err.Error(), "ANOMALY: KMS returned a second signature with the same r") {
		t.Fatalf("another signature with the same r: %x, %v", got, err)
	}
	if len(f.objs) != 1 {
		t.Fatalf("want the first record only, have %d", len(f.objs))
	}
}

// listAnchorer, over the KMS key anchorPublicKey returns, records each
// signature: a real Anchorer.Sign through a fake KMS leaves its record.
// (TestPublishSetupRecords covers the path from publish.)
func TestListAnchorerRecords(t *testing.T) {
	ctx := context.Background()
	ec := testECKey(t)
	f := &anchorFake{fakeKMS: newFakeKMS(testKey("site")), ec: ec}
	key, spki, err := anchorPublicKey(ctx, f, testAnchorARN)
	if err != nil {
		t.Fatal(err)
	}
	b := newFakeS3()
	a, err := listAnchorer("staging", key, spki, b, "bucket")
	if err != nil {
		t.Fatal(err)
	}
	digest, sig, err := a.Sign(ctx, []byte("a list"))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := signer.RFromDER(sig)
	o, ok := b.objs[signRecordKey(digest, r)]
	if !ok || len(b.objs) != 1 || len(f.signs) != 1 {
		t.Fatalf("want one KMS sign and its record, have %d signs, records %v", len(f.signs), b.objs)
	}
	var rec signRecord
	if err := json.Unmarshal(o.data, &rec); err != nil || !bytes.Equal(rec.Signature, sig) || !bytes.Equal(rec.KeySPKI, spki) {
		t.Fatalf("record %+v, %v", rec, err)
	}
}

// A second write of the same name is refused by S3 (If-None-Match: *), so
// a record is never replaced.
func TestRecordNeverReplaced(t *testing.T) {
	f := newFakeS3()
	rs, _ := testRecorder(t, f)
	d := sha256.Sum256([]byte("a list"))
	sig, err := rs.SignDigest(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	r, _ := signer.RFromDER(sig)
	key := signRecordKey(d[:], r)
	before := f.objs[key]
	if err := writeOnce(context.Background(), f, "bucket", key, []byte("other"), "application/json"); err == nil {
		t.Fatal("a second write of a record went through")
	}
	if !bytes.Equal(f.objs[key].data, before.data) {
		t.Fatal("the record changed")
	}
}

// otherKeySigner answers with a valid signature under another key.
type otherKeySigner struct {
	pub   *ecdsa.PublicKey
	other *ecdsa.PrivateKey
}

func (o otherKeySigner) Public() *ecdsa.PublicKey { return o.pub }

func (o otherKeySigner) SignDigest(_ context.Context, d []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, o.other, d)
}

// The record is written before the Anchorer checks the signature, so a
// signature the Anchorer refuses (and never logs) is recorded too, and a
// signer's error leaves no record.
func TestRecordBeforeAnchorerCheck(t *testing.T) {
	f := newFakeS3()
	rs, k := testRecorder(t, f)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs.key = otherKeySigner{pub: &k.PublicKey, other: other}
	a, err := anchor.NewSigner("staging", rs)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Sign(context.Background(), []byte("a list")); err == nil {
		t.Fatal("the Anchorer took a signature under another key")
	}
	if len(f.objs) != 1 {
		t.Fatalf("want the signature recorded before the Anchorer's check, have %d records", len(f.objs))
	}

	g := newFakeS3()
	rs2, _ := testRecorder(t, g)
	rs2.key = errSigner{rs2.key.Public()}
	if sig, err := rs2.SignDigest(context.Background(), make([]byte, 32)); sig != nil || err == nil || len(g.objs) != 0 {
		t.Fatalf("a failed sign: want no signature and no record, have %x, %v, %d records", sig, err, len(g.objs))
	}
}

// Sign is KMS's for anchorFake's P-256 key: ECDSA_SHA_256 over a DIGEST,
// as awsio.Key asks. Without ec it is fakeKMS's.
func (a *anchorFake) Sign(ctx context.Context, in *kms.SignInput, o ...func(*kms.Options)) (*kms.SignOutput, error) {
	if a.ec == nil {
		return a.fakeKMS.Sign(ctx, in, o...)
	}
	a.signs = append(a.signs, in)
	if in.MessageType != kmstypes.MessageTypeDigest || in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != 32 {
		return nil, errors.New("ValidationException: unsupported message type or algorithm")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, a.ec, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{KeyId: in.KeyId, Signature: sig, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256}, nil
}

type errSigner struct{ pub *ecdsa.PublicKey }

func (e errSigner) Public() *ecdsa.PublicKey { return e.pub }

func (errSigner) SignDigest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("KMS: throttled")
}
