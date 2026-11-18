package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	for _, c := range []struct {
		name, want string
		err        error
	}{
		{"denied", "nothing logged", errors.New("AccessDenied")},
		{"already recorded", "already recorded", &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold"}},
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

type errSigner struct{ pub *ecdsa.PublicKey }

func (e errSigner) Public() *ecdsa.PublicKey { return e.pub }

func (errSigner) SignDigest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("KMS: throttled")
}
