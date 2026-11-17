package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// The list anchor key's test ARN: testKeyARN's account and region, another
// key id (derived, so that no other key-like value is in the source).
var testAnchorARN = strings.Replace(testKeyARN, "0123abcd", "4567abcd", 1)

// fakeLog is a listLog whose bundle is "bundle:" and the list's SHA-256,
// counting the entries it makes.
type fakeLog struct {
	entries [][]byte
	err     error
}

func fakeBundle(data []byte) []byte {
	h := sha256.Sum256(data)
	return []byte("bundle:" + hex.EncodeToString(h[:]))
}

func (f *fakeLog) Check(bundle, data []byte) error {
	if !bytes.Equal(bundle, fakeBundle(data)) {
		return errors.New("not this list's bundle")
	}
	return nil
}

func (f *fakeLog) Anchor(_ context.Context, data []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.entries = append(f.entries, data)
	return fakeBundle(data), nil
}

// failOnce fails the first put of one key, as a lost race or an S3 error.
type failOnce struct {
	*fakeS3
	key    string
	failed bool
}

func (f *failOnce) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if aws.ToString(in.Key) == f.key && !f.failed {
		f.failed = true
		return nil, errors.New("InternalError")
	}
	return f.fakeS3.PutObject(ctx, in, opts...)
}

// Each new list is logged once, after it is signed and before it is moved:
// its bundle is kept write-once at services/<version>.bundle, written
// before the signature and the list, and a rerun logs nothing.
func TestPublishLogsTheList(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, err := newKMSSigner(ctx, f, testKeyARN, pub(key))
	if err != nil {
		t.Fatal(err)
	}
	b := newFakeS3()
	lg := &fakeLog{}
	a := testService(3, "A")
	v1 := testList(1, make([]byte, 32), a)
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 || !bytes.Equal(lg.entries[0], v1) {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
	bundle, sig, list := b.objs["v1/services/1.bundle"], b.objs["v1/services.json.sig"], b.objs["v1/services.json"]
	if !bytes.Equal(bundle.data, fakeBundle(v1)) {
		t.Fatalf("bundle %q", bundle.data)
	}
	// Etags count the puts: the bundle went first.
	if !(bundle.etag < sig.etag && sig.etag < list.etag) {
		t.Fatalf("put order: bundle %s, sig %s, list %s", bundle.etag, sig.etag, list.etag)
	}
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 {
		t.Fatalf("a rerun: %d signs, %d entries", len(f.signs), len(lg.entries))
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], a, testService(4, "B"))
	if err := publishList(ctx, b, "bucket", k, lg, nil, v2); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 2 || len(lg.entries) != 2 || !bytes.Equal(b.objs["v1/services/2.bundle"].data, fakeBundle(v2)) {
		t.Fatalf("v2: %d signs, %d entries", len(f.signs), len(lg.entries))
	}
}

// A list that is refused is neither signed nor logged (a Rekor entry is
// public and permanent), and nor is one whose version already has a
// bundle for other bytes: a version is never rewritten.
func TestRefusedListNotLogged(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	lg := &fakeLog{}
	a := testService(3, "A")
	b := newFakeS3()
	if err := publishList(ctx, b, "bucket", k, lg, nil, testList(2, make([]byte, 32), a)); err == nil {
		t.Fatal("a first list at version 2")
	}
	v1 := testList(1, make([]byte, 32), a)
	b.set("v1/services/1.bundle", fakeBundle(testList(1, make([]byte, 32))))
	err := publishList(ctx, b, "bucket", k, lg, nil, v1)
	if err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("a stray bundle: %v", err)
	}
	if len(f.signs) != 0 || len(lg.entries) != 0 || b.objs["v1/services.json"].data != nil {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
}

// A log that fails leaves the bucket as it was: no list is served without
// its entry. Run again, it publishes (the site key signs again: the first
// signature was never kept).
func TestLogFailsNothingWritten(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	lg := &fakeLog{err: errors.New("rekor: 503")}
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
	if len(b.objs) != 0 {
		t.Fatalf("written: %v", b.objs)
	}
	lg.err = nil
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 2 || len(lg.entries) != 1 {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
}

// A publish that kept its bundle and then failed to move the list uses
// that bundle when run again: one entry per version.
func TestKeptBundleUsed(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	lg := &fakeLog{}
	b := &failOnce{fakeS3: newFakeS3(), key: "v1/services.json.sig"}
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err == nil {
		t.Fatal("the move should fail")
	}
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil {
		t.Fatal(err)
	}
	if len(lg.entries) != 1 || !bytes.Equal(b.objs["v1/services.json"].data, v1) {
		t.Fatalf("%d entries", len(lg.entries))
	}
}

// A list published before lists were logged (with no log) is logged by a
// rerun with the log, without being signed again; a list moved but whose
// copy failed is logged when it is finished.
func TestPublishedListLoggedLater(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.objs["v1/services/1.bundle"]; ok {
		t.Fatal("logged with no log")
	}
	lg := &fakeLog{}
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 || !bytes.Equal(b.objs["v1/services/1.bundle"].data, fakeBundle(v1)) {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
	// Run again: the kept bundle is checked and used.
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err != nil || len(lg.entries) != 1 {
		t.Fatalf("%v, %d entries", err, len(lg.entries))
	}
	// A kept bundle for other bytes is refused here too.
	b.set("v1/services/1.bundle", []byte("bundle:other"))
	if err := publishList(ctx, b, "bucket", k, lg, nil, v1); err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("%v", err)
	}
}

// The list anchor key's flags are refused before KMS is called: an alias
// or a key id, the site key itself, another account or region, an unknown
// instance; then a key that isn't P-256 (the fake is Ed25519).
func TestRekorLogRefuses(t *testing.T) {
	ctx := context.Background()
	f := newFakeKMS(testKey("site"))
	for _, c := range []struct{ key, instance, want string }{
		{"alias/vettid-votes-staging-list-anchor", "staging", "not an alias"},
		{testKeyARN, "staging", "is -kms"},
		{strings.Replace(testAnchorARN, "123456789012", "210987654321", 1), "staging", "partition, region and account"},
		{strings.Replace(testAnchorARN, "us-east-1", "eu-west-1", 1), "staging", "partition, region and account"},
		{testAnchorARN, "", "-sigstore"},
		{testAnchorARN, "prod", "-sigstore"},
	} {
		if _, err := newRekorLog(ctx, f, c.key, testKeyARN, c.instance); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q: %v, want %q", c.key, c.instance, err, c.want)
		}
	}
	if f.publicReads != 0 {
		t.Fatalf("KMS called %d times", f.publicReads)
	}
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging"); err == nil || !strings.Contains(err.Error(), "ECC_NIST_P256") {
		t.Fatalf("an Ed25519 key: %v", err)
	}
	if len(f.signs) != 0 {
		t.Fatal("signed")
	}
}
