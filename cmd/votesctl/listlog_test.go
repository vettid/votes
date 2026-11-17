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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/vettid/votes/site"
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
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 || !bytes.Equal(lg.entries[0], v1) {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
	bundle, sig, list := b.objs["v1/services/1.bundle"], b.objs["v1/services.json.sig"], b.objs["v1/services.json"]
	if !bytes.Equal(bundle.data, fakeBundle(v1)) || bundle.cc != "public, max-age=31536000, immutable" {
		t.Fatalf("bundle %q, Cache-Control %q", bundle.data, bundle.cc)
	}
	// Etags count the puts: the bundle went first.
	if n := func(o fakeObject) int { v, _ := strconv.Atoi(strings.Trim(o.etag, `"`)); return v }; !(n(bundle) < n(sig) && n(sig) < n(list)) {
		t.Fatalf("put order: bundle %s, sig %s, list %s", bundle.etag, sig.etag, list.etag)
	}
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 {
		t.Fatalf("a rerun: %d signs, %d entries", len(f.signs), len(lg.entries))
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], a, testService(4, "B"))
	if err := publishList(ctx, b, "bucket", k, lg, v2); err != nil {
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
	if err := publishList(ctx, b, "bucket", k, lg, testList(2, make([]byte, 32), a)); err == nil {
		t.Fatal("a first list at version 2")
	}
	v1 := testList(1, make([]byte, 32), a)
	b.set("v1/services/1.bundle", fakeBundle(testList(1, make([]byte, 32))))
	err := publishList(ctx, b, "bucket", k, lg, v1)
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
	if err := publishList(ctx, b, "bucket", k, lg, v1); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
	if len(b.objs) != 0 {
		t.Fatalf("written: %v", b.objs)
	}
	lg.err = nil
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
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
	if err := publishList(ctx, b, "bucket", k, lg, v1); err == nil {
		t.Fatal("the move should fail")
	}
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
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
	if err := publishList(ctx, b, "bucket", k, nil, v1); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.objs["v1/services/1.bundle"]; ok {
		t.Fatal("logged with no log")
	}
	lg := &fakeLog{}
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
		t.Fatal(err)
	}
	if len(f.signs) != 1 || len(lg.entries) != 1 || !bytes.Equal(b.objs["v1/services/1.bundle"].data, fakeBundle(v1)) {
		t.Fatalf("%d signs, %d entries", len(f.signs), len(lg.entries))
	}
	// Run again: the kept bundle is checked and used.
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil || len(lg.entries) != 1 {
		t.Fatalf("%v, %d entries", err, len(lg.entries))
	}
	// A kept bundle for other bytes is refused here too.
	b.set("v1/services/1.bundle", []byte("bundle:other"))
	if err := publishList(ctx, b, "bucket", k, lg, v1); err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("%v", err)
	}
}

// The list anchor key's flags are refused before KMS is called: an alias
// or a key id, the site key itself, another account, region or partition,
// an unknown instance, no pin; then a key that isn't P-256 (the fake is
// Ed25519).
func TestRekorLogRefuses(t *testing.T) {
	ctx := context.Background()
	f := &anchorFake{fakeKMS: newFakeKMS(testKey("site"))}
	pin := []byte("pin")
	for _, c := range []struct {
		key, instance string
		pin           []byte
		want          string
	}{
		{"alias/vettid-votes-staging-list-anchor", "staging", pin, "not an alias"},
		{testKeyARN, "staging", pin, "is -kms"},
		{strings.Replace(testAnchorARN, "123456789012", "210987654321", 1), "staging", pin, "partition, region and account"},
		{strings.Replace(testAnchorARN, "us-east-1", "eu-west-1", 1), "staging", pin, "partition, region and account"},
		{strings.Replace(testAnchorARN, "arn:aws:", "arn:aws-us-gov:", 1), "staging", pin, "partition, region and account"},
		{testAnchorARN, "", pin, "-sigstore"},
		{testAnchorARN, "prod", pin, "-sigstore"},
		{testAnchorARN, "staging", nil, "-list-anchor-pub"},
	} {
		if _, err := newRekorLog(ctx, f, c.key, testKeyARN, c.instance, c.pin); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q: %v, want %q", c.key, c.instance, err, c.want)
		}
	}
	if f.publicReads != 0 || f.tagReads != 0 {
		t.Fatalf("KMS called: %d reads, %d tag reads", f.publicReads, f.tagReads)
	}
	// KMS's answer: for another key, or a key that doesn't sign with
	// ECDSA_SHA_256 (the fake is Ed25519), or not P-256 (awsio.NewKeyFrom).
	f.keyID = testKeyARN
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", pin); err == nil || !strings.Contains(err.Error(), "answered for key") {
		t.Fatalf("another key's answer: %v", err)
	}
	f.keyID = ""
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", pin); err == nil || !strings.Contains(err.Error(), "ECDSA_SHA_256") {
		t.Fatalf("an Ed25519 key: %v", err)
	}
	f.algs = append(f.algs, kmstypes.SigningAlgorithmSpecEcdsaSha256)
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", pin); err == nil || !strings.Contains(err.Error(), "ECC_NIST_P256") {
		t.Fatalf("not a P-256 key: %v", err)
	}
	if len(f.signs) != 0 || f.publicReads != 3 {
		t.Fatalf("%d signs, %d reads (one per attempt)", len(f.signs), f.publicReads)
	}
}

// anchorFake is a fake KMS for the list anchor key: a P-256 key with
// tags (or fakeKMS's Ed25519 key, when ec is nil).
type anchorFake struct {
	*fakeKMS
	ec       *ecdsa.PrivateKey
	tags     []kmstypes.Tag
	pages    [][]kmstypes.Tag // overrides tags: one page each
	tagReads int
}

func (a *anchorFake) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, o ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if a.ec == nil {
		return a.fakeKMS.GetPublicKey(ctx, in, o...)
	}
	a.publicReads++
	spki, _ := x509.MarshalPKIXPublicKey(&a.ec.PublicKey)
	return &kms.GetPublicKeyOutput{KeyId: in.KeyId, KeySpec: kmstypes.KeySpecEccNistP256, KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256}, PublicKey: spki}, nil
}

func (a *anchorFake) ListResourceTags(_ context.Context, in *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	a.tagReads++
	if a.pages == nil {
		return &kms.ListResourceTagsOutput{Tags: a.tags}, nil
	}
	// Pages: the marker is the next page's index.
	i, _ := strconv.Atoi(aws.ToString(in.Marker))
	out := &kms.ListResourceTagsOutput{Tags: a.pages[i]}
	if i+1 < len(a.pages) {
		out.Truncated, out.NextMarker = true, aws.String(strconv.Itoa(i+1))
	}
	return out, nil
}

// The tag is found on any page of the key's tags, and its absence only
// after the last.
func TestKeySigstorePages(t *testing.T) {
	ctx := context.Background()
	tag := func(k, v string) kmstypes.Tag { return kmstypes.Tag{TagKey: aws.String(k), TagValue: aws.String(v)} }
	f := &anchorFake{fakeKMS: newFakeKMS(testKey("site")), pages: [][]kmstypes.Tag{{tag("a", "1"), tag("b", "2")}, {tag(sigstoreTag, "production")}}}
	if s, err := keySigstore(ctx, f, testAnchorARN); err != nil || s != "production" || f.tagReads != 2 {
		t.Fatalf("%q %v, %d reads", s, err, f.tagReads)
	}
	f = &anchorFake{fakeKMS: newFakeKMS(testKey("site")), pages: [][]kmstypes.Tag{{tag("a", "1")}, {tag("b", "2")}}}
	if _, err := keySigstore(ctx, f, testAnchorARN); err == nil || !strings.Contains(err.Error(), "no vettid:sigstore tag") || f.tagReads != 2 {
		t.Fatalf("%v, %d reads", err, f.tagReads)
	}
}

// A P-256 key is checked against the pin, then its tag against -sigstore,
// before anything is signed: a wrong pin, a missing tag and another
// instance's tag are each refused.
func TestRekorLogPinAndTag(t *testing.T) {
	ctx := context.Background()
	ec := testECKey(t)
	f := &anchorFake{fakeKMS: newFakeKMS(testKey("site")), ec: ec}
	spki, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	other, _ := x509.MarshalPKIXPublicKey(&testECKey(t).PublicKey)
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", other); err == nil || !strings.Contains(err.Error(), "not -list-anchor-pub") || f.tagReads != 0 {
		t.Fatalf("another pin: %v (%d tag reads)", err, f.tagReads)
	}
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", spki); err == nil || !strings.Contains(err.Error(), "no vettid:sigstore tag") {
		t.Fatalf("no tag: %v", err)
	}
	f.tags = []kmstypes.Tag{{TagKey: aws.String("other"), TagValue: aws.String("staging")}, {TagKey: aws.String(sigstoreTag), TagValue: aws.String("production")}}
	if _, err := newRekorLog(ctx, f, testAnchorARN, testKeyARN, "staging", spki); err == nil || !strings.Contains(err.Error(), "tag says production, -sigstore says staging") {
		t.Fatalf("another instance's tag: %v", err)
	}
	if len(f.signs) != 0 {
		t.Fatal("signed")
	}
	// The tag agrees: the key is the pinned one (the rest fetches the
	// trusted root, which this test doesn't).
	if s, err := keySigstore(ctx, &anchorFake{fakeKMS: f.fakeKMS, tags: []kmstypes.Tag{{TagKey: aws.String(sigstoreTag), TagValue: aws.String("staging")}}}, testAnchorARN); err != nil || s != "staging" {
		t.Fatalf("%q %v", s, err)
	}
	if _, got, err := anchorPublicKey(ctx, f, testAnchorARN); err != nil || !bytes.Equal(got, spki) {
		t.Fatalf("%v", err)
	}
}

// Every list from the first one logged on has a bundle: the next list is
// refused, before signing, while the current one has none (published
// before lists were logged); its rerun logs it, then the next publishes.
func TestPreviousBundleRequired(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	a := testService(3, "A")
	v1 := testList(1, make([]byte, 32), a)
	if err := publishList(ctx, b, "bucket", k, nil, v1); err != nil {
		t.Fatal(err)
	}
	lg := &fakeLog{}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], a)
	err := publishList(ctx, b, "bucket", k, lg, v2)
	if err == nil || !strings.Contains(err.Error(), "version 1 is current without its bundle") || len(f.signs) != 1 || len(lg.entries) != 0 {
		t.Fatalf("%v, %d signs, %d entries", err, len(f.signs), len(lg.entries))
	}
	if err := publishList(ctx, b, "bucket", k, lg, v1); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, b, "bucket", k, lg, v2); err != nil || len(lg.entries) != 2 {
		t.Fatalf("%v, %d entries", err, len(lg.entries))
	}
}

// A -sigstore (or list anchor key) that isn't the stack's: the published
// list's bundle doesn't verify, and the next list is refused before it is
// signed or logged.
func TestWrongInstanceRefused(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	a := testService(3, "A")
	v1 := testList(1, make([]byte, 32), a)
	if err := publishList(ctx, b, "bucket", k, &fakeLog{}, v1); err != nil {
		t.Fatal(err)
	}
	other := &otherLog{}
	h1 := sha256.Sum256(v1)
	err := publishList(ctx, b, "bucket", k, other, testList(2, h1[:], a))
	if err == nil || !strings.Contains(err.Error(), "-sigstore") || !strings.Contains(err.Error(), "1.bundle") {
		t.Fatalf("%v", err)
	}
	if len(f.signs) != 1 || other.entries != 0 {
		t.Fatalf("%d signs, %d entries", len(f.signs), other.entries)
	}
}

// otherLog is a log on another instance: no bundle verifies on it.
type otherLog struct{ entries int }

func (o *otherLog) Check([]byte, []byte) error { return errors.New("not on this instance") }
func (o *otherLog) Anchor(context.Context, []byte) ([]byte, error) {
	o.entries++
	return nil, errors.New("unreachable")
}

// A stray bundle at the current list's version is refused before its
// history is written.
func TestStrayBundleBeforeHistory(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, v1); err != nil {
		t.Fatal(err)
	}
	delete(b.objs, "v1/services/1.json")
	delete(b.objs, "v1/services/1.json.sig")
	b.set("v1/services/1.bundle", []byte("bundle:other"))
	lg := &fakeLog{}
	if err := publishList(ctx, b, "bucket", k, lg, v1); err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("%v", err)
	}
	if _, ok := b.objs["v1/services/1.json"]; ok || len(lg.entries) != 0 {
		t.Fatalf("history written or logged: %d entries", len(lg.entries))
	}
}

// rekorLog checks bundles with site.Anchors: service-vault's anchor
// vector (a real staging bundle and its trusted root) verifies for its own
// document and key only, and Anchor refuses a bundle that doesn't verify.
func TestRekorLogCheck(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/service-vault")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "vote", "testdata", "anchor-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		AnchorKey   []byte          `json:"anchor_key"`
		Proposal    string          `json:"proposal"`
		Bundle      json.RawMessage `json:"bundle"`
		TrustedRoot json.RawMessage `json:"trusted_root"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(v.TrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(v.Proposal)
	other, _ := x509.MarshalPKIXPublicKey(&testECKey(t).PublicKey)
	r := &rekorLog{v: site.NewAnchorsWith(tr), spki: v.AnchorKey, instance: "staging"}
	if err := r.Check(v.Bundle, doc); err != nil {
		t.Fatalf("the vector: %v", err)
	}
	if err := r.Check(v.Bundle, append(doc, ' ')); err == nil {
		t.Fatal("other bytes")
	}
	if err := (&rekorLog{v: r.v, spki: other, instance: "staging"}).Check(v.Bundle, doc); err == nil {
		t.Fatal("another key")
	}
	// The staging bundle under production's trusted root: another instance.
	emb, _, err := site.EmbeddedRoot(site.Production)
	if err != nil {
		t.Fatal(err)
	}
	prod, err := root.NewTrustedRootFromJSON(emb)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&rekorLog{v: site.NewAnchorsWith(prod), spki: v.AnchorKey, instance: "production"}).Check(v.Bundle, doc); err == nil || !strings.Contains(err.Error(), "production") {
		t.Fatalf("another instance: %v", err)
	}
	r.a = fixedAnchor(v.Bundle)
	if b, err := r.Anchor(context.Background(), doc); err != nil || !bytes.Equal(b, v.Bundle) {
		t.Fatalf("anchor: %v", err)
	}
	if _, err := r.Anchor(context.Background(), append(doc, ' ')); err == nil || !strings.Contains(err.Error(), "doesn't verify") {
		t.Fatalf("an entry for other bytes: %v", err)
	}
}

// fixedAnchor answers every Anchor with one bundle.
type fixedAnchor json.RawMessage

func (f fixedAnchor) Anchor(context.Context, []byte) (json.RawMessage, error) {
	return json.RawMessage(f), nil
}

func testECKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
