package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/votes/site"
)

// fakeS3 is a bucket with S3's conditional writes (If-None-Match: *,
// If-Match) and NoSuchKey.
type fakeS3 struct {
	objs map[string]fakeObject
	n    int
}

type fakeObject struct {
	data []byte
	etag string
	cc   string // its Cache-Control
}

func newFakeS3() *fakeS3 { return &fakeS3{objs: map[string]fakeObject{}} }

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	o, ok := f.objs[aws.ToString(in.Key)]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(o.data)), ETag: aws.String(o.etag)}, nil
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	k := aws.ToString(in.Key)
	// As the bucket policy: under v1/services/ a put needs If-None-Match.
	if strings.HasPrefix(k, "v1/services/") && aws.ToString(in.IfNoneMatch) != "*" {
		return nil, errors.New("AccessDenied: write-once")
	}
	o, exists := f.objs[k]
	if aws.ToString(in.IfNoneMatch) == "*" && exists || in.IfMatch != nil && (!exists || o.etag != aws.ToString(in.IfMatch)) {
		return nil, errors.New("PreconditionFailed")
	}
	b, _ := io.ReadAll(in.Body)
	f.n++
	f.objs[k] = fakeObject{data: b, etag: fmt.Sprintf(`"%d"`, f.n), cc: aws.ToString(in.CacheControl)}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) set(key string, data []byte) {
	f.n++
	f.objs[key] = fakeObject{data: data, etag: fmt.Sprintf(`"%d"`, f.n)}
}

func testList(version int64, previous []byte, services ...site.Service) []byte {
	if services == nil {
		services = []site.Service{}
	}
	b, _ := json.Marshal(&site.ServiceList{V: 1, Version: version, Previous: previous, Services: services})
	b, _ = vote.Canonicalize(b)
	return b
}

func testService(b byte, name string) site.Service {
	ik := bytes.Repeat([]byte{b}, 32)
	return site.Service{ServiceID: site.ServiceID(ik), Name: name, IKs: [][]byte{ik}, AnchorKeys: []site.AnchorKey{}}
}

// Every check that can refuse a list runs before KMS signs it, and a rerun
// of a list already signed (published, or interrupted) signs nothing: one
// publish of a new list is exactly one signature.
func TestPublishSignsOnlyWhatItPublishes(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, err := newKMSSigner(ctx, f, testKeyARN, pub(key))
	if err != nil {
		t.Fatal(err)
	}
	b := newFakeS3()
	signs := func(want int, when string) {
		t.Helper()
		if len(f.signs) != want {
			t.Fatalf("%s: %d signs, want %d", when, len(f.signs), want)
		}
	}
	a, a2 := testService(3, "A"), testService(4, "B")

	// The first list must be version 1 with a zero previous.
	if err := publishList(ctx, b, "bucket", k, nil, nil, testList(2, make([]byte, 32), a)); err == nil || !strings.Contains(err.Error(), "first list") {
		t.Fatalf("a first list at version 2: %v", err)
	}
	// A list the site would refuse: an unknown member, a service listed twice.
	if err := publishList(ctx, b, "bucket", k, nil, nil, []byte(`{"extra":1,"previous":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","services":[],"v":1,"version":1}`)); err == nil {
		t.Fatal("an unknown member")
	}
	if err := publishList(ctx, b, "bucket", k, nil, nil, testList(1, make([]byte, 32), a, a)); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a service twice: %v", err)
	}
	signs(0, "refused first lists")

	v1 := testList(1, make([]byte, 32), a)
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	signs(1, "the first list")
	// A rerun of the published list: nothing signed.
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	signs(1, "a rerun")
	h1 := sha256.Sum256(v1)
	if err := publishList(ctx, b, "bucket", k, nil, nil, testList(3, h1[:], a)); err == nil || !strings.Contains(err.Error(), "next version is 2") {
		t.Fatalf("a gap: %v", err)
	}
	if err := publishList(ctx, b, "bucket", k, nil, nil, testList(2, h1[:], a2)); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("a dropped service: %v", err)
	}
	signs(1, "refused next lists")

	// An interrupted publish (the signature written, not the list): the
	// rerun finishes it with the bucket's signature.
	v2 := testList(2, h1[:], a, a2)
	sig2, _ := signList(ctx, secretSigner(key), v2)
	b.set("v1/services.json.sig", sig2)
	if err := publishList(ctx, b, "bucket", k, nil, nil, v2); err != nil {
		t.Fatal(err)
	}
	signs(1, "an interrupted publish finished")
	if !bytes.Equal(b.objs["v1/services.json"].data, v2) || !bytes.Equal(b.objs["v1/services/2.json.sig"].data, sig2) {
		t.Fatal("v2 not published")
	}

	// A published pair that doesn't verify: refused before signing.
	b.set("v1/services.json.sig", bytes.Repeat([]byte{1}, 64))
	h2 := sha256.Sum256(v2)
	if err := publishList(ctx, b, "bucket", k, nil, nil, testList(3, h2[:], a, a2)); err == nil || !strings.Contains(err.Error(), "restore the pair") {
		t.Fatalf("a broken pair: %v", err)
	}
	signs(1, "a broken pair")
}

// The flag day: the published list is under the secret's key, the next
// under KMS's. Without -previous-site-key it is refused before signing;
// with it, it is published, and the list after needs no flag.
func TestPublishFlagDay(t *testing.T) {
	ctx := context.Background()
	old, nw := testKey("old"), testKey("new")
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", secretSigner(old), nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	f := newFakeKMS(nw)
	k, err := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"))
	// With the list log, as every -kms publish: the first list under the
	// new key is logged, the old key's list (from -secret) isn't.
	lg := &fakeLog{}
	if err := publishList(ctx, b, "bucket", k, lg, nil, v2); err == nil || !strings.Contains(err.Error(), "-previous-site-key") {
		t.Fatalf("without the previous key: %v", err)
	}
	if len(f.signs) != 0 || len(lg.entries) != 0 {
		t.Fatal("signed or logged a list it then refused")
	}
	if err := publishList(ctx, b, "bucket", k, lg, pub(testKey("third")), v2); err == nil || len(f.signs) != 0 || len(lg.entries) != 0 {
		t.Fatalf("another previous key: %v, %d signs", err, len(f.signs))
	}
	if err := publishList(ctx, b, "bucket", k, lg, pub(old), v2); err != nil || len(f.signs) != 1 {
		t.Fatalf("the flag day: %v, %d signs", err, len(f.signs))
	}
	if len(lg.entries) != 1 || !bytes.Equal(b.objs["v1/services/2.bundle"].data, fakeBundle(v2)) {
		t.Fatalf("the flag day's list isn't logged: %d entries", len(lg.entries))
	}
	if _, ok := b.objs["v1/services/1.bundle"]; ok {
		t.Fatal("the old key's list was logged")
	}
	if _, err := site.ParseServiceList(b.objs["v1/services/2.json"].data, b.objs["v1/services/2.json.sig"].data, pub(nw)); err != nil {
		t.Fatalf("v2 isn't under the new key: %v", err)
	}
	if _, err := site.ParseServiceList(b.objs["v1/services/1.json"].data, b.objs["v1/services/1.json.sig"].data, pub(old)); err != nil {
		t.Fatalf("v1's copy isn't the old key's: %v", err)
	}
	h2 := sha256.Sum256(v2)
	if err := publishList(ctx, b, "bucket", k, lg, nil, testList(3, h2[:], testService(3, "A"))); err != nil || len(f.signs) != 2 || len(lg.entries) != 2 {
		t.Fatalf("after the flag day: %v, %d signs, %d entries", err, len(f.signs), len(lg.entries))
	}
}

// One attempt only: each signature is emailed.
func TestKMSSignNoRetry(t *testing.T) {
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(context.Background(), f, testKeyARN, pub(key))
	if _, err := signList(context.Background(), k, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if len(f.retries) != 1 || f.retries[0] != 1 {
		t.Fatalf("RetryMaxAttempts %v", f.retries)
	}
	var o kms.Options
	noRetry(&o)
	if o.RetryMaxAttempts != 1 {
		t.Fatal(o.RetryMaxAttempts)
	}
}

// The watch topics are in the key's partition, region and account, and
// the -kms ARN's form is checked before any AWS call.
func TestKMSPublishBindsTopics(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	ok := &fakeSNS{pages: map[string][][]snstypes.Subscription{
		topicA: {{sub(topicA, "confirmed", "email")}}, topicB: {{sub(topicB, "confirmed", "email")}}}}
	for _, w := range []string{
		strings.ReplaceAll(topicA+","+topicB, "us-east-1", "eu-west-1"),
		strings.ReplaceAll(topicA+","+topicB, "123456789012", "210987654321"),
		strings.ReplaceAll(topicA+","+topicB, "arn:aws:", "arn:aws-cn:"),
	} {
		f := newFakeKMS(key)
		if _, err := kmsPublishSigner(ctx, publishArgs{kms: testKeyARN, siteKey: base64Key(pub(key)), watch: w}, f, ok); err == nil ||
			!strings.Contains(err.Error(), "key's partition, region and account") || f.publicReads != 0 {
			t.Errorf("%s: %v", w, err)
		}
	}
	// The ARN's form, before reading the file or calling AWS.
	err := publish(ctx, publishArgs{kms: "alias/vettid-votes-staging-site", siteKey: "k", watch: "w", listAnchor: testAnchorARN, listAnchorPub: "cGlu", sigstore: "staging", bucket: "b", in: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "not an alias") {
		t.Fatalf("%v", err)
	}
	if err := publish(ctx, publishArgs{secret: "s", previous: "k", bucket: "b", in: "x"}); err == nil || !strings.Contains(err.Error(), "go with -kms") {
		t.Fatalf("-previous-site-key with -secret: %v", err)
	}
}

// A copy already at the next version's key is checked before signing: other
// bytes (a planted copy, or a pair rolled back past it) are refused with
// no signature; a copy of this list's own signature is used, not signed.
func TestPublishCopyBeforeSigning(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"), testService(4, "B"))
	b.set("v1/services/2.json", []byte("planted"))
	if err := publishList(ctx, b, "bucket", k, nil, nil, v2); err == nil || !strings.Contains(err.Error(), "other bytes") || len(f.signs) != 1 {
		t.Fatalf("a planted copy: %v, %d signs", err, len(f.signs))
	}
	delete(b.objs, "v1/services/2.json")
	b.set("v1/services/2.json.sig", bytes.Repeat([]byte{7}, 64))
	if err := publishList(ctx, b, "bucket", k, nil, nil, v2); err == nil || !strings.Contains(err.Error(), "other bytes") || len(f.signs) != 1 {
		t.Fatalf("a planted signature copy: %v, %d signs", err, len(f.signs))
	}
	// The copy of v2's own signature (a pair rolled back after v2 was
	// current): used as v2's signature, nothing signed.
	sig2, _ := signList(ctx, secretSigner(key), v2)
	b.set("v1/services/2.json", v2)
	b.set("v1/services/2.json.sig", sig2)
	if err := publishList(ctx, b, "bucket", k, nil, nil, v2); err != nil || len(f.signs) != 1 {
		t.Fatalf("its own copy: %v, %d signs", err, len(f.signs))
	}
	if !bytes.Equal(b.objs["v1/services.json.sig"].data, sig2) || !bytes.Equal(b.objs["v1/services.json"].data, v2) {
		t.Fatal("v2 not published from its copy")
	}
}

// -previous-site-key only on the flag day: refused when it is -site-key,
// on a first list, a rerun, a resume, or a published list already under
// the new key; never a signature for any of them.
func TestPreviousKeyOnlyOnFlagDay(t *testing.T) {
	ctx := context.Background()
	old, nw := testKey("old"), testKey("new")
	f := newFakeKMS(nw)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"))

	if err := publishList(ctx, newFakeS3(), "bucket", k, nil, pub(nw), v1); err == nil || !strings.Contains(err.Error(), "is -site-key") {
		t.Fatalf("previous is the key: %v", err)
	}
	if err := publishList(ctx, newFakeS3(), "bucket", k, nil, pub(old), v1); err == nil || !strings.Contains(err.Error(), "only for the flag day") {
		t.Fatalf("a first list: %v", err)
	}
	// Already under the new key.
	b := newFakeS3()
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	signs := len(f.signs)
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v2); err == nil || !strings.Contains(err.Error(), "only for the flag day") {
		t.Fatalf("a list already under the new key: %v", err)
	}
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v1); err == nil || !strings.Contains(err.Error(), "only for the flag day") {
		t.Fatalf("a rerun: %v", err)
	}
	// The flag day itself, then a rerun with the flag: refused.
	ob := newFakeS3()
	if err := publishList(ctx, ob, "bucket", secretSigner(old), nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	// The old list again, under the new key, with the old key given: not
	// the next version (and not "already published" under the old key).
	if err := publishList(ctx, ob, "bucket", k, nil, pub(old), v1); err == nil {
		t.Fatal("the old list again on the flag day")
	}
	if len(f.signs) != signs {
		t.Fatalf("signed for a refusal: %d", len(f.signs)-signs)
	}
	if err := publishList(ctx, ob, "bucket", k, nil, pub(old), v2); err != nil || len(f.signs) != signs+1 {
		t.Fatalf("the flag day: %v", err)
	}
	if err := publishList(ctx, ob, "bucket", k, nil, pub(old), v2); err == nil || !strings.Contains(err.Error(), "only for the flag day") || len(f.signs) != signs+1 {
		t.Fatalf("a rerun of the flag day with the flag: %v", err)
	}
	// The flag's own decoding, before AWS.
	if err := publish(ctx, publishArgs{kms: testKeyARN, siteKey: base64Key(pub(nw)), watch: topicA + "," + topicB, previous: "nope", listAnchor: testAnchorARN, listAnchorPub: "cGlu", sigstore: "staging", bucket: "b", in: "/nonexistent"}); err == nil ||
		!strings.HasPrefix(err.Error(), "-previous-site-key: an Ed25519 public key") {
		t.Fatalf("%v", err)
	}
}

// A signature in the bucket over this list is a resume only if the list
// it would replace is the one this list extends.
func TestResumeNeedsThePrevious(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	f := newFakeKMS(key)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(key))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	// A signature over a list that doesn't extend v1, planted as current.
	other := testList(2, bytes.Repeat([]byte{9}, 32), testService(3, "A"))
	sig, _ := signList(ctx, secretSigner(key), other)
	b.set("v1/services.json.sig", sig)
	if err := publishList(ctx, b, "bucket", k, nil, nil, other); err == nil || !strings.Contains(err.Error(), "restore the pair") || len(f.signs) != 1 {
		t.Fatalf("%v, %d signs", err, len(f.signs))
	}
	if !bytes.Equal(b.objs["v1/services.json"].data, v1) {
		t.Fatal("the current list moved")
	}
}

// An interrupted flag day (the new key's signature written, the list
// not): the rerun needs no old key, and is refused with it; resuming is
// judged under the new key only.
func TestFlagDayInterrupted(t *testing.T) {
	ctx := context.Background()
	old, nw := testKey("old"), testKey("new")
	f := newFakeKMS(nw)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", secretSigner(old), nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"))
	// The old key's own interrupted publish of v2: not a resume under the
	// new key, and the published pair doesn't verify under the old key.
	oldSig, _ := signList(ctx, secretSigner(old), v2)
	b.set("v1/services.json.sig", oldSig)
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v2); err == nil || !strings.Contains(err.Error(), "restore the pair") || len(f.signs) != 0 {
		t.Fatalf("an old-key interrupted publish: %v, %d signs", err, len(f.signs))
	}
	// The new key's signature of v2 written, the list not.
	newSig, _ := signList(ctx, secretSigner(nw), v2)
	b.set("v1/services.json.sig", newSig)
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v2); err == nil || !strings.Contains(err.Error(), "only for the flag day") {
		t.Fatalf("the rerun with the old key: %v", err)
	}
	if err := publishList(ctx, b, "bucket", k, nil, nil, v2); err != nil || len(f.signs) != 0 {
		t.Fatalf("the rerun: %v, %d signs", err, len(f.signs))
	}
	if !bytes.Equal(b.objs["v1/services.json"].data, v2) {
		t.Fatal("v2 not published")
	}
}

// After the flag day the old key is never taken again: a pair under it put
// back as current (a planted history) is refused with the flag, and its
// error no longer suggests the flag.
func TestFlagDayOver(t *testing.T) {
	ctx := context.Background()
	old, nw := testKey("old"), testKey("new")
	f := newFakeKMS(nw)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	b := newFakeS3()
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	if err := publishList(ctx, b, "bucket", secretSigner(old), nil, nil, v1); err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v2); err != nil {
		t.Fatal(err)
	}
	// The old key's own v3, put back as current by someone with the old
	// secret and bucket write.
	h2 := sha256.Sum256(v2)
	planted := testList(3, h2[:], testService(3, "A"), testService(5, "Evil"))
	ps, _ := signList(ctx, secretSigner(old), planted)
	b.set("v1/services.json", planted)
	b.set("v1/services.json.sig", ps)
	next := testList(4, sha256Of(planted), testService(3, "A"), testService(5, "Evil"))
	signs := len(f.signs)
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), next); err == nil || !strings.Contains(err.Error(), "flag day is over") {
		t.Fatalf("the flag after the flag day: %v", err)
	}
	err := publishList(ctx, b, "bucket", k, nil, nil, next)
	if err == nil || !strings.Contains(err.Error(), "restore the pair") || strings.Contains(err.Error(), "-previous-site-key") {
		t.Fatalf("without the flag: %v", err)
	}
	if len(f.signs) != signs {
		t.Fatal("signed for a refusal")
	}
}

func sha256Of(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// A broken pair with the flag is "restore the pair"; the flag equal to
// -site-key is refused before any AWS call; a small-order key given as
// the old key verifies nothing.
func TestFlagDayEdges(t *testing.T) {
	ctx := context.Background()
	old, nw := testKey("old"), testKey("new")
	f := newFakeKMS(nw)
	k, _ := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	v1 := testList(1, make([]byte, 32), testService(3, "A"))
	v2 := testList(2, sha256Of(v1), testService(3, "A"))
	b := newFakeS3()
	b.set("v1/services.json", v1) // no signature: a broken pair
	if err := publishList(ctx, b, "bucket", k, nil, pub(old), v2); err == nil || !strings.Contains(err.Error(), "restore the pair") {
		t.Fatalf("a broken pair with the flag: %v", err)
	}
	err := publish(ctx, publishArgs{kms: testKeyARN, siteKey: base64Key(pub(nw)), previous: base64Key(pub(nw)),
		watch: topicA + "," + topicB, listAnchor: testAnchorARN, listAnchorPub: "cGlu", sigstore: "staging", bucket: "b", in: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "is -site-key") {
		t.Fatalf("the flag equal to -site-key: %v", err)
	}
	// The identity point as the old key, with a pair forged for it (R the
	// identity, S = 0, which plain ed25519.Verify accepts under it).
	identity := append([]byte{1}, make([]byte, 31)...)
	forged := append(append([]byte{1}, make([]byte, 31)...), make([]byte, 32)...)
	ob := newFakeS3()
	ob.set("v1/services.json", v1)
	ob.set("v1/services.json.sig", forged)
	if err := publishList(ctx, ob, "bucket", k, nil, identity, v2); err == nil || !strings.Contains(err.Error(), "restore the pair") || len(f.signs) != 0 {
		t.Fatalf("a small-order old key: %v, %d signs", err, len(f.signs))
	}
}
