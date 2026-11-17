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
	o, exists := f.objs[k]
	if aws.ToString(in.IfNoneMatch) == "*" && exists || in.IfMatch != nil && (!exists || o.etag != aws.ToString(in.IfMatch)) {
		return nil, errors.New("PreconditionFailed")
	}
	b, _ := io.ReadAll(in.Body)
	f.n++
	f.objs[k] = fakeObject{data: b, etag: fmt.Sprintf(`"%d"`, f.n)}
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
	if err := publishList(ctx, b, "bucket", k, nil, testList(2, make([]byte, 32), a)); err == nil || !strings.Contains(err.Error(), "first list") {
		t.Fatalf("a first list at version 2: %v", err)
	}
	// A list the site would refuse: an unknown member, a service listed twice.
	if err := publishList(ctx, b, "bucket", k, nil, []byte(`{"extra":1,"previous":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","services":[],"v":1,"version":1}`)); err == nil {
		t.Fatal("an unknown member")
	}
	if err := publishList(ctx, b, "bucket", k, nil, testList(1, make([]byte, 32), a, a)); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a service twice: %v", err)
	}
	signs(0, "refused first lists")

	v1 := testList(1, make([]byte, 32), a)
	if err := publishList(ctx, b, "bucket", k, nil, v1); err != nil {
		t.Fatal(err)
	}
	signs(1, "the first list")
	// A rerun of the published list: nothing signed.
	if err := publishList(ctx, b, "bucket", k, nil, v1); err != nil {
		t.Fatal(err)
	}
	signs(1, "a rerun")
	h1 := sha256.Sum256(v1)
	if err := publishList(ctx, b, "bucket", k, nil, testList(3, h1[:], a)); err == nil || !strings.Contains(err.Error(), "next version is 2") {
		t.Fatalf("a gap: %v", err)
	}
	if err := publishList(ctx, b, "bucket", k, nil, testList(2, h1[:], a2)); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("a dropped service: %v", err)
	}
	signs(1, "refused next lists")

	// An interrupted publish (the signature written, not the list): the
	// rerun finishes it with the bucket's signature.
	v2 := testList(2, h1[:], a, a2)
	sig2, _ := signList(ctx, secretSigner(key), v2)
	b.set("v1/services.json.sig", sig2)
	if err := publishList(ctx, b, "bucket", k, nil, v2); err != nil {
		t.Fatal(err)
	}
	signs(1, "an interrupted publish finished")
	if !bytes.Equal(b.objs["v1/services.json"].data, v2) || !bytes.Equal(b.objs["v1/services/2.json.sig"].data, sig2) {
		t.Fatal("v2 not published")
	}

	// A published pair that doesn't verify: refused before signing.
	b.set("v1/services.json.sig", bytes.Repeat([]byte{1}, 64))
	h2 := sha256.Sum256(v2)
	if err := publishList(ctx, b, "bucket", k, nil, testList(3, h2[:], a, a2)); err == nil || !strings.Contains(err.Error(), "restore the pair") {
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
	if err := publishList(ctx, b, "bucket", secretSigner(old), nil, v1); err != nil {
		t.Fatal(err)
	}
	f := newFakeKMS(nw)
	k, err := newKMSSigner(ctx, f, testKeyARN, pub(nw))
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.Sum256(v1)
	v2 := testList(2, h1[:], testService(3, "A"))
	if err := publishList(ctx, b, "bucket", k, nil, v2); err == nil || !strings.Contains(err.Error(), "-previous-site-key") {
		t.Fatalf("without the previous key: %v", err)
	}
	if len(f.signs) != 0 {
		t.Fatal("signed a list it then refused")
	}
	if err := publishList(ctx, b, "bucket", k, pub(testKey("third")), v2); err == nil || len(f.signs) != 0 {
		t.Fatalf("another previous key: %v, %d signs", err, len(f.signs))
	}
	if err := publishList(ctx, b, "bucket", k, pub(old), v2); err != nil || len(f.signs) != 1 {
		t.Fatalf("the flag day: %v, %d signs", err, len(f.signs))
	}
	if _, err := site.ParseServiceList(b.objs["v1/services/2.json"].data, b.objs["v1/services/2.json.sig"].data, pub(nw)); err != nil {
		t.Fatalf("v2 isn't under the new key: %v", err)
	}
	if _, err := site.ParseServiceList(b.objs["v1/services/1.json"].data, b.objs["v1/services/1.json.sig"].data, pub(old)); err != nil {
		t.Fatalf("v1's copy isn't the old key's: %v", err)
	}
	h2 := sha256.Sum256(v2)
	if err := publishList(ctx, b, "bucket", k, nil, testList(3, h2[:], testService(3, "A"))); err != nil || len(f.signs) != 2 {
		t.Fatalf("after the flag day: %v, %d signs", err, len(f.signs))
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
	err := publish(ctx, publishArgs{kms: "alias/vettid-votes-staging-site", siteKey: "k", watch: "w", bucket: "b", in: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "not an alias") {
		t.Fatalf("%v", err)
	}
	if err := publish(ctx, publishArgs{secret: "s", previous: "k", bucket: "b", in: "x"}); err == nil || !strings.Contains(err.Error(), "go with -kms") {
		t.Fatalf("-previous-site-key with -secret: %v", err)
	}
}
