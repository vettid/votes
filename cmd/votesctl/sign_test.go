package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/votes/site"
)

// Fixed test values: no real account or key.
const testKeyARN = "arn:aws:kms:us-east-1:123456789012:key/0123abcd-4567-89ab-cdef-0123456789ab"

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(name))
	return ed25519.NewKeyFromSeed(seed[:])
}

// fakeKMS answers as KMS does for an Ed25519 key, with each answer
// changeable.
type fakeKMS struct {
	priv        ed25519.PrivateKey
	spki        []byte // overrides the public key
	keyID       string // overrides the KeyId answered
	spec        kmstypes.KeySpec
	usage       kmstypes.KeyUsageType
	algs        []kmstypes.SigningAlgorithmSpec
	signAlg     kmstypes.SigningAlgorithmSpec
	signErr     error
	badSig      bool
	signs       []*kms.SignInput
	publicReads int
}

func newFakeKMS(priv ed25519.PrivateKey) *fakeKMS {
	return &fakeKMS{priv: priv, spec: kmstypes.KeySpecEccNistEdwards25519, usage: kmstypes.KeyUsageTypeSignVerify,
		algs:    []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEd25519Sha512, kmstypes.SigningAlgorithmSpecEd25519PhSha512},
		signAlg: kmstypes.SigningAlgorithmSpecEd25519Sha512}
}

func (f *fakeKMS) id(in *string) *string {
	if f.keyID != "" {
		return aws.String(f.keyID)
	}
	return in
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.publicReads++
	spki := f.spki
	if spki == nil {
		spki, _ = x509.MarshalPKIXPublicKey(f.priv.Public())
	}
	return &kms.GetPublicKeyOutput{KeyId: f.id(in.KeyId), KeySpec: f.spec, KeyUsage: f.usage, SigningAlgorithms: f.algs, PublicKey: spki}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signs = append(f.signs, in)
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig := ed25519.Sign(f.priv, in.Message)
	if f.badSig {
		sig[0] ^= 1
	}
	return &kms.SignOutput{KeyId: f.id(in.KeyId), Signature: sig, SigningAlgorithm: f.signAlg}, nil
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// The list's signature is suite.Sign's, byte for byte, whichever signer
// makes it (Ed25519 is deterministic), and KMS is asked for pure Ed25519
// over label ‖ SHA-256(list), 59 bytes.
func TestSignListSameAsSuite(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	data := []byte(`{"previous":"AAAA","services":[],"v":1,"version":1}`)
	want, err := suite.Sign(key, vote.LabelServiceList, sum(data))
	if err != nil {
		t.Fatal(err)
	}
	got, err := signList(ctx, secretSigner(key), data)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("secret signer: %x %v", got, err)
	}
	f := newFakeKMS(key)
	k, err := newKMSSigner(ctx, f, testKeyARN, pub(key))
	if err != nil {
		t.Fatal(err)
	}
	got, err = signList(ctx, k, data)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("KMS signer: %x %v", got, err)
	}
	if len(f.signs) != 1 {
		t.Fatalf("%d signs", len(f.signs))
	}
	in := f.signs[0]
	if aws.ToString(in.KeyId) != testKeyARN || in.MessageType != kmstypes.MessageTypeRaw ||
		in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEd25519Sha512 || in.GrantTokens != nil {
		t.Fatalf("sign input %+v", in)
	}
	if want := append([]byte(vote.LabelServiceList), sum(data)...); !bytes.Equal(in.Message, want) || len(in.Message) != 59 {
		t.Fatalf("message %q (%d bytes)", in.Message, len(in.Message))
	}
}

// The key is refused before anything is signed unless it is the ARN of an
// Ed25519 signing key that signs with ED25519_SHA_512 and whose public key
// is the expected site key.
func TestKMSSignerRefusesKey(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSPKI, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(testKey("other").Public())
	for _, c := range []struct {
		name   string
		arn    string
		expect ed25519.PublicKey
		change func(*fakeKMS)
		want   string
	}{
		{"an alias name", "alias/vettid-votes-staging-site", pub(key), nil, "not an alias"},
		{"an alias ARN", "arn:aws:kms:us-east-1:123456789012:alias/vettid-votes-staging-site", pub(key), nil, "not an alias"},
		{"a bare key id", "0123abcd-4567-89ab-cdef-0123456789ab", pub(key), nil, "not an alias"},
		{"no expected key", testKeyARN, nil, nil, "-site-key"},
		{"another public key", testKeyARN, pub(key), func(f *fakeKMS) { f.spki = otherSPKI }, "not -site-key"},
		{"another expected key", testKeyARN, pub(testKey("other")), nil, "not -site-key"},
		{"a P-256 key", testKeyARN, pub(key), func(f *fakeKMS) { f.spki = ecSPKI }, "not Ed25519"},
		{"garbage", testKeyARN, pub(key), func(f *fakeKMS) { f.spki = []byte{1, 2, 3} }, "public key"},
		{"another key spec", testKeyARN, pub(key), func(f *fakeKMS) { f.spec = kmstypes.KeySpecEccNistP256 }, "ECC_NIST_EDWARDS25519"},
		{"another key usage", testKeyARN, pub(key), func(f *fakeKMS) { f.usage = kmstypes.KeyUsageTypeEncryptDecrypt }, "SIGN_VERIFY"},
		{"prehash only", testKeyARN, pub(key), func(f *fakeKMS) {
			f.algs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEd25519PhSha512}
		}, "ED25519_SHA_512"},
		{"an answer for another key", testKeyARN, pub(key), func(f *fakeKMS) {
			f.keyID = "arn:aws:kms:us-east-1:123456789012:key/ffffffff-4567-89ab-cdef-0123456789ab"
		}, "answered for key"},
	} {
		f := newFakeKMS(key)
		if c.change != nil {
			c.change(f)
		}
		_, err := newKMSSigner(ctx, f, c.arn, c.expect)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if len(f.signs) != 0 {
			t.Errorf("%s: signed", c.name)
		}
	}
	// A multi-Region key's ARN is a key ARN too.
	if _, err := newKMSSigner(ctx, newFakeKMS(key), "arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef", pub(key)); err != nil {
		t.Fatal(err)
	}
}

// A signature is returned only if it verifies under the site key, from
// that key, with that algorithm (fail closed).
func TestKMSSignerRefusesSignature(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	data := []byte(`{}`)
	for _, c := range []struct {
		name   string
		change func(*fakeKMS)
		want   string
	}{
		{"a signature that doesn't verify", func(f *fakeKMS) { f.badSig = true }, "doesn't verify"},
		{"another key's signature", func(f *fakeKMS) { f.priv = testKey("other") }, "doesn't verify"},
		{"another key id", func(f *fakeKMS) {
			f.keyID = "arn:aws:kms:us-east-1:123456789012:key/ffffffff-4567-89ab-cdef-0123456789ab"
		}, "signed with key"},
		{"another algorithm", func(f *fakeKMS) { f.signAlg = kmstypes.SigningAlgorithmSpecEd25519PhSha512 }, "not ED25519_SHA_512"},
		{"an error", func(f *fakeKMS) { f.signErr = errors.New("AccessDeniedException") }, "AccessDeniedException"},
	} {
		f := newFakeKMS(key)
		k, err := newKMSSigner(ctx, f, testKeyARN, pub(key))
		if err != nil {
			t.Fatal(err)
		}
		c.change(f)
		sig, err := signList(ctx, k, data)
		if err == nil || sig != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %x %v, want %q", c.name, sig, err, c.want)
		}
	}
}

// The KMS signer checks each signature itself too, not only signList.
func TestKMSSignerChecksItself(t *testing.T) {
	key := testKey("site")
	f := newFakeKMS(key)
	k, err := newKMSSigner(context.Background(), f, testKeyARN, pub(key))
	if err != nil {
		t.Fatal(err)
	}
	f.badSig = true
	if sig, err := k.Sign(context.Background(), []byte("message")); err == nil || sig != nil {
		t.Fatalf("%x %v", sig, err)
	}
}

// signList itself checks the signature, whatever the signer.
type lyingSigner struct{ secretSigner }

func (l lyingSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	return l.secretSigner.Sign(ctx, append(msg, 0))
}

func TestSignListChecks(t *testing.T) {
	if sig, err := signList(context.Background(), lyingSigner{secretSigner(testKey("site"))}, []byte(`{}`)); err == nil || sig != nil {
		t.Fatalf("%x %v", sig, err)
	}
}

// fakeSNS lists each topic's subscriptions, a page at a time.
type fakeSNS struct {
	pages map[string][][]snstypes.Subscription
	err   error
}

func (f *fakeSNS) ListSubscriptionsByTopic(_ context.Context, in *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	pages := f.pages[aws.ToString(in.TopicArn)]
	i := 0
	if in.NextToken != nil {
		i = int(aws.ToString(in.NextToken)[0] - '0')
	}
	out := &sns.ListSubscriptionsByTopicOutput{}
	if i < len(pages) {
		out.Subscriptions = pages[i]
	}
	if i+1 < len(pages) {
		out.NextToken = aws.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

const (
	topicA = "arn:aws:sns:us-east-1:123456789012:vettid-votes-staging-key-watch"
	topicB = "arn:aws:sns:us-east-1:123456789012:vettid-votes-staging-key-watch-b"
)

func sub(topic, arn, protocol string) snstypes.Subscription {
	if arn == "confirmed" {
		arn = topic + ":0123abcd-4567-89ab-cdef-0123456789ab"
	}
	return snstypes.Subscription{TopicArn: aws.String(topic), SubscriptionArn: aws.String(arn), Protocol: aws.String(protocol)}
}

// A KMS publish is refused before anything is signed unless both watch
// topics have an email subscription and every email subscription is
// confirmed.
func TestCheckWatch(t *testing.T) {
	ctx := context.Background()
	ok := func() map[string][][]snstypes.Subscription {
		return map[string][][]snstypes.Subscription{
			topicA: {{sub(topicA, "confirmed", "email")}},
			topicB: {{sub(topicB, "confirmed", "email"), sub(topicB, "PendingConfirmation", "sqs")}}, // not email: not counted
		}
	}
	if err := checkWatch(ctx, &fakeSNS{pages: ok()}, []string{topicA, topicB}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		topics []string
		change func(map[string][][]snstypes.Subscription)
		err    error
		want   string
	}{
		{"one topic", []string{topicA}, nil, nil, "-watch-topics"},
		{"none", nil, nil, nil, "-watch-topics"},
		{"the same topic twice", []string{topicA, topicA}, nil, nil, "-watch-topics"},
		{"the other order", []string{topicB, topicA}, nil, nil, "-watch-topics"},
		{"three", []string{topicA, topicB, topicB}, nil, nil, "-watch-topics"},
		{"another stack's b", []string{topicA, "arn:aws:sns:us-east-1:123456789012:vettid-votes-prod-key-watch-b"}, nil, nil, "-watch-topics"},
		{"not watch topics", []string{"arn:aws:sns:us-east-1:123456789012:alerts", "arn:aws:sns:us-east-1:123456789012:alerts-b"}, nil, nil, "-watch-topics"},
		{"not an ARN", []string{"vettid-votes-staging-key-watch", "vettid-votes-staging-key-watch-b"}, nil, nil, "-watch-topics"},
		{"a second email", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicA] = [][]snstypes.Subscription{{sub(topicA, "confirmed", "email"), sub(topicA, "confirmed", "email")}}
		}, nil, "more than one email"},
		{"pending", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicB] = [][]snstypes.Subscription{{sub(topicB, "PendingConfirmation", "email")}}
		}, nil, "not confirmed"},
		{"deleted", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicA] = [][]snstypes.Subscription{{sub(topicA, "Deleted", "email")}}
		}, nil, "not confirmed"},
		{"another topic's subscription", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicA] = [][]snstypes.Subscription{{sub(topicA, topicB+":0123abcd-4567-89ab-cdef-0123456789ab", "email")}}
		}, nil, "not confirmed"},
		{"pending on a later page", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicA] = [][]snstypes.Subscription{{sub(topicA, "confirmed", "sqs")}, {sub(topicA, "PendingConfirmation", "email")}}
		}, nil, "not confirmed"},
		{"no email", []string{topicA, topicB}, func(m map[string][][]snstypes.Subscription) {
			m[topicB] = nil
		}, nil, "no email subscription"},
		{"an error", []string{topicA, topicB}, nil, errors.New("AuthorizationError"), "AuthorizationError"},
	} {
		m := ok()
		if c.change != nil {
			c.change(m)
		}
		err := checkWatch(ctx, &fakeSNS{pages: m, err: c.err}, c.topics)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// The flags: exactly one way to the key; -site-key and -watch-topics only
// with -kms; refused before AWS is called.
func TestPublishFlags(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		a    publishArgs
		want string
	}{
		{publishArgs{bucket: "b", in: "x"}, "exactly one"},
		{publishArgs{kms: testKeyARN, secret: "s", bucket: "b", in: "x"}, "exactly one"},
		{publishArgs{secret: "s", siteKey: "k", bucket: "b", in: "x"}, "go with -kms"},
		{publishArgs{secret: "s", watch: topicA, bucket: "b", in: "x"}, "go with -kms"},
		{publishArgs{kms: testKeyARN, in: "x"}, "-bucket"},
		{publishArgs{kms: testKeyARN, watch: topicA + "," + topicB, bucket: "b", in: "x"}, "needs -site-key"},
		{publishArgs{kms: testKeyARN, siteKey: "k", bucket: "b", in: "x"}, "needs -site-key"},
	} {
		if err := publish(ctx, c.a); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.a, err, c.want)
		}
	}
	if _, err := sitePublicKey(ctx, testKeyARN, "s"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatal(err)
	}
	if _, err := sitePublicKey(ctx, "", ""); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatal(err)
	}
}

// A KMS publish checks the watch, then the key, before anything is signed:
// a watch that fails means no call to KMS at all.
func TestKMSPublishOrder(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	a := publishArgs{kms: testKeyARN, siteKey: base64Key(pub(key)), watch: topicA + "," + topicB}
	f := newFakeKMS(key)
	if _, err := kmsPublishSigner(ctx, a, f, &fakeSNS{err: errors.New("AuthorizationError")}); err == nil {
		t.Fatal("a watch that can't be read")
	}
	if f.publicReads != 0 || len(f.signs) != 0 {
		t.Fatalf("KMS called: %d reads, %d signs", f.publicReads, len(f.signs))
	}
	pending := &fakeSNS{pages: map[string][][]snstypes.Subscription{
		topicA: {{sub(topicA, "confirmed", "email")}}, topicB: {{sub(topicB, "PendingConfirmation", "email")}}}}
	if _, err := kmsPublishSigner(ctx, a, f, pending); err == nil || f.publicReads != 0 || len(f.signs) != 0 {
		t.Fatalf("a pending watch: %v, %d reads, %d signs", err, f.publicReads, len(f.signs))
	}
	ok := &fakeSNS{pages: map[string][][]snstypes.Subscription{
		topicA: {{sub(topicA, "confirmed", "email")}}, topicB: {{sub(topicB, "confirmed", "email")}}}}
	s, err := kmsPublishSigner(ctx, a, f, ok)
	if err != nil || !bytes.Equal(s.Public(), pub(key)) || len(f.signs) != 0 {
		t.Fatalf("%v, %d signs", err, len(f.signs))
	}
	// A malformed -site-key is refused before any call.
	f = newFakeKMS(key)
	if _, err := kmsPublishSigner(ctx, publishArgs{kms: testKeyARN, siteKey: "!", watch: a.watch}, f, ok); err == nil || f.publicReads != 0 {
		t.Fatalf("%v", err)
	}
}

func base64Key(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// preCheck refuses, before signing, a new list that the published one
// refuses; it leaves every other case to the checks after signing.
func TestPreCheck(t *testing.T) {
	ctx := context.Background()
	key := testKey("site")
	ik := bytes.Repeat([]byte{3}, 32)
	svc := site.Service{ServiceID: site.ServiceID(ik), Name: "A", IKs: [][]byte{ik}, AnchorKeys: []site.AnchorKey{}}
	list := func(version int64, previous []byte, services ...site.Service) []byte {
		if services == nil {
			services = []site.Service{}
		}
		b, _ := json.Marshal(&site.ServiceList{V: 1, Version: version, Previous: previous, Services: services})
		b, _ = vote.Canonicalize(b)
		return b
	}
	v1 := list(1, make([]byte, 32), svc)
	sig1, err := signList(ctx, secretSigner(key), v1)
	if err != nil {
		t.Fatal(err)
	}
	cur, curSig := object{data: v1, tag: "t"}, object{data: sig1, tag: "s"}
	h := sha256.Sum256(v1)
	for _, c := range []struct {
		name string
		data []byte
		want string
	}{
		{"skips a version", list(3, h[:], svc), "next version is 2"},
		{"drops a service", list(2, h[:]), "dropped"},
		{"another previous", list(2, make([]byte, 32), svc), ""},
	} {
		err := preCheck(cur, curSig, c.data, pub(key))
		if c.want == "" && err == nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	for _, c := range []struct {
		name        string
		cur, curSig object
		data        []byte
	}{
		{"the next version", cur, curSig, list(2, h[:], svc)},
		{"the first list", object{}, object{}, v1},
		{"the published list again", cur, curSig, v1},
		{"a pair that doesn't verify (an interrupted publish)", cur, object{data: bytes.Repeat([]byte{1}, 64)}, list(5, h[:])},
		{"only a signature", object{}, curSig, list(5, h[:])},
	} {
		if err := preCheck(c.cur, c.curSig, c.data, pub(key)); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
