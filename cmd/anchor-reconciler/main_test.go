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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/vettid/votes/reconcile"
	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

const (
	keyARN = "arn:aws:kms:us-east-1:444455556666:key/abc"
	role   = "arn:aws:iam::444455556666:role/vettid-anchor-signer-staging"
)

type fakeKMS struct{ spki []byte }

func (f fakeKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Arn: aws.String(keyARN)}}, nil
}

func (f fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{PublicKey: f.spki}, nil
}

// fakeLogs answers by log group.
type fakeLogs map[string][]string

func (f fakeLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	msgs, ok := f[aws.ToString(in.LogGroupName)]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	for _, m := range msgs {
		out.Events = append(out.Events, cwltypes.FilteredLogEvent{Message: aws.String(m)})
	}
	return out, nil
}

type fakeLambda struct{ code, policy string }

func (f fakeLambda) GetFunctionConfiguration(context.Context, *lambda.GetFunctionConfigurationInput, ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	return &lambda.GetFunctionConfigurationOutput{CodeSha256: aws.String(f.code)}, nil
}

func (f fakeLambda) ListVersionsByFunction(context.Context, *lambda.ListVersionsByFunctionInput, ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	return &lambda.ListVersionsByFunctionOutput{Versions: []lambdatypes.FunctionConfiguration{{Version: aws.String("$LATEST")}}}, nil
}

func (f fakeLambda) ListAliases(context.Context, *lambda.ListAliasesInput, ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	return &lambda.ListAliasesOutput{}, nil
}

type fakeTrail struct{}

func (fakeTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	t := time.Date(2026, 11, 11, 11, 55, 0, 0, time.UTC)
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &t}, nil
}

func (fakeTrail) GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	return &cloudtrail.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{
		{FieldSelectors: []cttypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}}}, nil
}

type fakeClaims map[string]*signer.Claim

func (f fakeClaims) Get(_ context.Context, slot string) (*signer.Claim, error) { return f[slot], nil }

func (f fakeLambda) GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return &lambda.GetPolicyOutput{Policy: aws.String(f.policy)}, nil
}

type fakeList map[string][]string

func (f fakeList) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	out := &s3.ListObjectsV2Output{IsTruncated: aws.Bool(false)}
	for _, k := range f[aws.ToString(in.Prefix)] {
		out.Contents = append(out.Contents, s3types.Object{Key: aws.String(k)})
	}
	return out, nil
}

type okVerifier struct{}

func (okVerifier) VerifyTimes(_, _, _ []byte) (site.AnchorTimes, error) {
	return site.AnchorTimes{}, nil
}

const code = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

// world is a signer account with one sign, accounted for everywhere.
func world(t *testing.T) (*sources, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("vettid/test/reconciler/anchor-key"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	digest := sha256.Sum256([]byte("doc"))
	sig, _ := ecdsa.SignASN1(rand.Reader, k, digest[:])
	var rs struct{ R, S *big.Int }
	_, _ = asn1.Unmarshal(sig, &rs)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	at := now.Add(-90 * time.Minute).Format(time.RFC3339)
	b64 := base64.StdEncoding.EncodeToString
	signLine := `{"kind":"sign","kms_request_id":"req-1","at":"` + at + `","proposal_id":"p1","name":"proposal","digest":"` + b64(digest[:]) +
		`","signature":"` + b64(sig) + `","r":"` + b64(rs.R.Bytes()) + `"}`
	trailLine := `{"eventTime":"` + at + `","requestID":"req-1","userIdentity":{"arn":"x","sessionContext":{"sessionIssuer":{"arn":"` + role +
		`"}}},"requestParameters":{"signingAlgorithm":"ECDSA_SHA_256","messageType":"DIGEST"},"resources":[{"ARN":"` + keyARN + `"}]}`
	store := &site.MemStorage{}
	ctx := context.Background()
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json", []byte("doc"), "")
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json.sigstore.json", []byte(`{"messageSignature":{"signature":"`+b64(sig)+`"}}`), "")
	sum := sha256.Sum256(spki)
	c := &cfg{keyAlias: "arn:aws:kms:us-east-1:444455556666:alias/vettid-anchor-staging", keyARN: keyARN, keySPKISHA256: hex.EncodeToString(sum[:]),
		trailName: "t", journalGroup: "/j", journalStream: "signs",
		trailGroup: "/trail", bucket: "b", function: "fn", role: role, codeSha256: code, policy: `{"Statement": []}`}
	return &sources{
		logs: fakeLogs{"/j": {signLine}, "/trail": {trailLine}}, kms: fakeKMS{spki: spki},
		lambda: fakeLambda{code: code, policy: `{"Statement":[]}`}, store: store,
		list:   fakeList{"v1/p/": {"v1/p/p1/proposal.json", "v1/p/p1/proposal.json.sigstore.json"}},
		trail:  fakeTrail{},
		claims: fakeClaims{"p1/proposal": {Digest: digest[:], Sig: sig, R: rs.R.Bytes(), RequestID: "req-1"}},
		verify: okVerifier{}, c: c, now: func() time.Time { return now }, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}, sig
}

func TestPassClean(t *testing.T) {
	s, _ := world(t)
	if fs := s.pass(context.Background()); len(fs) != 0 {
		t.Fatalf("findings: %+v", fs)
	}
}

func TestPassReportsWhatItCantRead(t *testing.T) {
	s, _ := world(t)
	delete(s.logs.(fakeLogs), "/trail")
	fs := s.pass(context.Background())
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Rule] = true
	}
	// The trail not read: incomplete, and the sign it would have shown is
	// reported missing too, never taken as fine.
	if !got[reconcile.RuleIncomplete] || !got[reconcile.RuleTrailMissing] {
		t.Fatalf("an unread trail: %+v", fs)
	}
	s, _ = world(t)
	s.lambda = fakeLambda{code: "other", policy: `{"Statement":[]}`}
	if fs := s.pass(context.Background()); len(fs) != 1 || fs[0].Rule != reconcile.RuleCodeDrift {
		t.Fatalf("code drift: %+v", fs)
	}
	// The key: the alias resolving elsewhere, or another public key.
	s, _ = world(t)
	s.c.keyARN = "arn:aws:kms:us-east-1:444455556666:key/other"
	if fs := s.pass(context.Background()); !hasRule(fs, reconcile.RuleKeyDrift) {
		t.Fatalf("the alias elsewhere: %+v", fs)
	}
	s, _ = world(t)
	s.c.keySPKISHA256 = strings.Repeat("0", 64)
	if fs := s.pass(context.Background()); !hasRule(fs, reconcile.RuleKeyDrift) || !hasRule(fs, reconcile.RuleIncomplete) {
		t.Fatalf("another public key: %+v", fs)
	}
	// An old document on the site, outside the period: its claim accounts for it.
	s, _ = world(t)
	ctx := context.Background()
	st := s.store.(*site.MemStorage)
	_ = st.PutOnce(ctx, "v1/p/p0/proposal.json", []byte("old"), "")
	_ = st.PutOnce(ctx, "v1/p/p0/proposal.json.sigstore.json", []byte(`{"messageSignature":{"signature":"AQI="}}`), "")
	s.list = fakeList{"v1/p/": {"v1/p/p0/proposal.json.sigstore.json", "v1/p/p1/proposal.json.sigstore.json"}}
	s.claims.(fakeClaims)["p0/proposal"] = &signer.Claim{Digest: []byte{9}, Sig: []byte{1, 2}, R: []byte{1}, RequestID: "req-old"}
	if fs := s.pass(ctx); len(fs) != 0 {
		t.Fatalf("an old document: %+v", fs)
	}
}

func hasRule(fs []reconcile.Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestReport(t *testing.T) {
	var b bytes.Buffer
	report(slog.New(slog.NewJSONHandler(&b, nil)), []reconcile.Finding{
		{Rule: reconcile.RuleUnattributed, Severity: reconcile.Alarm, RequestID: "r", Detail: "d"},
		{Rule: reconcile.RuleSecondSign, Severity: reconcile.Notice, Slot: "p/n", Detail: "d"},
	})
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	var first, second, last map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	_ = json.Unmarshal([]byte(lines[2]), &last)
	// The metric filters read $.alarm and $.notice.
	if first["alarm"] != reconcile.RuleUnattributed || first["notice"] != nil || second["notice"] != reconcile.RuleSecondSign || second["alarm"] != nil {
		t.Fatalf("findings logged as %v / %v", first, second)
	}
	if last["msg"] != "reconciled" || last["alarms"] != float64(1) || last["notices"] != float64(1) {
		t.Fatalf("the end %v", last)
	}
}

func TestCompiled(t *testing.T) {
	set := func() {
		compiledRegion, compiledKeyAlias = "us-east-1", "arn:aws:kms:us-east-1:444455556666:alias/vettid-anchor-staging"
		compiledKeyARN, compiledKeySPKISHA256 = keyARN, strings.Repeat("ab", 32)
		compiledClaimsTable, compiledTrailName = "claims", "trail"
		compiledJournalGroup, compiledJournalStream, compiledTrailGroup = "/j", "signs", "/t"
		compiledVotesBucket, compiledSigstore, compiledSignerFunction = "b", "staging", "fn"
		compiledSignerRole, compiledCodeSha256 = role, code
		compiledPolicy = base64.StdEncoding.EncodeToString([]byte(`{"Statement":[]}`))
		compiledAcknowledged = base64.StdEncoding.EncodeToString([]byte(`[]`))
	}
	set()
	if _, err := compiled(); err != nil {
		t.Fatal(err)
	}
	for _, mod := range []func(){
		func() { compiledTrailGroup = "" },
		func() { compiledKeyARN = "arn:aws:kms:us-east-1:444455556666:alias/x" },
		func() { compiledKeySPKISHA256 = "AB" },
		func() { compiledKeyAlias = "arn:aws:kms:us-east-1:444455556666:key/abc" },
		func() { compiledSigstore = "other" },
		func() { compiledSignerRole = "signer" },
		func() { compiledCodeSha256 = "abc" },
		func() { compiledPolicy = base64.StdEncoding.EncodeToString([]byte("not json")) },
		func() { compiledAcknowledged = base64.StdEncoding.EncodeToString([]byte(`{}`)) },
	} {
		set()
		mod()
		if _, err := compiled(); err == nil {
			t.Fatal("a bad configuration started")
		}
	}
}

func TestParseAcknowledged(t *testing.T) {
	d := strings.Repeat("ab", 32)
	if a, err := ParseAcknowledged([]byte(`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","r":"0a1b","reason":"why"}]`)); err != nil || len(a) != 1 || a[0].R != "0a1b" {
		t.Fatalf("%v %v", a, err)
	}
	for _, bad := range []string{
		`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","reason":""}]`,
		`[{"rule":"unpublished_sign","slot":"pn","digest":"` + d + `","reason":"why"}]`,
		`[{"rule":"unpublished_sign","slot":"p/n","digest":"AB","reason":"why"}]`,
		`[{"rule":"x","slot":"p/n","digest":"` + d + `","reason":"why","extra":1}]`,
		`[{"rule":"x","slot":"p/n","digest":"` + d + `","r":"xyz","reason":"why"}]`,
		`[] []`, `null`,
	} {
		if _, err := ParseAcknowledged([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
