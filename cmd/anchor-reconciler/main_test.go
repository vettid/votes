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

// fakeLogs answers by log group; a line "stream::msg" is in that stream.
// asked records each read's group and start.
type fakeLogs map[string][]string

var asked = map[string][]time.Time{}

func (f fakeLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	g := aws.ToString(in.LogGroupName)
	asked[g] = append(asked[g], time.UnixMilli(aws.ToInt64(in.StartTime)).UTC())
	msgs, ok := f[g]
	if !ok {
		return nil, errors.New("ResourceNotFoundException")
	}
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	// Ingested as CloudWatch Logs would: just after the sign.
	ingested := time.Date(2026, 11, 11, 10, 30, 2, 0, time.UTC).UnixMilli()
	for _, m := range msgs {
		stream := "signs"
		if st, msg, ok := strings.Cut(m, "::"); ok {
			stream, m = st, msg
		}
		out.Events = append(out.Events, cwltypes.FilteredLogEvent{Message: aws.String(m), IngestionTime: aws.Int64(ingested), LogStreamName: aws.String(stream)})
	}
	return out, nil
}

type fakeLambda struct{ code, policy string }

func (f fakeLambda) GetFunctionConfiguration(context.Context, *lambda.GetFunctionConfigurationInput, ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	return &lambda.GetFunctionConfigurationOutput{CodeSha256: aws.String(f.code), Runtime: lambdatypes.RuntimeProvidedal2023,
		Handler: aws.String("bootstrap"), Role: aws.String(role), Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureArm64}}, nil
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

// GetEventSelectors answers with the stack's three selectors (function
// "fn", table "tbl").
func (fakeTrail) GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	eq := func(f, v string) cttypes.AdvancedFieldSelector {
		return cttypes.AdvancedFieldSelector{Field: aws.String(f), Equals: []string{v}}
	}
	return &cloudtrail.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{
		{FieldSelectors: []cttypes.AdvancedFieldSelector{eq("eventCategory", "Management")}},
		{FieldSelectors: []cttypes.AdvancedFieldSelector{eq("eventCategory", "Data"),
			{Field: aws.String("resources.ARN"), StartsWith: []string{"arn:aws:lambda:us-east-1:444455556666:function:fn"}},
			eq("resources.type", "AWS::Lambda::Function")}},
		{FieldSelectors: []cttypes.AdvancedFieldSelector{eq("eventCategory", "Data"),
			eq("resources.ARN", "arn:aws:dynamodb:us-east-1:444455556666:table/tbl"), eq("readOnly", "false"),
			eq("resources.type", "AWS::DynamoDB::Table")}},
	}}, nil
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
	trailLine := "444455556666_CloudTrail_us-east-1::" + `{"eventTime":"` + at + `","eventType":"AwsApiCall","awsRegion":"us-east-1","recipientAccountId":"444455556666","requestID":"req-1","userIdentity":{"arn":"x","sessionContext":{"sessionIssuer":{"arn":"` + role +
		`"}}},"requestParameters":{"signingAlgorithm":"ECDSA_SHA_256","messageType":"DIGEST"},"resources":[{"ARN":"` + keyARN + `"}]}`
	store := &site.MemStorage{}
	ctx := context.Background()
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json", []byte("doc"), "")
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json.sigstore.json", []byte(`{"messageSignature":{"signature":"`+b64(sig)+`"}}`), "")
	sum := sha256.Sum256(spki)
	c := &cfg{keyAlias: "arn:aws:kms:us-east-1:444455556666:alias/vettid-anchor-staging", keyARN: keyARN, keySPKISHA256: hex.EncodeToString(sum[:]),
		trailName: "t", journalGroup: "/j", journalStream: "signs", region: "us-east-1", partition: "aws", account: "444455556666",
		claimsTable: "tbl", ownLogGroup: "/aws/lambda/rec",
		trailGroup: "/trail", bucket: "b", function: "fn", role: role, codeSha256: code, policy: `{"Statement": []}`}
	lastRun := `{"time":"2026-11-11T11:00:05Z","level":"INFO","msg":"reconciled","alarms":0,"notices":0,"complete":true}`
	return &sources{
		logs: fakeLogs{"/j": {signLine}, "/trail": {trailLine}, "/aws/lambda/rec": {lastRun}}, kms: fakeKMS{spki: spki},
		lambda: fakeLambda{code: code, policy: `{"Statement":[]}`}, store: store,
		list:   fakeList{"v1/p/": {"v1/p/p1/proposal.json", "v1/p/p1/proposal.json.sigstore.json"}},
		trail:  fakeTrail{},
		claims: fakeClaims{"p1/proposal": {Digest: digest[:], Sig: sig, R: rs.R.Bytes(), RequestID: "req-1", Journaled: true}},
		verify: okVerifier{}, c: c, now: func() time.Time { return now }, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		siteCheck: func(context.Context, string, time.Time) (string, error) { return "", nil },
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
	if last["msg"] != "reconciled" || last["alarms"] != float64(1) || last["notices"] != float64(1) || last["complete"] != true {
		t.Fatalf("the end %v", last)
	}
	// A run that couldn't read something isn't complete: the next starts
	// before it.
	b.Reset()
	report(slog.New(slog.NewJSONHandler(&b, nil)), []reconcile.Finding{{Rule: reconcile.RuleIncomplete, Severity: reconcile.Alarm, Detail: "d"}})
	lines = strings.Split(strings.TrimSpace(b.String()), "\n")
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if last["complete"] != false {
		t.Fatalf("an incomplete run's end %v", last)
	}
}

// After a stop, a run reads back to the last complete run; with none in
// MaxCatchUp it reads all of it and says it is incomplete.
func TestCatchUp(t *testing.T) {
	ctx := context.Background()
	s, _ := world(t)
	now := s.now()
	asked = map[string][]time.Time{}
	if fs := s.pass(ctx); len(fs) != 0 {
		t.Fatalf("findings: %+v", fs)
	}
	// The last complete run at 11:00 (its line's time; it reached the log
	// at 10:30:02 in this fake, and counts from then): a Period before it.
	lastFrom := time.Date(2026, 11, 11, 7, 30, 2, 0, time.UTC)
	if got := asked["/trail"]; len(got) != 1 || !got[0].Equal(lastFrom) {
		t.Fatalf("trail read from %v", got)
	}
	// The journal from a margin before, and its whole retention.
	if got := asked["/j"]; len(got) != 2 || !got[0].Equal(lastFrom.Add(-NoteMargin)) || !got[1].Equal(now.Add(-HistoryRetention)) {
		t.Fatalf("journal read from %v", got)
	}
	// The last complete run 10 hours ago: from 13 hours back.
	s.logs.(fakeLogs)["/aws/lambda/rec"] = []string{`{"time":"2026-11-11T02:00:00Z","msg":"reconciled","complete":true}`}
	asked = map[string][]time.Time{}
	_ = s.pass(ctx)
	if got := asked["/trail"]; len(got) != 1 || !got[0].Equal(time.Date(2026, 11, 10, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("after a stop, the trail read from %v", got)
	}
	// None: all of MaxCatchUp, and incomplete.
	s.logs.(fakeLogs)["/aws/lambda/rec"] = nil
	asked = map[string][]time.Time{}
	fs := s.pass(ctx)
	if got := asked["/trail"]; len(got) != 1 || !got[0].Equal(now.Add(-MaxCatchUp)) || !hasRule(fs, reconcile.RuleIncomplete) {
		t.Fatalf("no complete run: from %v, %+v", got, fs)
	}
	// Its own log group unreadable: all of MaxCatchUp, and incomplete.
	delete(s.logs.(fakeLogs), "/aws/lambda/rec")
	asked = map[string][]time.Time{}
	fs = s.pass(ctx)
	if got := asked["/trail"]; len(got) != 1 || !got[0].Equal(now.Add(-MaxCatchUp)) || !hasRule(fs, reconcile.RuleIncomplete) {
		t.Fatalf("its own log unread: from %v, %+v", got, fs)
	}
}

// The site check: a refusal alarms; a failed read is incomplete.
func TestPassSiteCheck(t *testing.T) {
	ctx := context.Background()
	s, _ := world(t)
	var checked []string
	s.siteCheck = func(_ context.Context, id string, _ time.Time) (string, error) {
		checked = append(checked, id)
		return "the IK signature doesn't verify", nil
	}
	fs := s.pass(ctx)
	if strings.Join(checked, ",") != "p1" || !hasRule(fs, reconcile.RuleSignatureMismatch) {
		t.Fatalf("checked %v: %+v", checked, fs)
	}
	s.siteCheck = func(context.Context, string, time.Time) (string, error) { return "", errors.New("AccessDenied") }
	if fs := s.pass(ctx); !hasRule(fs, reconcile.RuleIncomplete) {
		t.Fatalf("a failed check read: %+v", fs)
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
		compiledSiteKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		compiledOwnLogGroup = "/aws/lambda/vettid-anchor-reconciler-staging"
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
		func() { compiledSiteKey = "" },
		func() { compiledSiteKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		func() { compiledOwnLogGroup = "/vettid/anchor/staging/journal" },
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
	if a, err := ParseAcknowledged([]byte(`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","r":"0a1b","kms_request_id":"8b2d-11","reason":"why"}]`)); err != nil || len(a) != 1 || a[0].R != "0a1b" || a[0].RequestID != "8b2d-11" {
		t.Fatalf("%v %v", a, err)
	}
	if a, err := ParseAcknowledged([]byte(`[{"rule":"signature_mismatch","slot":"p/n","digest":"` + d + `","sig_sha256":"` + d + `","reason":"why"}]`)); err != nil || len(a) != 1 {
		t.Fatalf("by the signature's hash: %v %v", a, err)
	}
	for _, bad := range []string{
		// Neither a request id nor a signature hash: it would excuse every
		// finding of its slot and digest.
		`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","r":"0a1b","reason":"why"}]`,
		`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","kms_request_id":"a b","reason":"why"}]`,
		`[{"rule":"unpublished_sign","slot":"p/n","digest":"` + d + `","sig_sha256":"AB","reason":"why"}]`,
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
