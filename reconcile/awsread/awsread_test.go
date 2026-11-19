package awsread

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

// fakeLogs serves pages of messages, and records the inputs. A message
// "stream::msg" comes from that stream (else from "signs"); a page in
// failPage fails.
type fakeLogs struct {
	pages    [][]string
	failPage map[int]bool
	got      []*cloudwatchlogs.FilterLogEventsInput
}

func (f *fakeLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	f.got = append(f.got, in)
	i := 0
	if in.NextToken != nil {
		i = int(aws.ToString(in.NextToken)[0] - '0')
	}
	if f.failPage[i] {
		return nil, errors.New("throttled")
	}
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	for _, m := range f.pages[i] {
		stream := "signs"
		if s, msg, ok := strings.Cut(m, "::"); ok {
			stream, m = s, msg
		}
		out.Events = append(out.Events, cwltypes.FilteredLogEvent{Message: aws.String(m), IngestionTime: aws.Int64(1794394800000), LogStreamName: aws.String(stream)})
	}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

var (
	from = time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	to   = from.Add(3 * time.Hour)
)

func TestJournal(t *testing.T) {
	f := &fakeLogs{pages: [][]string{
		{`{"kind":"note","note":"sign_intent","at":"2026-11-11T10:00:00Z","proposal_id":"p1","name":"proposal","digest":"AQI=","lease_until":"2026-11-11T10:00:40Z"}`,
			`{"kind":"sign","kms_request_id":"r1","at":"2026-11-11T10:00:01Z","proposal_id":"p1","name":"proposal","digest":"AQI=","signature":"AwQ=","r":"BQ=="}`},
		{`{"kind":"complete","at":"2026-11-11T10:00:09Z","proposal_id":"p1","name":"proposal","digest":"AQI=","r":"BQ==","site_status":201}`},
	}}
	es, err := Journal(context.Background(), f, "/j", "signs", from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(es.Signs) != 1 || es.Signs[0].KMSRequestID != "r1" || string(es.Signs[0].R) != "\x05" || len(es.Completions) != 1 ||
		es.Completions[0].SiteStatus != 201 || len(es.Notes) != 1 || es.Notes[0].Kind != "sign_intent" ||
		!es.Notes[0].LeaseUntil.Equal(from.Add(time.Hour+40*time.Second)) || len(es.Unreadable) != 0 {
		t.Fatalf("read %+v", es)
	}
	if len(es.Ingested) != 1 {
		t.Fatalf("ingested %v", es.Ingested)
	}
	if len(f.got) != 2 || aws.ToString(f.got[0].LogGroupName) != "/j" || f.got[0].LogStreamNames[0] != "signs" ||
		aws.ToInt64(f.got[0].StartTime) != from.UnixMilli() || aws.ToInt64(f.got[0].EndTime) != to.UnixMilli() {
		t.Fatalf("asked %+v", f.got)
	}
	// An entry it can't decode is listed, and the read goes on past it:
	// one bad entry doesn't hide the rest of the journal.
	good := `{"kind":"sign","kms_request_id":"r2","at":"2026-11-11T10:00:01Z","proposal_id":"p1","name":"proposal","digest":"AQI=","signature":"AwQ=","r":"BQ=="}`
	f = &fakeLogs{pages: [][]string{{`not json`, `{"kind":"other"}`, `{"kind":"sign","digest":"not base64!"}`, good}}}
	es, err = Journal(context.Background(), f, "/j", "signs", from, to)
	if err != nil || len(es.Unreadable) != 3 || len(es.Signs) != 1 || es.Signs[0].KMSRequestID != "r2" {
		t.Fatalf("read past unreadable entries: %+v %v", es, err)
	}
}

// A failed page mid-read is a failed read: never a partial journal.
func TestJournalFailedPage(t *testing.T) {
	f := &fakeLogs{pages: [][]string{{`{"kind":"complete"}`}, {`{"kind":"complete"}`}}, failPage: map[int]bool{1: true}}
	if _, err := Journal(context.Background(), f, "/j", "signs", from, to); err == nil {
		t.Fatal("a failed second page read as the whole journal")
	}
	if _, err := History(context.Background(), f, "/j", "signs", from, to); err == nil {
		t.Fatal("a failed second page read as the whole history")
	}
	if _, _, err := KMSSigns(context.Background(), f, "/trail", "444455556666", from, to); err == nil {
		t.Fatal("a failed second page read as the whole trail")
	}
}

// Past the bound, a read fails rather than check part of what it reads.
func TestMaxEvents(t *testing.T) {
	f := &fakeLogs{pages: [][]string{{"a", "b"}, {"c"}}}
	n := 0
	err := filter(context.Background(), f, read{group: "/g", from: from, to: to, max: 2}, func(event) error { n++; return nil })
	if err == nil || n != 2 {
		t.Fatalf("read %d events past a bound of 2: %v", n, err)
	}
	if maxHistoryEvents < 2*20*24*366 {
		t.Fatalf("the history's bound %d is under a year of signs and completions at the alarm's rate", maxHistoryEvents)
	}
}

func TestHistory(t *testing.T) {
	f := &fakeLogs{pages: [][]string{{
		`{"kind":"sign","kms_request_id":"r1","at":"2026-01-11T10:00:01Z","proposal_id":"p1","name":"proposal","digest":"AQI=","signature":"AwQ=","r":"BQ=="}`,
		`{"kind":"complete","at":"2026-01-11T10:00:09Z","proposal_id":"p1","name":"proposal","digest":"AQI=","r":"BQ==","site_status":201}`,
	}}}
	es, err := History(context.Background(), f, "/j", "signs", from.Add(-365*24*time.Hour), to)
	if err != nil || len(es.Signs) != 1 || len(es.Completions) != 1 || len(es.Ingested) != 1 {
		t.Fatalf("%+v %v", es, err)
	}
	if aws.ToString(f.got[0].FilterPattern) != HistoryPattern || f.got[0].LogStreamNames[0] != "signs" ||
		aws.ToInt64(f.got[0].StartTime) != from.Add(-365*24*time.Hour).UnixMilli() {
		t.Fatalf("asked %+v", f.got[0])
	}
}

const acct = "444455556666"

func TestKMSSigns(t *testing.T) {
	key := "arn:aws:kms:us-east-1:" + acct + ":key/abc"
	rec := func(stream, id, issuer, keyARN, errCode, region, recipient, typ string) string {
		s := stream + `::{"eventTime":"2026-11-11T10:00:00Z","eventType":"` + typ + `","awsRegion":"` + region + `","recipientAccountId":"` + recipient +
			`","requestID":"` + id + `","userIdentity":{"arn":"arn:aws:sts::` + acct + `:assumed-role/x/s"`
		if issuer != "" {
			s += `,"sessionContext":{"sessionIssuer":{"arn":"` + issuer + `"}}`
		}
		s += `},"requestParameters":{"signingAlgorithm":"ECDSA_SHA_256","messageType":"DIGEST"},"resources":[{"ARN":"` + keyARN + `"}]`
		if errCode != "" {
			s += `,"errorCode":"` + errCode + `"`
		}
		return s + "}"
	}
	ct := acct + "_CloudTrail_us-east-1"
	signerRole := "arn:aws:iam::" + acct + ":role/signer"
	f := &fakeLogs{pages: [][]string{{
		rec(ct, "r1", signerRole, key, "", "us-east-1", acct, "AwsApiCall"),
		rec(ct+"_2", "r2", "", key, "AccessDeniedException", "us-east-1", acct, "AwsApiCall"),
		rec(acct+"_CloudTrail_eu-west-1", "r3", signerRole, "arn:aws:kms:eu-west-1:"+acct+":key/other", "", "eu-west-1", acct, "AwsApiCall"),
		// Not CloudTrail's: refused, never used.
		rec(acct+"_CloudTrail_us-east-1_x", "f1", signerRole, key, "", "us-east-1", acct, "AwsApiCall"),
		rec(acct+"_CloudTrail_us-east-1", "f2", signerRole, key, "", "eu-west-1", acct, "AwsApiCall"),
		rec(ct, "f3", signerRole, key, "", "us-east-1", "777788889999", "AwsApiCall"),
		rec(ct, "f4", signerRole, key, "", "us-east-1", acct, "AwsServiceEvent"),
		rec("777788889999_CloudTrail_us-east-1", "f5", signerRole, key, "", "us-east-1", "777788889999", "AwsApiCall"),
		ct + "::not json",
	}}}
	got, refused, err := KMSSigns(context.Background(), f, "/trail", acct, from, to)
	if err != nil {
		t.Fatal(err)
	}
	// Every Sign, on any key and in any region's stream (a rolled-over
	// stream too): one on another key is a finding, never dropped.
	if len(got) != 3 || got[2].KeyARN != "arn:aws:kms:eu-west-1:"+acct+":key/other" || got[0].KeyARN != key {
		t.Fatalf("signs %+v", got)
	}
	if got[0].RequestID != "r1" || got[0].Principal != signerRole || got[0].Algorithm != "ECDSA_SHA_256" || got[0].MessageType != "DIGEST" ||
		got[1].ErrorCode != "AccessDeniedException" || got[1].Principal != "arn:aws:sts::"+acct+":assumed-role/x/s" {
		t.Fatalf("signs %+v", got)
	}
	if len(refused) != 6 {
		t.Fatalf("refused %d: %q", len(refused), refused)
	}
	in := f.got[0]
	if aws.ToString(in.FilterPattern) != SignPattern || aws.ToString(in.LogStreamNamePrefix) != acct+"_CloudTrail_" || len(in.LogStreamNames) != 0 {
		t.Fatalf("asked %+v", in)
	}
}

func TestLastComplete(t *testing.T) {
	line := func(at string, complete bool) string {
		b, _ := json.Marshal(map[string]any{"time": at, "level": "INFO", "msg": "reconciled", "alarms": 0, "notices": 0, "complete": complete})
		return string(b)
	}
	// The fake's ingestion time is 2026-11-11T11:00:00Z: a line dated later
	// than it reached the log counts from then.
	f := &fakeLogs{pages: [][]string{{line("2026-11-10T17:00:00Z", true), line("2026-11-11T08:00:00Z", true), line("2026-11-11T12:00:00Z", true), `not json`}}}
	last, found, err := LastComplete(context.Background(), f, "/aws/lambda/rec", from.Add(-7*24*time.Hour), to)
	if err != nil || !found || !last.Equal(time.UnixMilli(1794394800000)) {
		t.Fatalf("%v %v %v", last, found, err)
	}
	if aws.ToString(f.got[0].FilterPattern) != CompletePattern || aws.ToString(f.got[0].LogGroupName) != "/aws/lambda/rec" {
		t.Fatalf("asked %+v", f.got[0])
	}
	f = &fakeLogs{pages: [][]string{{}}}
	if _, found, err := LastComplete(context.Background(), f, "/aws/lambda/rec", from, to); err != nil || found {
		t.Fatalf("none: %v %v", found, err)
	}
}

type fakeList map[string][]string // prefix → keys

func (f fakeList) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	out := &s3.ListObjectsV2Output{IsTruncated: aws.Bool(false)}
	for _, k := range f[aws.ToString(in.Prefix)] {
		out.Contents = append(out.Contents, s3types.Object{Key: aws.String(k)})
	}
	return out, nil
}

func TestSlots(t *testing.T) {
	list := fakeList{"v1/p/": {"v1/p/p1/proposal.json", "v1/p/p1/proposal.json.sig", "v1/p/p1/proposal.json.sigstore.json",
		"v1/p/p1/extension-1.json.sigstore.json", "v1/p/p2/rows.json", "v1/p/p2/x/y.json.sigstore.json", "v1/p/p3/results.json.sigstore.json"}}
	slots, odd, err := Slots(context.Background(), list, "b")
	if err != nil {
		t.Fatal(err)
	}
	// Every bundle under v1/p/, indexed or not; one that isn't a slot is
	// returned, never dropped.
	if strings.Join(slots, ",") != "p1/proposal,p1/extension-1,p3/results" || strings.Join(odd, ",") != "v1/p/p2/x/y.json.sigstore.json" {
		t.Fatalf("slots %v, odd %v", slots, odd)
	}
	for _, bad := range []string{"../x/proposal", "p1/other", "p1/proposal/x", "", "p1/extension-0"} {
		if ValidSlot(bad) {
			t.Fatalf("%q is a slot", bad)
		}
	}
}

type fakeVerifier struct{ err error }

func (f fakeVerifier) VerifyTimes(_, _, _ []byte) (site.AnchorTimes, error) {
	if f.err != nil {
		return site.AnchorTimes{}, f.err
	}
	return site.AnchorTimes{TSA: from}, nil
}

func TestHolding(t *testing.T) {
	ctx := context.Background()
	sig := []byte{3, 4}
	bundle := []byte(`{"messageSignature":{"signature":"` + base64.StdEncoding.EncodeToString(sig) + `"}}`)
	store := &site.MemStorage{}
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json.sigstore.json", bundle, "")
	_ = store.PutOnce(ctx, "v1/p/p1/proposal.json", []byte("doc"), "")
	_ = store.PutOnce(ctx, "v1/p/p2/proposal.json.sigstore.json", bundle, "")

	p, err := Holding(ctx, store, fakeVerifier{}, nil, "p1/proposal")
	if err != nil || !p.Held || string(p.Signature) != string(sig) || p.VerifyErr != "" || !p.AnchoredAt.Equal(from) {
		t.Fatalf("held: %+v %v", p, err)
	}
	p, err = Holding(ctx, store, fakeVerifier{err: errors.New("bad")}, nil, "p1/proposal")
	if err != nil || !p.Held || p.VerifyErr != "bad" {
		t.Fatalf("not verifying: %+v %v", p, err)
	}
	p, err = Holding(ctx, store, fakeVerifier{}, nil, "p2/proposal")
	if err != nil || !p.Held || p.VerifyErr == "" {
		t.Fatalf("a bundle with no document: %+v %v", p, err)
	}
	p, err = Holding(ctx, store, fakeVerifier{}, nil, "p3/proposal")
	if err != nil || p.Held {
		t.Fatalf("nothing held: %+v %v", p, err)
	}
	if _, err := MessageSignature([]byte(`{}`)); err == nil {
		t.Fatal("a bundle with no message signature")
	}
}

func TestCanonical(t *testing.T) {
	if Canonical("{ \"a\" : [1, 2] }") != `{"a":[1,2]}` || Canonical("not json") != "not json" {
		t.Fatal("canonical")
	}
}

type fakeClaims map[string]*signer.Claim

func (f fakeClaims) Get(_ context.Context, slot string) (*signer.Claim, error) {
	if slot == "err/proposal" {
		return nil, errors.New("throttled")
	}
	return f[slot], nil
}

func TestClaim(t *testing.T) {
	f := fakeClaims{"p1/proposal": {Digest: []byte{1}, Sig: []byte{2}, R: []byte{3}, RequestID: "r1"}}
	c, err := Claim(context.Background(), f, "p1/proposal")
	if err != nil || !c.Exists || c.RequestID != "r1" || !bytes.Equal(c.Sig, []byte{2}) {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := Claim(context.Background(), f, "p2/proposal"); err != nil || c.Exists {
		t.Fatalf("no claim: %+v %v", c, err)
	}
	if _, err := Claim(context.Background(), f, "err/proposal"); err == nil {
		t.Fatal("an error read as no claim")
	}
	if _, err := Claim(context.Background(), f, "../p1/proposal"); err == nil {
		t.Fatal("not a slot")
	}
}

type fakeTrail struct {
	out *cloudtrail.GetTrailStatusOutput
	sel []cttypes.AdvancedEventSelector
}

func (f fakeTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return f.out, nil
}

func (f fakeTrail) GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	return &cloudtrail.GetEventSelectorsOutput{AdvancedEventSelectors: f.sel}, nil
}

var stagingNames = TrailNames{Partition: "aws", Region: "us-east-1", Account: acct, Function: "vettid-anchor-signer-staging", ClaimsTable: "vettid-anchor-claims-staging"}

// deployed is the selectors AnchorSigner-staging's trail has, as AWS
// returned them (get-event-selectors, the account masked).
func deployed(t *testing.T) []cttypes.AdvancedEventSelector {
	b, err := os.ReadFile("testdata/staging-trail-selectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var out cloudtrail.GetEventSelectorsOutput
	if err := json.Unmarshal(b, &out); err != nil || len(out.AdvancedEventSelectors) != 3 {
		t.Fatalf("testdata: %v", err)
	}
	return out.AdvancedEventSelectors
}

func TestTrailProblem(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)
	quiet := now.Add(-65 * time.Minute) // a quiet account: the last run's own calls, an hour ago
	stale := now.Add(-2 * time.Hour)
	want := WantSelectors(stagingNames)
	sel := deployed(t)
	for _, c := range []struct {
		out  cloudtrail.GetTrailStatusOutput
		want bool
	}{
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh}, false},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &quiet}, false},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(false), LatestCloudWatchLogsDeliveryTime: &fresh}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &stale}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh, LatestCloudWatchLogsDeliveryError: aws.String("AccessDenied")}, true},
	} {
		got, err := TrailProblem(context.Background(), fakeTrail{&c.out, sel}, "t", want, now)
		if err != nil || (got != "") != c.want {
			t.Fatalf("%+v: %q %v", c.out, got, err)
		}
	}
	// The selectors as deployed are the stack's, in any order; anything
	// narrowed, removed or added is a problem.
	ok := cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh}
	reversed := []cttypes.AdvancedEventSelector{sel[2], sel[1], sel[0]}
	if got, _ := TrailProblem(context.Background(), fakeTrail{&ok, reversed}, "t", want, now); got != "" {
		t.Fatalf("reordered: %q", got)
	}
	clone := func() []cttypes.AdvancedEventSelector {
		b, _ := json.Marshal(sel)
		var c []cttypes.AdvancedEventSelector
		_ = json.Unmarshal(b, &c)
		return c
	}
	writeOnly := clone()
	for i := range writeOnly {
		if len(writeOnly[i].FieldSelectors) == 1 {
			writeOnly[i].FieldSelectors = append(writeOnly[i].FieldSelectors, cttypes.AdvancedFieldSelector{Field: aws.String("readOnly"), Equals: []string{"false"}})
		}
	}
	narrowedInvokes := clone()
	for i := range narrowedInvokes {
		for j := range narrowedInvokes[i].FieldSelectors {
			if f := &narrowedInvokes[i].FieldSelectors[j]; aws.ToString(f.Field) == "resources.ARN" && len(f.StartsWith) == 1 {
				f.StartsWith = []string{f.StartsWith[0] + "-nothing"}
			}
		}
	}
	added := append(clone(), cttypes.AdvancedEventSelector{FieldSelectors: []cttypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
		{Field: aws.String("resources.type"), Equals: []string{"AWS::S3::Object"}}}})
	for name, s := range map[string][]cttypes.AdvancedEventSelector{"none": nil, "management write only": writeOnly,
		"invokes narrowed": narrowedInvokes, "claim writes removed": sel[:2], "one added": added} {
		if got, err := TrailProblem(context.Background(), fakeTrail{&ok, s}, "t", want, now); err != nil || got == "" {
			t.Fatalf("selectors %s: %q %v", name, got, err)
		}
	}
	// Basic selectors alongside: not the stack's.
	if selectorsAreTheStacks(&cloudtrail.GetEventSelectorsOutput{AdvancedEventSelectors: sel, EventSelectors: []cttypes.EventSelector{{}}}, want) {
		t.Fatal("basic selectors alongside")
	}
}

type fakeFunction struct {
	cfg lambda.GetFunctionConfigurationOutput
}

func (f fakeFunction) GetFunctionConfiguration(context.Context, *lambda.GetFunctionConfigurationInput, ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error) {
	return &f.cfg, nil
}

func (f fakeFunction) GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return &lambda.GetPolicyOutput{Policy: aws.String(`{ "Version": "2012-10-17" }`)}, nil
}

func TestFunction(t *testing.T) {
	f := fakeFunction{lambda.GetFunctionConfigurationOutput{CodeSha256: aws.String("c"), Runtime: lambdatypes.RuntimeProvidedal2023,
		Handler: aws.String("bootstrap"), Role: aws.String("arn:aws:iam::" + acct + ":role/signer"),
		Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureArm64},
		Layers:        []lambdatypes.Layer{{Arn: aws.String("arn:aws:lambda:us-east-1:" + acct + ":layer:x:1")}},
		Environment:   &lambdatypes.EnvironmentResponse{Variables: map[string]string{"B": "secret value", "A": "x"}}}}
	d, err := Function(context.Background(), f, "fn")
	if err != nil {
		t.Fatal(err)
	}
	if d.CodeSha256 != "c" || d.Policy != `{"Version":"2012-10-17"}` || d.Runtime != "provided.al2023" || d.Handler != "bootstrap" ||
		d.Role != "arn:aws:iam::"+acct+":role/signer" || strings.Join(d.Architectures, ",") != "arm64" || len(d.Layers) != 1 ||
		strings.Join(d.EnvNames, ",") != "A,B" {
		t.Fatalf("%+v", d)
	}
	// Names only: never a value.
	if strings.Contains(strings.Join(append(d.EnvNames, d.Layers...), " "), "secret") {
		t.Fatal("an environment value was read")
	}
}

type failStore struct{ site.Storage }

func (failStore) Get(context.Context, string) ([]byte, string, error) {
	return nil, "", errors.New("AccessDenied")
}

func TestSiteCheck(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	// A read that fails: an error (the proposal not checked), not a refusal.
	if refused, err := SiteCheck(ctx, failStore{}, nil, key, "00000000000000000000000001", from); err == nil || refused != "" {
		t.Fatalf("a failed read: %q %v", refused, err)
	}
	// What the check refuses (here services.json missing): a refusal.
	refused, err := SiteCheck(ctx, &site.MemStorage{Objects: map[string][]byte{}}, nil, key, "00000000000000000000000001", from)
	if err != nil || refused == "" {
		t.Fatalf("refused: %q %v", refused, err)
	}
}

type fakeVersions struct {
	versions []string
	aliases  []string
}

func (f fakeVersions) ListVersionsByFunction(context.Context, *lambda.ListVersionsByFunctionInput, ...func(*lambda.Options)) (*lambda.ListVersionsByFunctionOutput, error) {
	out := &lambda.ListVersionsByFunctionOutput{}
	for _, v := range f.versions {
		out.Versions = append(out.Versions, lambdatypes.FunctionConfiguration{Version: aws.String(v)})
	}
	return out, nil
}

func (f fakeVersions) ListAliases(context.Context, *lambda.ListAliasesInput, ...func(*lambda.Options)) (*lambda.ListAliasesOutput, error) {
	out := &lambda.ListAliasesOutput{}
	for _, a := range f.aliases {
		out.Aliases = append(out.Aliases, lambdatypes.AliasConfiguration{Name: aws.String(a)})
	}
	return out, nil
}

func TestVersionsAndAliases(t *testing.T) {
	v, a, err := VersionsAndAliases(context.Background(), fakeVersions{versions: []string{"$LATEST"}}, "fn")
	if err != nil || len(v) != 0 || len(a) != 0 {
		t.Fatalf("only $LATEST: %v %v %v", v, a, err)
	}
	v, a, err = VersionsAndAliases(context.Background(), fakeVersions{versions: []string{"$LATEST", "1"}, aliases: []string{"live"}}, "fn")
	if err != nil || strings.Join(v, ",") != "1" || strings.Join(a, ",") != "live" {
		t.Fatalf("%v %v %v", v, a, err)
	}
}

// The slot pattern's names are the site's own (site/site.go nameRe): a
// name the site adds and this doesn't fails here, not silently in a pass.
func TestSlotNamesAreTheSite(t *testing.T) {
	src, err := os.ReadFile("../../site/site.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var nameRe = regexp\.MustCompile\(` + "`" + `\^\(([^` + "`" + `]*)\)\$` + "`" + `\)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("the site's nameRe isn't where it was")
	}
	site := strings.ReplaceAll(string(m[1]), "extension-([1-9][0-9]?)", "extension-[1-9][0-9]?")
	if !strings.Contains(slotRe.String(), "/("+site+")$") {
		t.Fatalf("slot names %s, the site's %s", slotRe, site)
	}
}
