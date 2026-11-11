package awsread

import (
	"bytes"
	"context"
	"encoding/base64"
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

// fakeLogs serves pages of messages, and records the inputs.
type fakeLogs struct {
	pages [][]string
	got   []*cloudwatchlogs.FilterLogEventsInput
}

func (f *fakeLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	f.got = append(f.got, in)
	i := 0
	if in.NextToken != nil {
		i = int(aws.ToString(in.NextToken)[0] - '0')
	}
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	for _, m := range f.pages[i] {
		out.Events = append(out.Events, cwltypes.FilteredLogEvent{Message: aws.String(m)})
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
	signs, done, notes, err := Journal(context.Background(), f, "/j", "signs", from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(signs) != 1 || signs[0].KMSRequestID != "r1" || string(signs[0].R) != "\x05" || len(done) != 1 || done[0].SiteStatus != 201 ||
		len(notes) != 1 || notes[0].Kind != "sign_intent" || !notes[0].LeaseUntil.Equal(from.Add(time.Hour+40*time.Second)) {
		t.Fatalf("read %+v %+v %+v", signs, done, notes)
	}
	if len(f.got) != 2 || aws.ToString(f.got[0].LogGroupName) != "/j" || f.got[0].LogStreamNames[0] != "signs" ||
		aws.ToInt64(f.got[0].StartTime) != from.UnixMilli() || aws.ToInt64(f.got[0].EndTime) != to.UnixMilli() {
		t.Fatalf("asked %+v", f.got)
	}
	// An entry it can't read stops the read: never a partial journal.
	for _, bad := range []string{`not json`, `{"kind":"other"}`, `{"kind":"sign","digest":"not base64!"}`} {
		f := &fakeLogs{pages: [][]string{{bad}}}
		if _, _, _, err := Journal(context.Background(), f, "/j", "signs", from, to); err == nil {
			t.Fatalf("read %s", bad)
		}
	}
}

func TestKMSSigns(t *testing.T) {
	key := "arn:aws:kms:us-east-1:444455556666:key/abc"
	rec := func(id, issuer, keyARN, errCode string) string {
		s := `{"eventTime":"2026-11-11T10:00:00Z","requestID":"` + id + `","userIdentity":{"arn":"arn:aws:sts::444455556666:assumed-role/x/s"`
		if issuer != "" {
			s += `,"sessionContext":{"sessionIssuer":{"arn":"` + issuer + `"}}`
		}
		s += `},"requestParameters":{"signingAlgorithm":"ECDSA_SHA_256","messageType":"DIGEST"},"resources":[{"ARN":"` + keyARN + `"}]`
		if errCode != "" {
			s += `,"errorCode":"` + errCode + `"`
		}
		return s + "}"
	}
	f := &fakeLogs{pages: [][]string{{
		rec("r1", "arn:aws:iam::444455556666:role/signer", key, ""),
		rec("r2", "", key, "AccessDeniedException"),
		rec("r3", "arn:aws:iam::444455556666:role/signer", "arn:aws:kms:us-east-1:444455556666:key/other", ""),
	}}}
	got, err := KMSSigns(context.Background(), f, "/trail", from, to)
	if err != nil {
		t.Fatal(err)
	}
	// Every Sign, on any key: one on another key is a finding, never dropped.
	if len(got) != 3 || got[2].KeyARN != "arn:aws:kms:us-east-1:444455556666:key/other" || got[0].KeyARN != key {
		t.Fatalf("signs %+v", got)
	}
	if got[0].RequestID != "r1" || got[0].Principal != "arn:aws:iam::444455556666:role/signer" ||
		got[0].Algorithm != "ECDSA_SHA_256" || got[0].MessageType != "DIGEST" ||
		got[1].ErrorCode != "AccessDeniedException" || got[1].Principal != "arn:aws:sts::444455556666:assumed-role/x/s" {
		t.Fatalf("signs %+v", got)
	}
	if aws.ToString(f.got[0].FilterPattern) != SignPattern {
		t.Fatalf("pattern %q", aws.ToString(f.got[0].FilterPattern))
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
	return site.AnchorTimes{}, f.err
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
	if err != nil || !p.Held || string(p.Signature) != string(sig) || p.VerifyErr != "" {
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

var allManagement = []cttypes.AdvancedEventSelector{{FieldSelectors: []cttypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}}

func TestTrailProblem(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Minute)
	stale := now.Add(-time.Hour)
	for _, c := range []struct {
		out  cloudtrail.GetTrailStatusOutput
		want bool
	}{
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh}, false},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(false), LatestCloudWatchLogsDeliveryTime: &fresh}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &stale}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, true},
		{cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh, LatestCloudWatchLogsDeliveryError: aws.String("AccessDenied")}, true},
	} {
		got, err := TrailProblem(context.Background(), fakeTrail{&c.out, allManagement}, "t", now)
		if err != nil || (got != "") != c.want {
			t.Fatalf("%+v: %q %v", c.out, got, err)
		}
	}
	// Selectors narrowed (write only, or none): a problem.
	ok := cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true), LatestCloudWatchLogsDeliveryTime: &fresh}
	writeOnly := []cttypes.AdvancedEventSelector{{FieldSelectors: []cttypes.AdvancedFieldSelector{
		{Field: aws.String("eventCategory"), Equals: []string{"Management"}}, {Field: aws.String("readOnly"), Equals: []string{"false"}}}}}
	for _, sel := range [][]cttypes.AdvancedEventSelector{nil, writeOnly} {
		if got, err := TrailProblem(context.Background(), fakeTrail{&ok, sel}, "t", now); err != nil || got == "" {
			t.Fatalf("selectors %+v: %q %v", sel, got, err)
		}
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
