package site

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// published runs the fixture's vote through the site, as it was
// published, and returns what the site serves.
func published(t *testing.T, f *fixture, results bool) map[string][]byte {
	t.Helper()
	s, st := newSite(t, f, f.during())
	for _, step := range []struct {
		name string
		u    *Upload
	}{{"proposal", &f.Proposal}, {"extension-1", &f.Extension}} {
		if code, why := post(t, s, step.name, step.u); code != 201 {
			t.Fatalf("%s: %d %s", step.name, code, why)
		}
	}
	if results {
		at(s, f.closed())
		if code, why := post(t, s, "results", &f.Results); code != 201 {
			t.Fatalf("results: %d %s", code, why)
		}
	}
	return maps.Clone(st.Objects)
}

func fetcher(objs map[string][]byte) Fetcher {
	return func(_ context.Context, path string) ([]byte, error) { return bytes.Clone(objs[path]), nil }
}

func check(t *testing.T, f *fixture, objs map[string][]byte, id string) (*Report, error) {
	t.Helper()
	s, _ := newSite(t, f, f.during())
	return Check(context.Background(), fetcher(objs), s.Anchors, s.SiteKey, id, f.closed(), nil)
}

// A published vote checks from the site's files alone; one whose files
// were changed, or that lacks one, doesn't.
func TestCheck(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, true)
	rep, err := check(t, f, objs, testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Hashes) != 4 || rep.Partial != nil {
		t.Fatalf("hashes %v, partial %v", rep.Hashes, rep.Partial)
	}
	// Each anchored document's bundle gives its Rekor entry.
	if len(rep.Entries) != len(rep.Anchored) {
		t.Fatalf("%d entries for %d anchored documents", len(rep.Entries), len(rep.Anchored))
	}
	leaves := map[string]string{}
	for name, e := range rep.Entries {
		if len(e.Leaf) != 32 || e.Checkpoint == "" || e.Integrated.IsZero() {
			t.Errorf("%s: %+v", name, e)
		}
		// Each document's own entry, not one shared.
		if other, dup := leaves[string(e.Leaf)]; dup {
			t.Errorf("%s and %s share an entry", name, other)
		}
		leaves[string(e.Leaf)] = name
	}
	if rep.Title != f.p.Title || rep.Extensions != 1 || rep.ClosesAt != f.e.ClosesAt || rep.Results == nil ||
		rep.Results.Counts.Eligible != f.p.Eligible || len(rep.Anchored) != 3 || rep.ServiceName != "Test service" {
		t.Fatalf("report %+v", rep)
	}
	for name, change := range map[string]func(map[string][]byte){
		"rows changed": func(o map[string][]byte) {
			o["v1/p/"+testID+"/rows.json"] = append(bytes.Clone(o["v1/p/"+testID+"/rows.json"]), ' ')
		},
		"extension withdrawn": func(o map[string][]byte) { delete(o, docPath(testID, "extension-1")) },
		"bundle missing":      func(o map[string][]byte) { delete(o, docPath(testID, "results")+".sigstore.json") },
		"proposal signature": func(o map[string][]byte) {
			sig := bytes.Clone(o[docPath(testID, "proposal")+".sig"])
			sig[0] ^= 1
			o[docPath(testID, "proposal")+".sig"] = sig
		},
		"service list unsigned": func(o map[string][]byte) { delete(o, "v1/services.json.sig") },
		"extension after a gap": func(o map[string][]byte) { o[docPath(testID, "extension-3")] = o[docPath(testID, "extension-1")] },
		"extension past the limit": func(o map[string][]byte) {
			o[docPath(testID, "extension-25")] = o[docPath(testID, "extension-1")]
		},
		"bundles swapped": func(o map[string][]byte) {
			o[docPath(testID, "results")+".sigstore.json"] = o[docPath(testID, "proposal")+".sigstore.json"]
		},
	} {
		o := maps.Clone(objs)
		change(o)
		if _, err := check(t, f, o, testID); err == nil {
			t.Errorf("%s: checked", name)
		}
	}
}

// Before the results, a vote checks with none; an id the site doesn't
// serve is ErrNotPublished.
func TestCheckOpenAndUnknown(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, false)
	rep, err := check(t, f, objs, testID)
	if err != nil || rep.Results != nil || rep.Extensions != 1 {
		t.Fatalf("an open vote: %+v %v", rep, err)
	}
	// An upload of the results that wrote its signature but not the
	// document yet is reported, not counted.
	o := maps.Clone(objs)
	o[docPath(testID, "results")+".sig"] = []byte("x")
	if rep, err := check(t, f, o, testID); err != nil || rep.Results != nil || len(rep.Partial) != 1 || rep.Partial[0] != "results" {
		t.Fatalf("partial results: %+v %v", rep, err)
	}
	if _, err := check(t, f, objs, "01KC0000000000000000000002"); !errors.Is(err, ErrNotPublished) {
		t.Fatalf("unknown: %v", err)
	}
}

// The index and the archive are compared with the documents: a
// difference is reported, not a failed check.
func TestCheckListing(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, true)
	rep, err := check(t, f, objs, testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Listing) != 0 {
		t.Fatalf("listing differences on a published vote: %v", rep.Listing)
	}
	edit := func(path string, change func(*IndexEntry)) map[string][]byte {
		o := maps.Clone(objs)
		var es []IndexEntry
		if err := json.Unmarshal(o[path], &es); err != nil || len(es) != 1 {
			t.Fatalf("%s: %v", path, err)
		}
		change(&es[0])
		o[path], _ = json.Marshal(es)
		return o
	}
	for name, c := range map[string]struct {
		objs map[string][]byte
		want string
	}{
		"closes_at":         {edit(indexPath, func(e *IndexEntry) { e.ClosesAt++ }), "index: closes_at"},
		"unhandled":         {edit(indexPath, func(e *IndexEntry) { n := *e.Unhandled + 1; e.Unhandled = &n }), "index: unhandled"},
		"published":         {edit(archivePath(f.p.OpensAt), func(e *IndexEntry) { e.Published = false }), "archive: published"},
		"missing":           {edit(archivePath(f.p.OpensAt), func(e *IndexEntry) { e.ProposalID = "01KC0000000000000000000002" }), "archive: missing"},
		"archive not there": {func() map[string][]byte { o := maps.Clone(objs); delete(o, archivePath(f.p.OpensAt)); return o }(), "archive: not published"},
	} {
		rep, err := check(t, f, c.objs, testID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Contains(rep.Listing, c.want) {
			t.Fatalf("%s: listing %v, want %q", name, rep.Listing, c.want)
		}
	}
	// An entry from before the site listed unhandled lacks it.
	if rep, err := check(t, f, edit(indexPath, func(e *IndexEntry) { e.Unhandled = nil }), testID); err != nil || len(rep.Listing) != 0 {
		t.Fatalf("an entry without unhandled: %v %v", rep, err)
	}
	// Long after the close, the index may have dropped it.
	o := edit(indexPath, func(e *IndexEntry) { e.ProposalID = "01KC0000000000000000000002" })
	s, _ := newSite(t, f, f.during())
	later := f.closed().Add(IndexWindow + time.Hour)
	if rep, err := Check(context.Background(), fetcher(o), s.Anchors, s.SiteKey, testID, later, nil); err != nil || len(rep.Listing) != 0 {
		t.Fatalf("an index past its window: %v %v", rep, err)
	}
	if rep, err := check(t, f, o, testID); err != nil || !slices.Contains(rep.Listing, "index: missing") {
		t.Fatalf("an index missing an entry in its window: %v %v", rep, err)
	}
}

// The results' embedded signatures must be the published .sig files: a
// vote whose proposal or extension is served with another valid
// signature fails the check, naming the document.
func TestCheckPublishedSigs(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, true)
	p2, e2 := f.resigned(t)
	for name, sig := range map[string][]byte{"proposal": p2.Sig, "extension-1": e2.Sig} {
		o := maps.Clone(objs)
		o[docPath(testID, name)+".sig"] = sig
		_, err := check(t, f, o, testID)
		if err == nil || !strings.Contains(err.Error(), "results: sig_mismatch") ||
			!strings.Contains(err.Error(), "the published "+name+".json.sig") {
			t.Fatalf("%s served with another signature: %v", name, err)
		}
	}
}

// The upload API's request rules are applied: a part the site should have
// refused fails the check.
func TestCheckUploadRules(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, true)
	o := maps.Clone(objs)
	b := "v1/p/" + testID + "/proposal.json.sigstore.json"
	o[b] = append(bytes.Clone(o[b]), bytes.Repeat([]byte(" "), maxBundle)...)
	if _, err := check(t, f, o, testID); err == nil || !strings.Contains(err.Error(), "should have refused (bad_request)") {
		t.Fatalf("an oversized bundle: %v", err)
	}
	o = maps.Clone(objs)
	o["v1/p/"+testID+"/results.json.sig"] = []byte("short")
	if _, err := check(t, f, o, testID); err == nil || !strings.Contains(err.Error(), "should have refused") {
		t.Fatalf("a short signature: %v", err)
	}
}

// A listing difference, or a partial upload, is a mismatch only past
// ListingGrace: after the latest anchor, or the partial's own timestamp.
func TestCheckMismatches(t *testing.T) {
	f := loadFixture(t)
	objs := published(t, f, true)
	s, _ := newSite(t, f, f.during())
	var modified func(context.Context, string) (time.Time, error)
	at := func(o map[string][]byte, now time.Time) *Report {
		t.Helper()
		rep, err := Check(context.Background(), fetcher(o), s.Anchors, s.SiteKey, testID, now, modified)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	rep := at(objs, f.closed().Add(24*time.Hour))
	if len(rep.Mismatches) != 0 || len(rep.Skew) != 3 {
		t.Fatalf("a vote served as it should be: mismatches %v, skew %v", rep.Mismatches, rep.Skew)
	}
	for name, d := range rep.Skew {
		if d > MaxSkew || d < -MaxSkew {
			t.Fatalf("%s: skew %s", name, d)
		}
	}
	latest := rep.Anchored["results"]

	o := maps.Clone(objs)
	var es []IndexEntry
	_ = json.Unmarshal(o[indexPath], &es)
	es[0].ClosesAt++
	o[indexPath], _ = json.Marshal(es)
	if rep := at(o, latest.Add(ListingGrace)); len(rep.Listing) != 1 || len(rep.Mismatches) != 0 {
		t.Fatalf("within the grace: %v %v", rep.Listing, rep.Mismatches)
	}
	if rep := at(o, latest.Add(ListingGrace+time.Second)); !slices.Equal(rep.Mismatches, []string{"listing: index: closes_at"}) {
		t.Fatalf("past the grace: %v", rep.Mismatches)
	}

	// Results whose signature and bundle are there without the document:
	// dated by the bundle's timestamp.
	open := published(t, f, false)
	o = maps.Clone(open)
	base := docPath(testID, "results")
	o[base+".sig"], o[base+".sigstore.json"] = f.Results.Sig, f.Results.Bundle
	ts, err := s.Anchors.TimestampOf(f.Results.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if rep := at(o, ts.Add(ListingGrace)); len(rep.Partial) != 1 || len(rep.Mismatches) != 0 {
		t.Fatalf("a partial upload within the grace: %v %v", rep.Partial, rep.Mismatches)
	}
	if rep := at(o, ts.Add(ListingGrace+time.Second)); len(rep.Mismatches) != 1 || !strings.HasPrefix(rep.Mismatches[0], "partial: results: since ") {
		t.Fatalf("a partial upload past the grace: %v", rep.Mismatches)
	}
	// A signature alone has no verified time: it is dated by its
	// Last-Modified, and is a mismatch at once without one.
	delete(o, base+".sigstore.json")
	if rep := at(o, ts); !slices.Equal(rep.Mismatches, []string{"partial: results: no verified timestamp"}) {
		t.Fatalf("an undated partial upload: %v", rep.Mismatches)
	}
	modified = func(_ context.Context, path string) (time.Time, error) {
		if path != base+".sig" {
			t.Fatalf("Last-Modified of %s", path)
		}
		return ts, nil
	}
	if rep := at(o, ts.Add(ListingGrace)); len(rep.Partial) != 1 || len(rep.Mismatches) != 0 {
		t.Fatalf("a signature alone within the grace: %v %v", rep.Partial, rep.Mismatches)
	}
	want := "partial: results: since " + ts.UTC().Format(time.RFC3339) + " (its signature's Last-Modified; no bundle)"
	if rep := at(o, ts.Add(ListingGrace+time.Second)); !slices.Equal(rep.Mismatches, []string{want}) {
		t.Fatalf("a signature alone past the grace: %v", rep.Mismatches)
	}
	modified = func(context.Context, string) (time.Time, error) { return time.Time{}, errors.New("no answer") }
	if rep := at(o, ts); !slices.Equal(rep.Mismatches, []string{"partial: results: no verified timestamp"}) {
		t.Fatalf("a signature alone with no Last-Modified: %v", rep.Mismatches)
	}
}

func TestSkewMismatch(t *testing.T) {
	t0 := time.Unix(1793354334, 0)
	for _, c := range []struct {
		tsa, rekor time.Time
		want       string
	}{
		{t0, t0, ""},
		{t0.Add(MaxSkew), t0, ""},
		{t0, t0.Add(MaxSkew), ""},
		{t0.Add(MaxSkew + time.Second), t0, "skew: proposal: the RFC 3161 time is 10m1s from Rekor's"},
		{t0, t0.Add(MaxSkew + time.Second), "skew: proposal: the RFC 3161 time is -10m1s from Rekor's"},
		{t0, time.Time{}, "skew: proposal: no Rekor integrated time"},
	} {
		if got := skewMismatch("proposal", AnchorTimes{TSA: c.tsa, Rekor: c.rekor}); got != c.want {
			t.Errorf("%v %v: %q, want %q", c.tsa, c.rekor, got, c.want)
		}
	}
}

// A partial extension is permanent once the close it extends has passed
// or the results are out; the results' partial never is.
func TestCheckPermanentPartial(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	ext2 := docPath(testID, "extension-2") + ".sig"
	for name, c := range map[string]struct {
		results   bool
		now       time.Time
		permanent bool
	}{
		"before its close":      {false, time.Unix(f.e.ClosesAt-60, 0), false},
		"after its close":       {false, time.Unix(f.e.ClosesAt, 0), true},
		"after the results are": {true, f.closed(), true},
	} {
		o := published(t, f, c.results)
		o[ext2] = f.Extension.Sig
		rep, err := Check(context.Background(), fetcher(o), s.Anchors, s.SiteKey, testID, c.now, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := slices.Contains(rep.PartialPermanent, "extension-2"); got != c.permanent || !slices.Contains(rep.Partial, "extension-2") {
			t.Fatalf("%s: partial %v, permanent %v", name, rep.Partial, rep.PartialPermanent)
		}
		if c.permanent != strings.Contains(strings.Join(rep.Mismatches, "\n"), "(permanent") {
			t.Fatalf("%s: mismatches %v", name, rep.Mismatches)
		}
		// Only a permanent partial may be acknowledged; acknowledging a
		// retryable one is itself a mismatch.
		ack := Acknowledgement{ProposalID: testID, Document: "extension-2", Reason: "x", AcknowledgedAt: "2026-11-04",
			Objects: []Object{objectOf(ext2, f.Extension.Sig)}}
		rep.Acknowledge([]Acknowledgement{ack})
		stale := slices.Contains(rep.Mismatches, StaleAcknowledgement(ack))
		if acked := slices.Contains(rep.Acknowledged, "extension-2"); acked != c.permanent || stale == c.permanent {
			t.Fatalf("%s: acknowledged %v, mismatches %v", name, rep.Acknowledged, rep.Mismatches)
		}
	}
}

// An acknowledged partial is reported, not a mismatch, while its served
// objects are exactly the entry's; an unlisted one is a mismatch, and so
// is an acknowledgement that matches no partial, or whose objects differ
// from those served.
func TestAcknowledged(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	o := published(t, f, true)
	sigKey := docPath(testID, "extension-2") + ".sig"
	bundleKey := docPath(testID, "extension-2") + ".sigstore.json"
	o[sigKey] = f.Extension.Sig
	now := f.closed()
	check := func(acks []Acknowledgement) *Report {
		t.Helper()
		rep, err := Check(context.Background(), fetcher(o), s.Anchors, s.SiteKey, testID, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		rep.Acknowledge(acks)
		return rep
	}
	rep := check(nil)
	if len(rep.Mismatches) != 1 || !strings.HasPrefix(rep.Mismatches[0], "partial: extension-2") {
		t.Fatalf("unlisted: %v", rep.Mismatches)
	}
	sigHash := hex.EncodeToString(sha(f.Extension.Sig))
	if want := []Object{{sigKey, sigHash}}; !slices.Equal(rep.PartialObjects["extension-2"], want) {
		t.Fatalf("partial objects %v, want %v", rep.PartialObjects, want)
	}
	entry := func(objects string) string {
		return `{"proposal_id":"` + testID + `","document":"extension-2","reason":"an upload interrupted after the close","acknowledged_at":"2026-11-04",
			"objects":[` + objects + `]}`
	}
	obj := func(key, h string) string { return `{"key":"` + key + `","sha256":"` + h + `"}` }
	acks, err := ParseAcknowledged([]byte(`[` + entry(obj(sigKey, sigHash)) + `,
		{"proposal_id":"01KC0000000000000000000002","document":"results","reason":"another vote's","acknowledged_at":"2026-11-04",
			"objects":[{"key":"v1/p/01KC0000000000000000000002/results.json.sig","sha256":"` + sigHash + `"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if rep := check(acks); len(rep.Mismatches) != 0 || !slices.Equal(rep.Acknowledged, []string{"extension-2"}) {
		t.Fatalf("acknowledged: %v %v", rep.Mismatches, rep.Acknowledged)
	}
	stale := []Acknowledgement{acks[0], {ProposalID: testID, Document: "results", Reason: "x", AcknowledgedAt: "2026-11-04",
		Objects: []Object{{docPath(testID, "results") + ".sig", sigHash}}}}
	if rep := check(stale); !slices.Equal(rep.Mismatches, []string{StaleAcknowledgement(stale[1])}) {
		t.Fatalf("stale: %v", rep.Mismatches)
	}

	// The entry names the objects: another signature at the name, an
	// object added to it, or one listed that isn't served, is a
	// mismatch, and the partial is not acknowledged.
	differs := func(name string, acks []Acknowledgement, want string) {
		t.Helper()
		rep := check(acks)
		if len(rep.Acknowledged) != 0 ||
			!slices.Contains(rep.Mismatches, "acknowledged: "+testID+" extension-2: the served objects differ from the entry's ("+want+")") {
			t.Fatalf("%s: acknowledged %v, mismatches %q", name, rep.Acknowledged, rep.Mismatches)
		}
	}
	o[sigKey] = append(bytes.Clone(f.Extension.Sig), 0)
	differs("a changed signature", acks, "changed: "+sigKey+" is served with sha256 "+hex.EncodeToString(sha(o[sigKey])))
	o[sigKey] = f.Extension.Sig
	o[bundleKey] = f.Extension.Bundle
	differs("an added bundle", acks, "not listed: "+bundleKey+" with sha256 "+hex.EncodeToString(sha(f.Extension.Bundle)))
	delete(o, bundleKey)
	withBundle := acks[0]
	withBundle.Objects = append(slices.Clone(withBundle.Objects), objectOf(bundleKey, f.Extension.Bundle))
	differs("a listed object not served", []Acknowledgement{withBundle}, "not served: "+bundleKey)

	// Another partial of the same vote isn't covered by the entry: with
	// extension-2 acknowledged, results left partial past the grace are
	// still a mismatch.
	open := published(t, f, false)
	o = maps.Clone(open)
	o[sigKey] = f.Extension.Sig
	o[docPath(testID, "results")+".sig"], o[docPath(testID, "results")+".sigstore.json"] = f.Results.Sig, f.Results.Bundle
	ts, err := s.Anchors.TimestampOf(f.Results.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	now = ts.Add(ListingGrace + time.Second)
	if rep := check(acks); !slices.Equal(rep.Acknowledged, []string{"extension-2"}) || len(rep.Mismatches) != 1 ||
		!strings.HasPrefix(rep.Mismatches[0], "partial: results: since ") {
		t.Fatalf("another partial: acknowledged %v, mismatches %v", rep.Acknowledged, rep.Mismatches)
	}

	h := `"` + sigHash + `"`
	e := func(doc, objects string) string {
		return `[{"proposal_id":"` + testID + `","document":"` + doc + `","reason":"x","acknowledged_at":"2026-11-04","objects":` + objects + `}]`
	}
	sig := func(doc string) string { return docPath(testID, doc) + ".sig" }
	for name, bad := range map[string]string{
		"not an array":            `{}`,
		"null":                    `null`,
		"another member":          `[{"proposal_id":"` + testID + `","document":"results","reason":"x","acknowledged_at":"2026-11-04","objects":[` + obj(sig("results"), sigHash) + `],"by":"y"}]`,
		"no reason":               `[{"proposal_id":"` + testID + `","document":"results","reason":"","acknowledged_at":"2026-11-04","objects":[` + obj(sig("results"), sigHash) + `]}]`,
		"a bad date":              `[{"proposal_id":"` + testID + `","document":"results","reason":"x","acknowledged_at":"4 Nov","objects":[` + obj(sig("results"), sigHash) + `]}]`,
		"a bad document":          e("rows", `[`+obj(docPath(testID, "rows"), sigHash)+`]`),
		"twice":                   `[` + entry(obj(sigKey, sigHash)) + `,` + entry(obj(sigKey, sigHash)) + `]`,
		"trailing data":           `[] []`,
		"no objects":              e("extension-2", `[]`),
		"null objects":            e("extension-2", `null`),
		"objects missing":         `[{"proposal_id":"` + testID + `","document":"extension-2","reason":"x","acknowledged_at":"2026-11-04"}]`,
		"another proposal's key":  e("extension-2", `[`+obj("v1/p/01KC0000000000000000000002/extension-2.json.sig", sigHash)+`]`),
		"another document's key":  e("extension-2", `[`+obj(sig("extension-1"), sigHash)+`]`),
		"the rows' key":           e("results", `[`+obj("v1/p/"+testID+"/rows.json", sigHash)+`]`),
		"a key twice":             e("extension-2", `[`+obj(sigKey, sigHash)+`,`+obj(sigKey, sigHash)+`]`),
		"a short hash":            e("extension-2", `[`+obj(sigKey, sigHash[:62])+`]`),
		"an uppercase hash":       e("extension-2", `[`+obj(sigKey, strings.ToUpper(sigHash))+`]`),
		"a base64 hash":           e("extension-2", `[{"key":"`+sigKey+`","sha256":"`+base64.StdEncoding.EncodeToString(sha(f.Extension.Sig))+`"}]`),
		"an object's other field": e("extension-2", `[{"key":"`+sigKey+`","sha256":`+h+`,"size":1}]`),
	} {
		if _, err := ParseAcknowledged([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if acks, err := ParseAcknowledged([]byte("[]\n")); err != nil || len(acks) != 0 {
		t.Fatalf("the empty list: %v", err)
	}
}
