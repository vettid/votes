package site

import (
	"bytes"
	"context"
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
	return Check(context.Background(), fetcher(objs), s.Anchors, s.SiteKey, id, f.closed())
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
	if rep, err := Check(context.Background(), fetcher(o), s.Anchors, s.SiteKey, testID, later); err != nil || len(rep.Listing) != 0 {
		t.Fatalf("an index past its window: %v %v", rep, err)
	}
	if rep, err := check(t, f, o, testID); err != nil || !slices.Contains(rep.Listing, "index: missing") {
		t.Fatalf("an index missing an entry in its window: %v %v", rep, err)
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
