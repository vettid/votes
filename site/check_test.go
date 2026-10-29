package site

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"
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
	return Check(context.Background(), fetcher(objs), s.Anchors, s.SiteKey, id)
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
