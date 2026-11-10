package site

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"
)

// prepare runs Prepare on an upload's parts, without its bundle.
func prepare(t *testing.T, s *Site, name string, u *Upload) (Prepared, string) {
	t.Helper()
	p, err := s.Prepare(context.Background(), testID, name, u.Doc, u.Sig, u.Rows)
	var rf *Refusal
	switch {
	case errors.As(err, &rf):
		return p, rf.Code
	case err != nil:
		t.Fatalf("%s: %v", name, err)
	}
	return p, ""
}

// Prepare runs the upload's checks without a bundle and writes nothing.
func TestPrepare(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())
	before := maps.Clone(st.Objects)
	check := func(what, name string, u *Upload, wantCode string, wantPublished bool) {
		t.Helper()
		p, code := prepare(t, s, name, u)
		if code != wantCode || code == "" && p.Published != wantPublished {
			t.Fatalf("%s: code %q published %v, want %q %v", what, code, p.Published, wantCode, wantPublished)
		}
		if !maps.EqualFunc(st.Objects, before, bytes.Equal) {
			t.Fatalf("%s: Prepare wrote to the store", what)
		}
	}
	check("the proposal", "proposal", &f.Proposal, "", false)
	check("an extension before its proposal", "extension-1", &f.Extension, "unknown_proposal", false)
	check("results before their proposal", "results", &f.Results, "unknown_proposal", false)
	check("another name", "extension-25", &f.Extension, "not_found", false)
	check("a bad signature", "proposal", mut(f.Proposal, func(u *Upload) { u.Sig[0] ^= 1 }), "bad_signature", false)
	check("non-canonical", "proposal", mut(f.Proposal, func(u *Upload) { u.Doc = append([]byte(" "), u.Doc...) }), "bad_document", false)
	check("too large", "proposal", mut(f.Proposal, func(u *Upload) { u.Doc = bytes.Repeat([]byte("x"), maxProposal+1) }), "too_large", false)
	check("rows on a proposal", "proposal", mut(f.Proposal, func(u *Upload) { u.Rows = []byte("[]") }), "bad_request", false)

	at(s, f.pastFirst())
	check("a proposal after its close", "proposal", &f.Proposal, "too_late", false)

	at(s, f.during())
	code, why := post(t, s, "proposal", &f.Proposal)
	want(t, "proposal", code, why, 201, "")
	before = maps.Clone(st.Objects)
	check("the published proposal", "proposal", &f.Proposal, "", true)
	check("the extension", "extension-1", &f.Extension, "", false)
	check("the extension out of order", "extension-2", &f.Extension, "bad_document", false)
	at(s, f.pastFirst())
	check("the extension after the close it extends", "extension-1", &f.Extension, "too_late", false)
	check("the published proposal after its close", "proposal", &f.Proposal, "", true)

	at(s, f.during())
	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "extension", code, why, 201, "")
	before = maps.Clone(st.Objects)
	at(s, f.pastFirst())
	check("the published extension after its close", "extension-1", &f.Extension, "", true)
	at(s, f.closing())
	check("results before collection ends", "results", &f.Results, "too_early", false)
	at(s, f.closed())
	check("results", "results", &f.Results, "", false)
	check("results without rows", "results", mut(f.Results, func(u *Upload) { u.Rows = nil }), "bad_request", false)

	// Other bytes at the slot: refused before any other check.
	st.Objects["v1/p/"+testID+"/results.json"] = []byte("{}")
	before = maps.Clone(st.Objects)
	check("other bytes at the slot", "results", &f.Results, "differs", false)
}
