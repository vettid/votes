package site

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
)

// testdata/vote.json is a small vote (a proposal, one extension, the
// results and rows) whose documents were anchored in Sigstore's staging
// log: the proposal and extension before the close, the results after
// the extended close. The service's identity key is from a fixed, public
// test seed. testdata/staging_trusted_root.json is the staging trusted
// root they verify against. Real bundles, checked offline; the tests set
// the site's clock from the vote's own times.
type fixture struct {
	ServiceSeed []byte `json:"service_seed"`
	AnchorKey   []byte `json:"anchor_key"`
	AnchorCert  []byte `json:"anchor_cert"`
	Rows        []byte `json:"rows"`
	Proposal    Upload `json:"proposal"`
	Extension   Upload `json:"extension-1"`
	Results     Upload `json:"results"`

	p *vote.Proposal
	e *vote.Extension
}

const testID = "01KC0000000000000000000001"

func loadFixture(t *testing.T) *fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/vote.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Results.Rows = f.Rows
	if f.p, err = vote.ParseProposal(f.Proposal.Doc); err != nil {
		t.Fatal(err)
	}
	if f.e, err = vote.ParseExtension(f.Extension.Doc); err != nil {
		t.Fatal(err)
	}
	return &f
}

func (f *fixture) ik() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(f.ServiceSeed).Public().(ed25519.PublicKey)
}

// Times of the vote: open, the original and extended closes, and when
// the results may go up.
func (f *fixture) during() time.Time    { return time.Unix(f.p.OpensAt+5, 0) }
func (f *fixture) closed() time.Time    { return time.Unix(f.e.ClosesAt, 0).Add(CollectMargin) }
func (f *fixture) closing() time.Time   { return time.Unix(f.e.ClosesAt+30, 0) }
func (f *fixture) pastFirst() time.Time { return time.Unix(f.p.ClosesAt+5, 0) }

func siteKey() ed25519.PrivateKey {
	h := sha256.Sum256([]byte("votes site test key"))
	return ed25519.NewKeyFromSeed(h[:])
}

func (f *fixture) list() *ServiceList {
	ik := f.ik()
	return &ServiceList{V: 1, Version: 1, Previous: make([]byte, 32), Services: []Service{{
		ServiceID: ServiceID(ik), Name: "Test service", IKs: [][]byte{ik},
		AnchorKeys: []AnchorKey{{Key: f.AnchorKey, AnchorCert: f.AnchorCert, IK: ik}}}}}
}

// failingStore is MemStorage whose next index writes fail.
type failingStore struct {
	*MemStorage
	failIndex int
}

func (s *failingStore) PutIf(ctx context.Context, path string, data []byte, ct, tag string) error {
	if s.failIndex > 0 {
		s.failIndex--
		return context.DeadlineExceeded
	}
	return s.MemStorage.PutIf(ctx, path, data, ct, tag)
}

// newSite is the site with the fixture's service registered, at now.
func newSite(t *testing.T, f *fixture, now time.Time) (*Site, *failingStore) {
	t.Helper()
	st := &failingStore{MemStorage: &MemStorage{}}
	putList(t, st.MemStorage, f.list(), siteKey())
	rootJSON, err := os.ReadFile("testdata/staging_trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	return &Site{Store: st, Anchors: NewAnchorsWith(tr), SiteKey: siteKey().Public().(ed25519.PublicKey),
		Now: func() time.Time { return clock }}, st
}

func at(s *Site, t time.Time) { s.Now = func() time.Time { return t } }

func putList(t *testing.T, st *MemStorage, l *ServiceList, key ed25519.PrivateKey) {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	if b, err = vote.Canonicalize(b); err != nil {
		t.Fatal(err)
	}
	sig, _ := suite.Sign(key, vote.LabelServiceList, sha(b))
	if st.Objects == nil {
		st.Objects = map[string][]byte{}
	}
	st.Objects["v1/services.json"], st.Objects["v1/services.json.sig"] = b, sig
}

func post(t *testing.T, s *Site, name string, u *Upload) (int, string) {
	t.Helper()
	body, _ := json.Marshal(u)
	return postRaw(t, s, name, body)
}

func postRaw(t *testing.T, s *Site, name string, body []byte) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/p/"+testID+"/"+name, bytes.NewReader(body)))
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m["error"]
}

func want(t *testing.T, what string, code int, why string, wantCode int, wantWhy string) {
	t.Helper()
	if code != wantCode || why != wantWhy {
		t.Errorf("%s: %d %q, want %d %q", what, code, why, wantCode, wantWhy)
	}
}

func index(t *testing.T, st *failingStore) []IndexEntry {
	t.Helper()
	var es []IndexEntry
	if err := json.Unmarshal(st.Objects[indexPath], &es); err != nil {
		t.Fatal(err)
	}
	return es
}

// A whole vote goes up in order and is published once.
func TestVote(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())

	code, why := post(t, s, "proposal", &f.Proposal)
	want(t, "proposal", code, why, 201, "")
	code, why = post(t, s, "proposal", &f.Proposal)
	want(t, "proposal again", code, why, 200, "")
	if es := index(t, st); len(es) != 1 || es[0].ProposalID != testID || es[0].ClosesAt != f.p.ClosesAt {
		t.Fatalf("index %+v", es)
	}
	for _, path := range []string{"proposal.json", "proposal.json.sig", "proposal.json.sigstore.json"} {
		if st.Objects["v1/p/"+testID+"/"+path] == nil {
			t.Fatalf("%s not published", path)
		}
	}
	code, why = post(t, s, "extension-2", &f.Extension)
	want(t, "the extension under another number", code, why, 422, "bad_document")
	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "extension", code, why, 201, "")
	if es := index(t, st); es[0].ClosesAt != f.e.ClosesAt || es[0].Extended != 1 {
		t.Fatalf("index after the extension %+v", es)
	}
	at(s, f.closing())
	code, why = post(t, s, "results", &f.Results)
	want(t, "results before the margin", code, why, 422, "too_early")
	at(s, f.closed())
	code, why = post(t, s, "results", &f.Results)
	want(t, "results", code, why, 201, "")
	code, why = post(t, s, "results", &f.Results)
	want(t, "results again", code, why, 200, "")
	if es := index(t, st); !es[0].Published {
		t.Fatal("index: not published")
	}
	if !bytes.Equal(st.Objects["v1/p/"+testID+"/rows.json"], f.Rows) {
		t.Fatal("rows not published")
	}
	if !bytes.Contains(st.Objects[archivePath(f.p.OpensAt)], []byte(testID)) {
		t.Fatal("not in the archive")
	}
	// A retry of the proposal after the close is still the same document.
	code, why = post(t, s, "proposal", &f.Proposal)
	want(t, "proposal again after the close", code, why, 200, "")
}

func mut(u Upload, fn func(*Upload)) *Upload {
	c := u
	c.Doc, c.Sig, c.Bundle = bytes.Clone(u.Doc), bytes.Clone(u.Sig), bytes.Clone(u.Bundle)
	fn(&c)
	return &c
}

// Each check on a proposal refuses what it should.
func TestProposalRefusals(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())
	for name, c := range map[string]struct {
		u    *Upload
		code int
		why  string
	}{
		"a changed document": {mut(f.Proposal, func(u *Upload) { u.Doc = bytes.Replace(u.Doc, []byte("Site test vote"), []byte("Site test vots"), 1) }), 422, "bad_signature"},
		"a bad signature":    {mut(f.Proposal, func(u *Upload) { u.Sig[0] ^= 1 }), 422, "bad_signature"},
		"another bundle":     {mut(f.Proposal, func(u *Upload) { u.Bundle = f.Extension.Bundle }), 422, "bad_anchor"},
		"another profile":    {mut(f.Proposal, func(u *Upload) { u.Bundle = bytes.Replace(u.Bundle, []byte("bundle.v0.3"), []byte("bundle.v0.2"), 1) }), 422, "bad_anchor"},
		"non-canonical":      {mut(f.Proposal, func(u *Upload) { u.Doc = append([]byte(" "), u.Doc...) }), 422, "bad_document"},
		"too large":          {mut(f.Proposal, func(u *Upload) { u.Doc = bytes.Repeat([]byte("x"), maxProposal+1) }), 413, "too_large"},
	} {
		code, why := post(t, s, "proposal", c.u)
		want(t, name, code, why, c.code, c.why)
	}
	if len(st.Objects) != 2 {
		t.Fatalf("refused uploads left %d objects", len(st.Objects))
	}

	// Unknown fields, and a missing signature, are bad requests.
	body, _ := json.Marshal(&f.Proposal)
	extra := append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"extra":1}`)...)
	code, why := postRaw(t, s, "proposal", extra)
	want(t, "an unknown field", code, why, 400, "bad_request")
	code, why = post(t, s, "proposal", mut(f.Proposal, func(u *Upload) { u.Sig = nil }))
	want(t, "no signature", code, why, 400, "bad_request")
	code, why = postRaw(t, s, "other", body)
	want(t, "an unknown name", code, why, 404, "not_found")

	// A service that isn't on the list.
	putList(t, st.MemStorage, &ServiceList{V: 1, Version: 2, Previous: make([]byte, 32), Services: []Service{}}, siteKey())
	code, why = post(t, s, "proposal", &f.Proposal)
	want(t, "unregistered", code, why, 422, "unknown_service")

	// The service listed with another anchor key: the bundle's key isn't
	// one of the service's.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	l := f.list()
	cert, _ := suite.Sign(ed25519.NewKeyFromSeed(f.ServiceSeed), vote.LabelAnchorKey, sha(spki))
	l.Services[0].AnchorKeys = []AnchorKey{{Key: spki, AnchorCert: cert, IK: f.ik()}}
	putList(t, st.MemStorage, l, siteKey())
	code, why = post(t, s, "proposal", &f.Proposal)
	want(t, "an unlisted anchor key", code, why, 422, "bad_anchor")

	// A list with an anchor key its service didn't certify, or signed by
	// another key: nothing is published.
	l = f.list()
	l.Services[0].AnchorKeys[0].AnchorCert = bytes.Clone(f.AnchorCert)
	l.Services[0].AnchorKeys[0].AnchorCert[0] ^= 1
	putList(t, st.MemStorage, l, siteKey())
	code, _ = post(t, s, "proposal", &f.Proposal)
	want(t, "a bad anchor certificate", code, "", 503, "")
	putList(t, st.MemStorage, f.list(), ed25519.NewKeyFromSeed(make([]byte, 32)))
	code, _ = post(t, s, "proposal", &f.Proposal)
	want(t, "a forged list", code, "", 503, "")

	// After the close, a new proposal is too late.
	s2, _ := newSite(t, f, time.Unix(f.p.ClosesAt, 0))
	code, why = post(t, s2, "proposal", &f.Proposal)
	want(t, "after the close", code, why, 422, "too_late")
}

// What an earlier upload left at a path must belong to this document.
func TestWriteOnce(t *testing.T) {
	f := loadFixture(t)
	base := "v1/p/" + testID + "/proposal.json"
	for name, c := range map[string]struct {
		path string
		data []byte
	}{
		"another document":          {base, []byte(`{"other":1}`)},
		"another document's sig":    {base + ".sig", bytes.Repeat([]byte{1}, 64)},
		"another document's bundle": {base + ".sigstore.json", f.Extension.Bundle},
	} {
		s, st := newSite(t, f, f.during())
		st.Objects[c.path] = c.data
		code, why := post(t, s, "proposal", &f.Proposal)
		want(t, name, code, why, 409, "differs")
	}
	// A matching remainder of a failed upload is filled in.
	s, st := newSite(t, f, f.during())
	st.Objects[base+".sig"] = f.Proposal.Sig
	code, why := post(t, s, "proposal", &f.Proposal)
	want(t, "a matching signature already there", code, why, 201, "")
}

// An index write that fails is finished by the retry.
func TestIndexRetry(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())
	st.failIndex = 1
	code, _ := post(t, s, "proposal", &f.Proposal)
	want(t, "the index fails", code, "", 503, "")
	if st.Objects["v1/p/"+testID+"/proposal.json"] == nil {
		t.Fatal("the document wasn't written")
	}
	at(s, f.pastFirst()) // even after the close, the same proposal is accepted
	code, why := post(t, s, "proposal", &f.Proposal)
	want(t, "the retry", code, why, 200, "")
	if es := index(t, st); len(es) != 1 {
		t.Fatalf("index %+v", es)
	}
}

// Extensions: in order, before the close they extend, never after results.
func TestExtensionRefusals(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())
	code, why := post(t, s, "extension-1", &f.Extension)
	want(t, "no proposal", code, why, 422, "unknown_proposal")
	post(t, s, "proposal", &f.Proposal)

	at(s, f.pastFirst())
	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "after the close it extends", code, why, 422, "too_late")

	at(s, f.during())
	st.Objects["v1/p/"+testID+"/results.json"] = []byte(`{}`)
	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "after the results", code, why, 422, "too_late")
	delete(st.Objects, "v1/p/"+testID+"/results.json")

	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "in time", code, why, 201, "")
	at(s, f.closed())
	code, why = post(t, s, "extension-1", &f.Extension)
	want(t, "the same extension again, later", code, why, 200, "")
}

// Results: after the final close, with exactly the published extensions,
// and passing the observer's check; the check is reached.
func TestResultsRefusals(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	post(t, s, "proposal", &f.Proposal)
	at(s, f.closed())
	code, why := post(t, s, "results", &f.Results)
	want(t, "results naming an unpublished extension", code, why, 422, "bad_document")

	at(s, f.during())
	post(t, s, "extension-1", &f.Extension)
	at(s, f.closed())

	// The same rows with a changed tally, re-signed by the service: the
	// observer's check refuses it on the tally.
	var res map[string]any
	_ = json.Unmarshal(f.Results.Doc, &res)
	res["tally"].(map[string]any)["yes"] = 2
	doc, _ := json.Marshal(res)
	doc, _ = vote.Canonicalize(doc)
	m, _ := vote.DocSigMsg(sha(f.Proposal.Doc), doc)
	sig, _ := suite.Sign(ed25519.NewKeyFromSeed(f.ServiceSeed), vote.LabelResults, m)
	if _, _, err := vote.Check(f.ik(), doc, sig, f.Rows); err == nil || !strings.Contains(err.Error(), "tally") {
		t.Fatalf("the changed tally isn't what Check catches: %v", err)
	}
	code, why = post(t, s, "results", mut(f.Results, func(u *Upload) { u.Doc, u.Sig = doc, sig }))
	want(t, "a changed tally", code, why, 422, "bad_document")

	code, why = post(t, s, "results", mut(f.Results, func(u *Upload) {
		u.Rows = bytes.Replace(f.Rows, []byte(`"choice_id":"yes"`), []byte(`"choice_id":"no"`), 1)
	}))
	want(t, "changed rows", code, why, 422, "bad_document")
	code, why = post(t, s, "results", mut(f.Results, func(u *Upload) { u.Rows = nil }))
	want(t, "no rows", code, why, 400, "bad_request")
	code, why = post(t, s, "results", &f.Results)
	want(t, "the real results", code, why, 201, "")
}
