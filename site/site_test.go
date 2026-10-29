package site

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
)

// testdata/vote.json is a small vote (a proposal, one extension, the
// results and rows) whose documents were anchored in Sigstore's staging
// log, with the service's fixed public test seed and its anchor key;
// testdata/staging_trusted_root.json is the staging trusted root they
// verify against. Real bundles, checked offline.
type fixture struct {
	ServiceSeed []byte `json:"service_seed"`
	AnchorKey   []byte `json:"anchor_key"`
	AnchorCert  []byte `json:"anchor_cert"`
	Rows        []byte `json:"rows"`
	Proposal    Upload `json:"proposal"`
	Extension   Upload `json:"extension-1"`
	Results     Upload `json:"results"`
}

const testID = "01KC0000000000000000000000"

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
	return &f
}

func siteKey() ed25519.PrivateKey {
	h := sha256.Sum256([]byte("votes site test key"))
	return ed25519.NewKeyFromSeed(h[:])
}

// newSite is the site with the fixture's service registered, at now.
func newSite(t *testing.T, f *fixture, now time.Time) (*Site, *MemStorage) {
	t.Helper()
	ik := ed25519.NewKeyFromSeed(f.ServiceSeed).Public().(ed25519.PublicKey)
	list := &ServiceList{V: 1, Version: 1, Previous: make([]byte, 32), Services: []Service{{
		ServiceID: ServiceID(ik), Name: "Test service", IKs: [][]byte{ik},
		AnchorKeys: []AnchorKey{{Key: f.AnchorKey, AnchorCert: f.AnchorCert, IK: ik}}}}}
	st := &MemStorage{}
	putList(t, st, list, siteKey())
	rootJSON, err := os.ReadFile("testdata/staging_trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		t.Fatal(err)
	}
	return &Site{Store: st, Anchors: NewAnchorsWith(tr), SiteKey: siteKey().Public().(ed25519.PublicKey),
		Now: func() time.Time { return now }}, st
}

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
	st.Objects = map[string][]byte{"v1/services.json": b, "v1/services.json.sig": sig}
}

func post(t *testing.T, s *Site, name string, u *Upload) (int, string) {
	t.Helper()
	body, _ := json.Marshal(u)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/p/"+testID+"/"+name, bytes.NewReader(body)))
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m["error"]
}

func index(t *testing.T, st *MemStorage) []IndexEntry {
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
	p, _ := vote.ParseProposal(f.Proposal.Doc)
	e, _ := vote.ParseExtension(f.Extension.Doc)
	s, st := newSite(t, f, time.Now())

	if code, _ := post(t, s, "proposal", &f.Proposal); code != 201 {
		t.Fatalf("proposal: %d", code)
	}
	if code, _ := post(t, s, "proposal", &f.Proposal); code != 200 {
		t.Fatalf("proposal again: %d", code)
	}
	if es := index(t, st); len(es) != 1 || es[0].ProposalID != testID || es[0].ClosesAt != p.ClosesAt {
		t.Fatalf("index %+v", es)
	}
	for _, path := range []string{"proposal.json", "proposal.json.sig", "proposal.json.sigstore.json"} {
		if st.Objects["v1/p/"+testID+"/"+path] == nil {
			t.Fatalf("%s not published", path)
		}
	}
	if code, why := post(t, s, "extension-2", &f.Extension); code != 422 {
		t.Fatalf("extension 2 first: %d %s", code, why)
	}
	if code, why := post(t, s, "results", &f.Results); code != 422 || why != "bad_document" {
		t.Fatalf("results without the extension: %d %s", code, why)
	}
	if code, why := post(t, s, "extension-1", &f.Extension); code != 201 {
		t.Fatalf("extension: %d %s", code, why)
	}
	if es := index(t, st); es[0].ClosesAt != e.ClosesAt || es[0].Extended != 1 {
		t.Fatalf("index after the extension %+v", es)
	}
	if code, why := post(t, s, "results", &f.Results); code != 422 || why != "too_early" {
		t.Fatalf("results before the close: %d %s", code, why)
	}
	s.Now = func() time.Time { return time.Unix(e.ClosesAt+60, 0) }
	if code, why := post(t, s, "results", &f.Results); code != 201 {
		t.Fatalf("results: %d %s", code, why)
	}
	if es := index(t, st); !es[0].Published {
		t.Fatal("index: not published")
	}
	if !bytes.Equal(st.Objects["v1/p/"+testID+"/rows.json"], f.Rows) {
		t.Fatal("rows not published")
	}
	archive := st.Objects[archivePath(p.OpensAt)]
	if !bytes.Contains(archive, []byte(testID)) {
		t.Fatal("not in the archive")
	}
}

// Each check refuses what it should.
func TestRefusals(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, time.Now())
	mut := func(u Upload, fn func(*Upload)) *Upload {
		c := u
		c.Doc, c.Sig = bytes.Clone(u.Doc), bytes.Clone(u.Sig)
		fn(&c)
		return &c
	}

	cases := map[string]struct {
		u    *Upload
		code int
		why  string
	}{
		"a changed document": {mut(f.Proposal, func(u *Upload) { u.Doc = bytes.Replace(u.Doc, []byte("Site test vote"), []byte("Site test vots"), 1) }), 422, "bad_signature"},
		"a bad signature":    {mut(f.Proposal, func(u *Upload) { u.Sig[0] ^= 1 }), 422, "bad_signature"},
		"another bundle":     {mut(f.Proposal, func(u *Upload) { u.Bundle = f.Extension.Bundle }), 422, "bad_anchor"},
		"non-canonical":      {mut(f.Proposal, func(u *Upload) { u.Doc = append([]byte(" "), u.Doc...) }), 422, "bad_document"},
	}
	for name, c := range cases {
		if code, why := post(t, s, "proposal", c.u); code != c.code || why != c.why {
			t.Errorf("%s: %d %s", name, code, why)
		}
	}
	// A service that isn't on the list.
	other := &ServiceList{V: 1, Version: 2, Previous: make([]byte, 32), Services: []Service{}}
	putList(t, st, other, siteKey())
	if code, why := post(t, s, "proposal", &f.Proposal); code != 422 || why != "unknown_service" {
		t.Errorf("unregistered: %d %s", code, why)
	}
	// A list signed by another key: nothing is published.
	s2, st2 := newSite(t, f, time.Now())
	putList(t, st2, &ServiceList{V: 1, Version: 1, Previous: make([]byte, 32), Services: []Service{}}, ed25519.NewKeyFromSeed(make([]byte, 32)))
	if code, _ := post(t, s2, "proposal", &f.Proposal); code != 503 {
		t.Errorf("a forged list: %d", code)
	}
	// A different document already at the path: 409, never replaced.
	s3, st3 := newSite(t, f, time.Now())
	st3.Objects["v1/p/"+testID+"/proposal.json"] = []byte(`{"other":1}`)
	if code, why := post(t, s3, "proposal", &f.Proposal); code != 409 || why != "differs" {
		t.Errorf("another document there: %d %s", code, why)
	}
	// After the close, a proposal is too late.
	p, _ := vote.ParseProposal(f.Proposal.Doc)
	s4, _ := newSite(t, f, time.Unix(p.ClosesAt, 0))
	if code, why := post(t, s4, "proposal", &f.Proposal); code != 422 || why != "too_late" {
		t.Errorf("after the close: %d %s", code, why)
	}
	// An extension or results with no proposal.
	s5, _ := newSite(t, f, time.Now())
	if code, why := post(t, s5, "extension-1", &f.Extension); code != 422 || why != "unknown_proposal" {
		t.Errorf("extension first: %d %s", code, why)
	}
	// Bad requests.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/p/"+testID+"/proposal", bytes.NewReader([]byte(`{"doc":"AA==","extra":1}`))))
	if rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/p/"+testID+"/other", bytes.NewReader([]byte(`{}`))))
	if rec.Code != 404 {
		t.Errorf("unknown name: %d", rec.Code)
	}
}

// Changed results are refused even with a valid anchor of other bytes.
func TestResultsChecked(t *testing.T) {
	f := loadFixture(t)
	e, _ := vote.ParseExtension(f.Extension.Doc)
	s, _ := newSite(t, f, time.Now())
	post(t, s, "proposal", &f.Proposal)
	post(t, s, "extension-1", &f.Extension)
	s.Now = func() time.Time { return time.Unix(e.ClosesAt+60, 0) }
	bad := f.Results
	bad.Rows = bytes.Replace(f.Rows, []byte(`"choice_id":"yes"`), []byte(`"choice_id":"no"`), 1)
	if code, why := post(t, s, "results", &bad); code != 422 || why != "bad_document" {
		t.Fatalf("changed rows: %d %s", code, why)
	}
}
