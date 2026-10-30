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
	res, err := vote.ParseResults(f.Results.Doc)
	if err != nil {
		t.Fatal(err)
	}
	if es := index(t, st); !es[0].Published || es[0].Unhandled == nil || *es[0].Unhandled != res.Counts.Unhandled {
		t.Fatal("index: not published, or without the results' unhandled")
	}
	if !bytes.Contains(st.Objects[archivePath(f.p.OpensAt)], []byte(`"unhandled":`)) {
		t.Fatal("archive: without unhandled")
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

// Extension n waits for n−1; numbers past 24 aren't routes.
func TestExtensionOrder(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	post(t, s, "proposal", &f.Proposal)
	doc, err := vote.EncodeExtension(&vote.Extension{V: 1, ProposalID: testID, N: 2, ClosesAt: f.e.ClosesAt + 3600, Outage: f.e.Outage})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := vote.DocSigMsg(sha(f.Proposal.Doc), doc)
	sig, _ := suite.Sign(ed25519.NewKeyFromSeed(f.ServiceSeed), vote.LabelExtended, m)
	code, why := post(t, s, "extension-2", &Upload{Doc: doc, Sig: sig, Bundle: f.Extension.Bundle})
	want(t, "extension 2 before 1", code, why, 422, "out_of_order")
	code, why = post(t, s, "extension-25", &f.Extension)
	want(t, "extension 25", code, why, 404, "not_found")
	code, why = post(t, s, "extension-1", mut(f.Extension, func(u *Upload) { u.Rows = []byte("x") }))
	want(t, "rows with an extension", code, why, 400, "bad_request")
}

// An extension whose index update failed is indexed by its retry.
func TestExtensionIndexRetry(t *testing.T) {
	f := loadFixture(t)
	s, st := newSite(t, f, f.during())
	post(t, s, "proposal", &f.Proposal)
	st.failIndex = 1
	code, _ := post(t, s, "extension-1", &f.Extension)
	want(t, "the index fails", code, "", 503, "")
	code, why := post(t, s, "extension-1", &f.Extension)
	want(t, "the retry", code, why, 200, "")
	if es := index(t, st); es[0].Extended != 1 || es[0].ClosesAt != f.e.ClosesAt {
		t.Fatalf("index %+v", es)
	}
}

// Bundles outside the protocol's profile are refused before Sigstore's
// verifier sees them.
func TestBundleProfile(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	edit := func(fn func(map[string]any)) json.RawMessage {
		var b map[string]any
		_ = json.Unmarshal(f.Proposal.Bundle, &b)
		fn(b)
		out, _ := json.Marshal(b)
		return out
	}
	vm := func(b map[string]any) map[string]any { return b["verificationMaterial"].(map[string]any) }
	for name, bundle := range map[string]json.RawMessage{
		"two log entries": edit(func(b map[string]any) {
			e := vm(b)["tlogEntries"].([]any)
			vm(b)["tlogEntries"] = append(e, e[0])
		}),
		"two timestamps": edit(func(b map[string]any) {
			td := vm(b)["timestampVerificationData"].(map[string]any)
			ts := td["rfc3161Timestamps"].([]any)
			td["rfc3161Timestamps"] = append(ts, ts[0])
		}),
		"another digest": edit(func(b map[string]any) {
			b["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_384"
		}),
		"a DSSE envelope": edit(func(b map[string]any) { b["dsseEnvelope"] = map[string]any{"payload": "e30="} }),
		"no public key":   edit(func(b map[string]any) { delete(vm(b), "publicKey") }),
	} {
		code, why := post(t, s, "proposal", mut(f.Proposal, func(u *Upload) { u.Bundle = bundle }))
		want(t, name, code, why, 422, "bad_anchor")
	}
}

// The service list is parsed in its exact form only.
func TestServiceListStrict(t *testing.T) {
	f := loadFixture(t)
	sign := func(b []byte) []byte { s, _ := suite.Sign(siteKey(), vote.LabelServiceList, sha(b)); return s }
	pub := siteKey().Public().(ed25519.PublicKey)
	l := f.list()
	good, _ := json.Marshal(l)
	good, _ = vote.Canonicalize(good)
	if _, err := ParseServiceList(good, sign(good), pub); err != nil {
		t.Fatal(err)
	}
	twice := f.list()
	twice.Services = append(twice.Services, twice.Services[0])
	dup, _ := json.Marshal(twice)
	dup, _ = vote.Canonicalize(dup)
	upper := bytes.Replace(good, []byte(`"services"`), []byte(`"Services"`), 1)
	upper, _ = vote.Canonicalize(upper)
	nl := f.list()
	nl.Services[0].AnchorKeys = nil // encodes as null
	null, _ := json.Marshal(nl)
	null, _ = vote.Canonicalize(null)
	if !bytes.Contains(null, []byte(`"anchor_keys":null`)) {
		t.Fatal("the test list has no null")
	}
	for name, b := range map[string][]byte{"a service twice": dup, "a name in another case": upper, "null arrays": null} {
		if _, err := ParseServiceList(b, sign(b), pub); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The service list's bounds (BALLOT-PROTOCOL §3.3).
func TestServiceListBounds(t *testing.T) {
	f := loadFixture(t)
	pub := siteKey().Public().(ed25519.PublicKey)
	parse := func(l *ServiceList) error {
		b, _ := json.Marshal(l)
		b, _ = vote.Canonicalize(b)
		s, _ := suite.Sign(siteKey(), vote.LabelServiceList, sha(b))
		_, err := ParseServiceList(b, s, pub)
		return err
	}
	ik := func(i int) []byte { k := bytes.Repeat([]byte{byte(i)}, 32); k[0] = 0xee; return k }
	services := func(n int) func(*ServiceList) {
		return func(l *ServiceList) {
			for i := len(l.Services); i < n; i++ {
				l.Services = append(l.Services, Service{ServiceID: ServiceID(ik(i)), Name: "S", IKs: [][]byte{ik(i)}, AnchorKeys: []AnchorKey{}})
			}
		}
	}
	iks := func(n int) func(*ServiceList) {
		return func(l *ServiceList) {
			for i := len(l.Services[0].IKs); i < n; i++ {
				l.Services[0].IKs = append(l.Services[0].IKs, ik(100+i))
			}
		}
	}
	anchors := func(n int) func(*ServiceList) {
		return func(l *ServiceList) {
			for len(l.Services[0].AnchorKeys) < n {
				l.Services[0].AnchorKeys = append(l.Services[0].AnchorKeys, l.Services[0].AnchorKeys[0])
			}
		}
	}
	name := func(s string) func(*ServiceList) { return func(l *ServiceList) { l.Services[0].Name = s } }
	for what, c := range map[string]struct {
		f   func(*ServiceList)
		why string // in the refusal; "" for accepted
	}{
		"64 services":      {services(MaxServices), ""},
		"65 services":      {services(MaxServices + 1), "too many services"},
		"16 identity keys": {iks(MaxServiceKeys), ""},
		"17 identity keys": {iks(MaxServiceKeys + 1), "too many keys"},
		"16 anchor keys":   {anchors(MaxServiceKeys), ""},
		"17 anchor keys":   {anchors(MaxServiceKeys + 1), "too many keys"},
		"a 100-byte name":  {name(strings.Repeat("é", 50)), ""},
		"a 101-byte name":  {name(strings.Repeat("é", 50) + "x"), "name"},
		"an empty name":    {name(""), "name"},
	} {
		l := f.list()
		c.f(l)
		err := parse(l)
		if c.why == "" && err != nil || c.why != "" && (err == nil || !strings.Contains(err.Error(), c.why)) {
			t.Errorf("%s: %v", what, err)
		}
	}
	// At the size limit the list gets past the size check (to fail on its
	// signature); one byte over, it doesn't.
	if _, err := ParseServiceList(make([]byte, MaxServiceList), nil, pub); err == nil || strings.Contains(err.Error(), "too large") {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := ParseServiceList(make([]byte, MaxServiceList+1), nil, pub); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized: %v", err)
	}
}

// A new service list must extend the published one.
func TestExtends(t *testing.T) {
	f := loadFixture(t)
	prev := f.list()
	prevData, _ := json.Marshal(prev)
	prevData, _ = vote.Canonicalize(prevData)
	next := f.list()
	next.Version, next.Previous = 2, sha(prevData)
	next.Services = append(next.Services, Service{ServiceID: ServiceID(bytes.Repeat([]byte{7}, 32)), Name: "Another",
		IKs: [][]byte{bytes.Repeat([]byte{7}, 32)}, AnchorKeys: []AnchorKey{}})
	if err := Extends(prev, prevData, next); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ServiceList){
		"the same version":    func(l *ServiceList) { l.Version = 1 },
		"another previous":    func(l *ServiceList) { l.Previous = make([]byte, 32) },
		"a dropped service":   func(l *ServiceList) { l.Services = l.Services[1:] },
		"a lost anchor key":   func(l *ServiceList) { l.Services[0].AnchorKeys = []AnchorKey{} },
		"a lost identity key": func(l *ServiceList) { l.Services[0].IKs = [][]byte{bytes.Repeat([]byte{8}, 32)} },
	} {
		n := f.list()
		n.Version, n.Previous = 2, sha(prevData)
		mutate(n)
		if Extends(prev, prevData, n) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
