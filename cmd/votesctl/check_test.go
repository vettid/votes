package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/votes/site"
)

// The site's test vote (site/testdata/vote.json, anchored in Sigstore's
// staging log), published through the upload API and served over HTTP,
// checks with votesctl check; a changed file fails it.
func TestCheckCommand(t *testing.T) {
	raw, err := os.ReadFile("../../site/testdata/vote.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ServiceSeed []byte      `json:"service_seed"`
		AnchorKey   []byte      `json:"anchor_key"`
		AnchorCert  []byte      `json:"anchor_cert"`
		Rows        []byte      `json:"rows"`
		Proposal    site.Upload `json:"proposal"`
		Extension   site.Upload `json:"extension-1"`
		Results     site.Upload `json:"results"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Results.Rows = f.Rows
	p, _ := vote.ParseProposal(f.Proposal.Doc)
	e, _ := vote.ParseExtension(f.Extension.Doc)

	// The service list, signed by a site key from a fixed public seed.
	seed := sha256.Sum256([]byte("votesctl check test site key"))
	sk := ed25519.NewKeyFromSeed(seed[:])
	ik := ed25519.NewKeyFromSeed(f.ServiceSeed).Public().(ed25519.PublicKey)
	list, _ := json.Marshal(site.ServiceList{V: 1, Version: 1, Previous: make([]byte, 32), Services: []site.Service{{
		ServiceID: site.ServiceID(ik), Name: "Test service", IKs: [][]byte{ik},
		AnchorKeys: []site.AnchorKey{{Key: f.AnchorKey, AnchorCert: f.AnchorCert, IK: ik}}}}})
	list, _ = vote.Canonicalize(list)
	h := sha256.Sum256(list)
	lsig, _ := suite.Sign(sk, vote.LabelServiceList, h[:])
	store := &site.MemStorage{Objects: map[string][]byte{"v1/services.json": list, "v1/services.json.sig": lsig}}

	anchors, err := anchorsFor("", "../../site/testdata/staging_trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(p.OpensAt+5, 0)
	s := &site.Site{Store: store, Anchors: anchors, SiteKey: sk.Public().(ed25519.PublicKey), Now: func() time.Time { return clock }}
	for _, step := range []struct {
		name string
		u    *site.Upload
		at   time.Time
	}{{"proposal", &f.Proposal, clock}, {"extension-1", &f.Extension, clock},
		{"results", &f.Results, time.Unix(e.ClosesAt, 0).Add(site.CollectMargin)}} {
		clock = step.at
		body, _ := json.Marshal(step.u)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/p/"+p.ProposalID+"/"+step.name, bytes.NewReader(body)))
		if rec.Code != 201 {
			t.Fatalf("%s: %d %s", step.name, rec.Code, rec.Body)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := store.Objects[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.Error(w, "", http.StatusForbidden) // as CloudFront without LIST
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	key := base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey))
	var out bytes.Buffer
	if err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, key, p.ProposalID); err != nil {
		t.Fatal(err)
	}
	var rep report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Extensions != 1 || rep.Results == nil || rep.Results.Eligible != p.Eligible || len(rep.Anchored) != 3 {
		t.Fatalf("report %s", out.Bytes())
	}

	// Another site key, or a changed row, fails the check.
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, other, p.ProposalID); err == nil {
		t.Fatal("checked under another site key")
	}
	rows := "v1/p/" + p.ProposalID + "/rows.json"
	store.Objects[rows] = append(bytes.Clone(store.Objects[rows]), '\n')
	if err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, key, p.ProposalID); err == nil {
		t.Fatal("checked with a changed row")
	}
}

// The fetcher takes 403 and 404 as absent, refuses a redirect and an
// error status.
func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ok":
			_, _ = w.Write([]byte("x"))
		case "/v1/gone":
			http.NotFound(w, r)
		case "/v1/moved":
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		default:
			http.Error(w, "", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	fetch, ctx := httpFetcher(srv.URL+"/", noRedirects()), context.Background()
	if b, err := fetch(ctx, "v1/ok"); err != nil || string(b) != "x" {
		t.Fatalf("ok: %q %v", b, err)
	}
	if b, err := fetch(ctx, "v1/gone"); err != nil || b != nil {
		t.Fatalf("gone: %q %v", b, err)
	}
	for _, p := range []string{"v1/moved", "v1/broken"} {
		if _, err := fetch(ctx, p); err == nil {
			t.Fatalf("%s: no error", p)
		}
	}
}
