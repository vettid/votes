package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
			http.NotFound(w, r) // the site's answer for a missing object
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	key := base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey))
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var out bytes.Buffer
	if ok, err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, key, p.ProposalID, nil, time.Now()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"unhandled": 0`)) {
		t.Fatalf("no unhandled in the report: %s", out.Bytes())
	}
	var rep report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Status != "counted" || len(rep.Hashes) != 4 || rep.Extensions != 1 || rep.Results == nil || rep.Results.Eligible != p.Eligible || len(rep.Anchored) != 3 ||
		len(rep.SkewSeconds) != 3 || rep.Mismatches != nil || rep.TrustedRoot != "file" {
		t.Fatalf("report %s", out.Bytes())
	}

	// -all: the service list's chain and every listed proposal. The list
	// was published before its copy was kept: a mismatch until it is.
	all := func() (allReport, bool, error) {
		t.Helper()
		var out bytes.Buffer
		ok, err := checkAll(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), httpModified(srv.URL, noRedirects()), anchors, key, "2026-10", nil, time.Now())
		var rep allReport
		if jerr := json.Unmarshal(out.Bytes(), &rep); jerr != nil {
			t.Fatalf("%v: %s", jerr, out.Bytes())
		}
		if rep.OK != ok {
			t.Fatalf("ok %v, report %v", ok, rep.OK)
		}
		return rep, ok, err
	}
	if rep, ok, err := all(); err != nil || ok || !slices.Equal(rep.Services.Mismatches, []string{"services/1: not published"}) {
		t.Fatalf("-all without the list's copy: %+v %v %v", rep, ok, err)
	}
	store.Objects["v1/services/1.json"], store.Objects["v1/services/1.json.sig"] = list, lsig
	rep2, ok, err := all()
	if err != nil || !ok || rep2.Services.Checked != 1 || len(rep2.Proposals) != 1 || !rep2.Proposals[0].OK ||
		rep2.Proposals[0].ProposalID != p.ProposalID || len(rep2.Months) == 0 {
		t.Fatalf("-all: %+v %v %v", rep2, ok, err)
	}
	// A listed proposal the site doesn't serve is an error, reported with
	// the rest.
	idx := store.Objects["v1/index.json"]
	var es []site.IndexEntry
	_ = json.Unmarshal(idx, &es)
	es = append(es, es[0])
	es[1].ProposalID = "01KC0000000000000000000009"
	store.Objects["v1/index.json"], _ = json.Marshal(es)
	if rep, ok, err := all(); !errors.Is(err, errChecksFailed) || ok || rep.Errors != 1 || len(rep.Proposals) != 2 || rep.Proposals[1].Error == "" {
		t.Fatalf("-all with an unpublished proposal: %+v %v %v", rep, ok, err)
	}
	store.Objects["v1/index.json"] = idx

	// Past the grace, a listing difference makes ok false.
	_ = json.Unmarshal(idx, &es)
	es[0].Extended = 0
	store.Objects["v1/index.json"], _ = json.Marshal(es)
	out.Reset()
	ok, err = checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, key, p.ProposalID, nil, time.Now())
	if err != nil || ok || !bytes.Contains(out.Bytes(), []byte(`"listing: index: extended"`)) {
		t.Fatalf("a stale listing: %v %v %s", ok, err, out.Bytes())
	}

	// The exit codes: 3 for a mismatch, 0 when all is well, 1 for a
	// failed check, 2 for a usage error.
	args := func(extra ...string) []string {
		return append([]string{"-site", srv.URL, "-sigstore", "staging", "-trusted-root", "../../site/testdata/staging_trusted_root.json"}, extra...)
	}
	code := func(a []string) int {
		var stdout, stderr bytes.Buffer
		return runCheck(context.Background(), a, &stdout, &stderr)
	}
	if c := code(args("-site-key", key, p.ProposalID)); c != exitMismatch {
		t.Fatalf("a mismatch: exit %d", c)
	}
	store.Objects["v1/index.json"] = idx
	for _, c := range []struct {
		args []string
		want int
	}{
		{args("-site-key", key, p.ProposalID), exitOK},
		{args("-site-key", key, "-all"), exitOK},
		{args("-site-key", other, p.ProposalID), exitFailed},
		{args("-site-key", other, "-all"), exitFailed},
		{args("-site-key", key), exitUsage},
		{args("-site-key", key, "-all", p.ProposalID), exitUsage},
		{args("-site-key", key, "-bogus"), exitUsage},
	} {
		if got := code(c.args); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args[6:], got, c.want)
		}
	}

	// An index that doesn't parse: the report is still written, naming it,
	// with the proposals the archive lists.
	store.Objects["v1/index.json"] = []byte("not json")
	if rep, ok, err := all(); !errors.Is(err, errChecksFailed) || ok || len(rep.Lists) != 1 || len(rep.Proposals) != 1 {
		t.Fatalf("an unreadable index: %+v %v %v", rep, ok, err)
	}
	store.Objects["v1/index.json"] = idx

	// -acknowledged: a partial upload on the list leaves ok true; one not
	// on it is a mismatch, and so is an entry that matches no partial.
	dir := t.TempDir()
	ackFile := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	entry := func(doc string) string {
		return `{"proposal_id":"` + p.ProposalID + `","document":"` + doc + `","reason":"an upload interrupted after the close","acknowledged_at":"2026-11-04"}`
	}
	ext2 := "v1/p/" + p.ProposalID + "/extension-2.json.sig"
	store.Objects[ext2] = f.Extension.Sig
	for _, c := range []struct {
		name, body string
		all        bool
		want       int
	}{
		{"an unlisted partial", `[]`, false, exitMismatch},
		{"an unlisted partial, -all", `[]`, true, exitMismatch},
		{"an acknowledged partial", "[" + entry("extension-2") + "]", false, exitOK},
		{"an acknowledged partial, -all", "[" + entry("extension-2") + "]", true, exitOK},
		{"a stale entry", "[" + entry("extension-2") + "," + entry("results") + "]", false, exitMismatch},
		{"a stale entry, -all", "[" + entry("extension-2") + "," + entry("results") + "]", true, exitMismatch},
		{"another proposal's, -all", "[" + entry("extension-2") + `,{"proposal_id":"01KC0000000000000000000009","document":"results","reason":"x","acknowledged_at":"2026-11-04"}]`, true, exitMismatch},
		{"not a list", `{}`, false, exitFailed},
	} {
		a := args("-site-key", key, "-acknowledged", ackFile("acks.json", c.body))
		if c.all {
			a = append(a, "-all")
		} else {
			a = append(a, p.ProposalID)
		}
		if got := code(a); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
	delete(store.Objects, ext2)

	// Another site key, or a changed row, fails the check.
	if _, err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, other, p.ProposalID, nil, time.Now()); err == nil {
		t.Fatal("checked under another site key")
	}
	rows := "v1/p/" + p.ProposalID + "/rows.json"
	store.Objects[rows] = append(bytes.Clone(store.Objects[rows]), '\n')
	if _, err := checkVote(context.Background(), &out, httpFetcher(srv.URL, noRedirects()), anchors, key, p.ProposalID, nil, time.Now()); err == nil {
		t.Fatal("checked with a changed row")
	}
}

// The fetcher takes a 404 as absent, refuses a redirect, a 403 and an
// error status.
func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ok":
			_, _ = w.Write([]byte("x"))
		case "/v1/gone":
			http.NotFound(w, r)
		case "/v1/denied":
			http.Error(w, "", http.StatusForbidden)
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
	for _, p := range []string{"v1/moved", "v1/denied", "v1/broken"} {
		if _, err := fetch(ctx, p); err == nil {
			t.Fatalf("%s: no error", p)
		}
	}
}

// A 5xx or a network error is retried; other answers aren't.
func TestHTTPFetcherRetries(t *testing.T) {
	saved := fetchRetries
	fetchRetries = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { fetchRetries = saved }()
	var mu sync.Mutex
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.Path]++
		n := calls[r.URL.Path]
		mu.Unlock()
		switch {
		case r.URL.Path == "/v1/flaky" && n < 3:
			http.Error(w, "", http.StatusBadGateway)
		case r.URL.Path == "/v1/flaky":
			_, _ = w.Write([]byte("x"))
		case r.URL.Path == "/v1/denied":
			http.Error(w, "", http.StatusForbidden)
		default:
			http.Error(w, "", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	fetch, ctx := httpFetcher(srv.URL, noRedirects()), context.Background()
	if b, err := fetch(ctx, "v1/flaky"); err != nil || string(b) != "x" || calls["/v1/flaky"] != 3 {
		t.Fatalf("flaky: %q %v after %d", b, err, calls["/v1/flaky"])
	}
	if _, err := fetch(ctx, "v1/down"); err == nil || calls["/v1/down"] != 3 {
		t.Fatalf("down: %v after %d", err, calls["/v1/down"])
	}
	if _, err := fetch(ctx, "v1/denied"); err == nil || calls["/v1/denied"] != 1 {
		t.Fatalf("denied: %v after %d", err, calls["/v1/denied"])
	}
	// A network error: a server that is gone.
	addr := srv.URL
	srv.Close()
	if _, err := httpFetcher(addr, noRedirects())(ctx, "v1/flaky"); err == nil {
		t.Fatal("a closed server answered")
	}
}

func TestHTTPModified(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/v1/services.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", at.Format(http.TimeFormat))
	}))
	defer srv.Close()
	modified := httpModified(srv.URL, noRedirects())
	if got, err := modified(context.Background(), "v1/services.json"); err != nil || !got.Equal(at) {
		t.Fatalf("modified: %v %v", got, err)
	}
	if _, err := modified(context.Background(), "v1/other"); err == nil {
		t.Fatal("a 404 gave a time")
	}
}
