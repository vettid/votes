package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/vettid/votes/rekor"
	"github.com/vettid/votes/site"
)

// Exit codes of votesctl check.
const (
	exitOK       = 0 // every check held, and ok is true
	exitFailed   = 1 // a check failed (with -all, the report names each)
	exitUsage    = 2
	exitMismatch = 3 // the checks held, but ok is false: a mismatch
)

// runCheck is votesctl check with its arguments; it returns the exit code.
func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("site", "https://votes.vettid.org", "the site")
	key := fs.String("site-key", "", "the site's public key (base64), from its release config")
	instance := fs.String("sigstore", site.Production, "the Sigstore instance the votes are anchored in")
	rootFile := fs.String("trusted-root", "", "a Sigstore trusted root file, instead of the embedded one refreshed through TUF")
	all := fs.Bool("all", false, "check the service list's chain and every proposal the index and the archive list")
	since := fs.String("since", firstMonth, "with -all: the first archive month read (YYYY-MM)")
	ackFile := fs.String("acknowledged", "", "a file of acknowledged partial uploads (docs/VOTES-SITE.md §7)")
	var rf rekorFlags
	rf.register(fs)
	if fs.Parse(args) != nil || *all != (fs.NArg() == 0) || fs.NArg() > 1 {
		fmt.Fprintln(stderr, "usage: votesctl check [-all [-since YYYY-MM] [-rekor ...] | <proposal_id>] -site-key <base64> [-site <url>] [-sigstore production|staging] [-trusted-root <file>] [-acknowledged <file>]")
		return exitUsage
	}
	sinceSet := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "since" {
			sinceSet = true
		}
	})
	if err := rf.usage(*all, sinceSet); err != nil {
		fmt.Fprintln(stderr, "votesctl:", err)
		return exitUsage
	}
	var acks []site.Acknowledgement
	anchors, err := anchorsFor(*instance, *rootFile)
	if err == nil && *ackFile != "" {
		var b []byte
		if b, err = os.ReadFile(*ackFile); err == nil {
			acks, err = site.ParseAcknowledged(b)
		}
	}
	ok := false
	if err == nil {
		c := noRedirects()
		fetch := httpFetcher(*base, c)
		if *all {
			var rk *rekorStep
			if rf.on {
				rk = &rekorStep{flags: &rf, instance: *instance}
			}
			ok, err = checkAll(ctx, stdout, fetch, httpModified(*base, c), anchors, *key, *since, acks, time.Now(), rk)
		} else {
			ok, err = checkVote(ctx, stdout, fetch, httpModified(*base, c), anchors, *key, fs.Arg(0), acks, time.Now())
		}
	}
	var adm *errRekorAdmin
	switch {
	case errors.As(err, &adm):
		fmt.Fprintln(stderr, "votesctl:", err)
		return exitUsage
	case err != nil:
		fmt.Fprintln(stderr, "votesctl:", err)
		return exitFailed
	case !ok:
		fmt.Fprintln(stderr, "votesctl: mismatches: see the report")
		return exitMismatch
	}
	return exitOK
}

// firstMonth is the month the site's first proposal opened in: -all reads
// the archive from it.
const firstMonth = "2026-10"

// maxObject bounds one fetched object: the rows of a large vote are the
// biggest.
const maxObject = 16 << 20

// httpFetcher reads published objects from a site's base URL. It follows
// no redirect and takes only a 404 as not published: the site answers
// 404 for a missing object, so a 403 (WAF, access) is an error, not an
// absent document.
//
// A network error or a 5xx answer is retried after each of fetchRetries;
// any other answer is final.
func httpFetcher(base string, c *http.Client) site.Fetcher {
	base = strings.TrimRight(base, "/")
	return func(ctx context.Context, path string) ([]byte, error) {
		for i := 0; ; i++ {
			b, retry, err := fetchOnce(ctx, c, base, path)
			if err == nil || !retry || i == len(fetchRetries) {
				return b, err
			}
			select {
			case <-ctx.Done():
				return nil, err
			case <-time.After(fetchRetries[i]):
			}
		}
	}
}

// fetchRetries are the waits before each retry of a failed fetch.
var fetchRetries = []time.Duration{time.Second, 3 * time.Second}

// fetchOnce is one GET; retry says whether a failure may pass.
func fetchOnce(ctx context.Context, c *http.Client, base, path string) (b []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+path, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, resp.StatusCode >= 500, fmt.Errorf("%s: %s", path, resp.Status)
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, maxObject+1))
	if err != nil {
		return nil, true, err
	}
	if len(b) > maxObject {
		return nil, false, fmt.Errorf("%s: over %d bytes", path, maxObject)
	}
	return b, false, nil
}

// httpModified is an object's Last-Modified, from a HEAD request.
func httpModified(base string, c *http.Client) func(context.Context, string) (time.Time, error) {
	base = strings.TrimRight(base, "/")
	return func(ctx context.Context, path string) (time.Time, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/"+path, nil)
		if err != nil {
			return time.Time{}, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return time.Time{}, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return time.Time{}, fmt.Errorf("%s: %s", path, resp.Status)
		}
		return http.ParseTime(resp.Header.Get("Last-Modified"))
	}
}

func noRedirects() *http.Client {
	return &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// report is the check's output for one proposal. OK is false when it has
// mismatches, or (under -all) an error.
type report struct {
	OK          bool              `json:"ok"`
	Error       string            `json:"error,omitempty"` // -all: the check that failed
	TrustedRoot string            `json:"trusted_root,omitempty"`
	ProposalID  string            `json:"proposal_id"`
	ServiceID   string            `json:"service_id"`
	ServiceName string            `json:"service_name"`
	Title       string            `json:"title"`
	Eligible    int64             `json:"eligible"`
	OpensAt     int64             `json:"opens_at"`
	ClosesAt    int64             `json:"closes_at"`
	Extensions  int               `json:"extensions"`
	Anchored    map[string]string `json:"anchored"`
	// Status: open (before the close in force, plus the minute collection
	// takes), closed (after it, with no results published yet: the
	// service hasn't published them, or is withholding them), or counted.
	Status  string            `json:"status"`
	Results *results          `json:"results"` // null until counted
	Hashes  map[string]string `json:"hashes"`  // hex SHA-256, to compare with other readers
	Partial []string          `json:"partial,omitempty"`
	// Listing: where index.json or the month's archive differs from the
	// documents. Not a failed check: the lists are rewritten after a
	// document is published, and may lag behind an upload not finished;
	// past site.ListingGrace it is also in Mismatches.
	Listing []string `json:"listing,omitempty"`
	// SkewSeconds: each anchor's RFC 3161 time less its Rekor time.
	SkewSeconds map[string]int64 `json:"skew_seconds,omitempty"`
	// PartialObjects: each partial upload's served objects, by key and
	// hex SHA-256; an acknowledged list's entry names them as here.
	PartialObjects map[string][]site.Object `json:"partial_objects,omitempty"`
	// PartialPermanent: partial uploads the site can no longer complete.
	PartialPermanent []string `json:"partial_permanent,omitempty"`
	// Acknowledged: partial uploads on the acknowledged list.
	Acknowledged []string `json:"acknowledged,omitempty"`
	// Mismatches: what makes ok false (site.Report.Mismatches).
	Mismatches []string `json:"mismatches,omitempty"`
}

type results struct {
	Tally    map[string]int64 `json:"tally"`
	Eligible int64            `json:"eligible"`
	Ballots  int64            `json:"ballots"`
	Removed  int64            `json:"removed"`
	// Unhandled: messages of the voting window the count went ahead
	// without (BALLOT-PROTOCOL §7); each may have held a ballot.
	Unhandled int64 `json:"unhandled"`
}

func decodeSiteKey(siteKeyB64 string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(siteKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("-site-key: the site's public key, base64 of 32 bytes")
	}
	return key, nil
}

func writeReport(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// checkVote checks one proposal on a site and writes the report. ok is
// the report's: false when it has mismatches. err is a check that failed
// (no report is written).
func checkVote(ctx context.Context, w io.Writer, fetch site.Fetcher, modified func(context.Context, string) (time.Time, error),
	anchors *site.Anchors, siteKeyB64, id string,
	acks []site.Acknowledgement, now time.Time) (ok bool, err error) {
	key, err := decodeSiteKey(siteKeyB64)
	if err != nil {
		return false, err
	}
	rep, err := site.Check(ctx, fetch, anchors, key, id, now, modified)
	if err != nil {
		return false, err
	}
	rep.Acknowledge(acks)
	out := toReport(rep, now)
	out.TrustedRoot = anchors.RootSource()
	return out.OK, writeReport(w, out)
}

func toReport(rep *site.Report, now time.Time) report {
	out := report{OK: len(rep.Mismatches) == 0, ProposalID: rep.ProposalID, ServiceID: rep.ServiceID, ServiceName: rep.ServiceName,
		Title: rep.Title, Eligible: rep.Eligible, OpensAt: rep.OpensAt, ClosesAt: rep.ClosesAt,
		Extensions: rep.Extensions, Anchored: map[string]string{}, Hashes: map[string]string{}, Partial: rep.Partial,
		Listing: rep.Listing, PartialObjects: rep.PartialObjects, PartialPermanent: rep.PartialPermanent, Acknowledged: rep.Acknowledged, Mismatches: rep.Mismatches}
	if len(rep.Skew) > 0 {
		out.SkewSeconds = map[string]int64{}
		for name, d := range rep.Skew {
			out.SkewSeconds[name] = int64(d.Round(time.Second) / time.Second)
		}
	}
	for name, ts := range rep.Anchored {
		out.Anchored[name] = ts.UTC().Format(time.RFC3339)
	}
	for name, h := range rep.Hashes {
		out.Hashes[name] = hex.EncodeToString(h)
	}
	switch {
	case rep.Results != nil:
		out.Status = "counted"
	case now.Before(time.Unix(rep.ClosesAt, 0).Add(site.CollectMargin)):
		out.Status = "open"
	default:
		out.Status = "closed"
	}
	if r := rep.Results; r != nil {
		out.Results = &results{Tally: r.Tally, Eligible: r.Counts.Eligible, Ballots: r.Counts.Ballots, Removed: r.Counts.Removed,
			Unhandled: r.Counts.Unhandled}
	}
	return out
}

// allReport is check -all's output: the service list's chain and every
// proposal the index and the archive list.
type allReport struct {
	OK          bool        `json:"ok"`
	TrustedRoot string      `json:"trusted_root"`
	Errors      int         `json:"errors"`
	Services    servicesOut `json:"services"`
	Months      []string    `json:"months"` // the archive months read
	// Lists: the index or an archive month that couldn't be read (each
	// counted in Errors); their proposals may be missing below.
	Lists []string `json:"lists,omitempty"`
	// StaleAcknowledged: acknowledgements of proposals not checked here
	// (a proposal's own are in its mismatches).
	StaleAcknowledged []string `json:"stale_acknowledged,omitempty"`
	Proposals         []report `json:"proposals"`
	// Rekor: the Rekor check (-rekor; VOTES-SITE §7).
	Rekor *rekor.RunReport `json:"rekor,omitempty"`
}

// rekorStep is -rekor's part of checkAll; log, if set, replaces the
// Rekor client (tests).
type rekorStep struct {
	flags    *rekorFlags
	instance string
	log      rekor.Log
}

type servicesOut struct {
	Version    int64    `json:"version"`
	Checked    int      `json:"checked"`
	Mismatches []string `json:"mismatches,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// errChecksFailed is check -all's error when a check failed somewhere;
// the report, written first, names each.
var errChecksFailed = errors.New("checks failed: see the report's errors")

// checkAll checks the service list's chain and every proposal listed in
// index.json or in the archive's months from since (YYYY-MM) to now's,
// and the months of the index's entries, and writes one report. ok is
// false on any mismatch or error; err is errChecksFailed when a check
// failed, or the index or an archive month couldn't be read (the
// report is still written, naming each).
func checkAll(ctx context.Context, w io.Writer, fetch site.Fetcher, modified func(context.Context, string) (time.Time, error),
	anchors *site.Anchors, siteKeyB64, since string, acks []site.Acknowledgement, now time.Time, rk *rekorStep) (ok bool, err error) {
	col := newRekorCollect()
	key, err := decodeSiteKey(siteKeyB64)
	if err != nil {
		return false, err
	}
	start, err := time.Parse("2006-01", since)
	if err != nil {
		return false, errors.New("-since: a month, YYYY-MM")
	}
	out := allReport{TrustedRoot: anchors.RootSource(), Months: []string{}, Proposals: []report{}}
	if c, err := site.CheckServiceChain(ctx, fetch, key, now, modified); err != nil {
		out.Services.Error = err.Error()
		out.Errors++
	} else {
		out.Services = servicesOut{Version: c.Version, Checked: c.Checked, Mismatches: c.Mismatches}
		col.services(c)
	}

	// The proposals: the index's, then each month's archive.
	ids := map[string]bool{}
	months := map[string]bool{}
	list := func(path string) ([]site.IndexEntry, error) {
		b, err := fetch(ctx, path)
		if err != nil || b == nil {
			return nil, err
		}
		var es []site.IndexEntry
		if err := json.Unmarshal(b, &es); err != nil {
			return nil, fmt.Errorf("%s: not a list of entries", path)
		}
		return es, nil
	}
	listFailed := func(err error) {
		out.Lists = append(out.Lists, err.Error())
		out.Errors++
	}
	es, err := list("v1/index.json")
	if err != nil {
		listFailed(err)
	}
	for _, e := range es {
		ids[e.ProposalID] = true
		months[time.Unix(e.OpensAt, 0).UTC().Format("2006-01")] = true
	}
	for m := start; !m.After(now); m = m.AddDate(0, 1, 0) {
		months[m.Format("2006-01")] = true
	}
	for _, m := range slices.Sorted(maps.Keys(months)) {
		es, err := list("v1/archive/" + m + ".json")
		if err != nil {
			listFailed(err)
			continue
		}
		if es != nil {
			out.Months = append(out.Months, m)
		}
		for _, e := range es {
			ids[e.ProposalID] = true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		rep, err := site.Check(ctx, fetch, anchors, key, id, now, modified)
		if err != nil {
			out.Proposals = append(out.Proposals, report{ProposalID: id, Error: err.Error()})
			out.Errors++
			continue
		}
		rep.Acknowledge(acks)
		col.proposal(rep)
		out.Proposals = append(out.Proposals, toReport(rep, now))
	}
	for _, a := range acks {
		if !ids[a.ProposalID] {
			out.StaleAcknowledged = append(out.StaleAcknowledged, site.StaleAcknowledgement(a))
		}
	}

	if rk != nil {
		rr, err := runRekor(ctx, rk.flags, rk.instance, anchors, fetch, siteKeyB64, col, len(out.Lists) > 0, rk.log, now)
		var adm *errRekorAdmin
		if errors.As(err, &adm) {
			return false, err
		}
		if err != nil {
			out.Rekor = &rekor.RunReport{Instance: rk.instance, Error: err.Error(), Mismatches: []rekor.Item{}}
			out.Errors++
		} else {
			out.Rekor = rr
		}
	}
	out.OK = out.Errors == 0 && len(out.Services.Mismatches) == 0 && len(out.StaleAcknowledged) == 0
	for _, p := range out.Proposals {
		out.OK = out.OK && p.OK
	}
	if out.Rekor != nil && !out.Rekor.OK() {
		out.OK = false
	}
	if err := writeReport(w, out); err != nil {
		return false, err
	}
	if out.Errors > 0 {
		return false, errChecksFailed
	}
	return out.OK, nil
}

// anchorsFor is the Sigstore trusted material: from a trusted root file,
// or fetched through the instance's TUF repository.
func anchorsFor(instance, rootFile string) (*site.Anchors, error) {
	if rootFile == "" {
		return site.NewAnchors(instance)
	}
	b, err := os.ReadFile(rootFile)
	if err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(b)
	if err != nil {
		return nil, err
	}
	return site.NewAnchorsWith(tr), nil
}
