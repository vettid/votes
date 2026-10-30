package site

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/vettid/service-vault/vote"
)

// An observer's check of a published vote (BALLOT-PROTOCOL §8.4): the
// documents the site serves are fetched and put, in the order they were
// published, through the upload API's document checks on an empty store,
// each with the clock at its anchor's time. Timing is so checked as
// anchored (timestamped) time, which is what the files can show; that a
// document was also uploaded in time is the live site's word. The upload
// API's request-level rules (parts and sizes) are applied too. The index
// and the month's archive are compared with what the documents show;
// a difference is reported, not refused, since the lists are rewritten
// after a document is published and may lag behind a failed upload.

// Fetcher reads one published object by path (v1/...): nil, nil when it
// isn't published.
type Fetcher func(ctx context.Context, path string) ([]byte, error)

// Report is what a check found.
type Report struct {
	ProposalID  string
	ServiceID   string
	ServiceName string
	Title       string
	Eligible    int64
	OpensAt     int64
	ClosesAt    int64 // in force, after the extensions
	Extensions  int
	// Anchored is each document's anchor time, by name (proposal,
	// extension-N, results).
	Anchored map[string]time.Time
	// Results are the checked results; nil while none are published.
	Results *vote.Results
	// Hashes are each document's SHA-256 by name, and rows', for readers
	// to compare what they were served.
	Hashes map[string][]byte
	// Partial names documents whose signature, bundle or rows are
	// published without the document: an upload not finished.
	Partial []string
	// Listing names each way index.json or the month's archive differs
	// from the documents ("archive: missing", "index: closes_at", …).
	Listing []string

	serviceIK []byte
}

// ErrNotPublished is a proposal the site doesn't serve.
var ErrNotPublished = errors.New("site: the proposal isn't published")

// Check checks proposal id as served by fetch, under the site's key, at
// now (for whether the index may have dropped it).
func Check(ctx context.Context, fetch Fetcher, anchors *Anchors, siteKey []byte, id string, now time.Time) (*Report, error) {
	if !vote.ValidProposalID(id) {
		return nil, errors.New("site: not a proposal id")
	}
	mem := &MemStorage{Objects: map[string][]byte{}}
	for _, p := range []string{"v1/services.json", "v1/services.json.sig"} {
		b, err := fetch(ctx, p)
		if err != nil {
			return nil, err
		}
		if b == nil {
			return nil, fmt.Errorf("site: %s isn't published", p)
		}
		mem.Objects[p] = b
	}
	var clock time.Time
	s := &Site{Store: mem, Anchors: anchors, SiteKey: siteKey, Now: func() time.Time { return clock }}
	l, err := s.services(ctx)
	if err != nil {
		return nil, err
	}
	rep := &Report{ProposalID: id, Anchored: map[string]time.Time{}, Hashes: map[string][]byte{}}
	// put fetches a document's parts and puts it as the site would have
	// at its anchor's time; found is false when the document isn't there.
	put := func(name string, rows bool, f func(*Upload) (bool, error)) (found bool, err error) {
		base := "v1/p/" + id + "/" + name + ".json"
		u := &Upload{}
		for _, part := range []struct {
			path string
			dst  *[]byte
		}{{base, &u.Doc}, {base + ".sig", &u.Sig}, {base + ".sigstore.json", (*[]byte)(&u.Bundle)}} {
			if *part.dst, err = fetch(ctx, part.path); err != nil {
				return false, err
			}
		}
		if u.Doc == nil {
			if u.Sig != nil || u.Bundle != nil {
				rep.Partial = append(rep.Partial, name)
			}
			return false, nil
		}
		if u.Sig == nil || u.Bundle == nil {
			return true, fmt.Errorf("%s: published without its signature or bundle", name)
		}
		if rows {
			if u.Rows, err = fetch(ctx, "v1/p/"+id+"/rows.json"); err != nil {
				return true, err
			}
		}
		if _, code := uploadShape(name, u); code != "" {
			return true, fmt.Errorf("%s: an upload the site should have refused (%s)", name, code)
		}
		// The request it would take, at its smallest: the API measured
		// the body as sent, so this is never more.
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(u); err != nil {
			return true, fmt.Errorf("%s: an upload the site should have refused (bad_request)", name)
		}
		if body.Len()-1 > MaxUpload {
			return true, fmt.Errorf("%s: an upload the site should have refused (too_large)", name)
		}
		// The anchor's time, under the anchor key of the document's
		// service: the proposal names it, and the rest are its.
		svc := l.ByIK(serviceOf(u.Doc, name, rep))
		if svc == nil {
			return true, fmt.Errorf("%s: the service isn't listed", name)
		}
		ts, err := s.anchor(svc, u)
		if err != nil {
			return true, fmt.Errorf("%s: %w", name, err)
		}
		clock = ts
		if _, err := f(u); err != nil {
			return true, fmt.Errorf("%s: %w", name, err)
		}
		rep.Anchored[name] = ts
		rep.Hashes[name] = sha(u.Doc)
		if u.Rows != nil {
			rep.Hashes["rows"] = sha(u.Rows)
		}
		return true, nil
	}
	found, err := put("proposal", false, func(u *Upload) (bool, error) { return s.putProposal(ctx, id, u) })
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotPublished
	}
	_, p, svc, err := s.proposalOf(ctx, id)
	if err != nil {
		return nil, err
	}
	rep.ServiceID, rep.ServiceName, rep.Title, rep.serviceIK = svc.ServiceID, svc.Name, p.Title, p.Service
	rep.Eligible, rep.OpensAt, rep.ClosesAt = p.Eligible, p.OpensAt, p.ClosesAt
	// Every number the site allows is looked at: an extension after a
	// gap, or past the bound, is one the site should have refused.
	gap := 0
	for n := 1; n <= maxExtensions+1; n++ {
		name := "extension-" + strconv.Itoa(n)
		if gap != 0 || n > maxExtensions {
			if b, err := fetch(ctx, docPath(id, name)); err != nil {
				return nil, err
			} else if b != nil && gap != 0 {
				return nil, fmt.Errorf("%s: published, but extension-%d isn't", name, gap)
			} else if b != nil {
				return nil, fmt.Errorf("%s: past the %d extensions allowed", name, maxExtensions)
			}
			continue
		}
		found, err := put(name, false, func(u *Upload) (bool, error) { return s.putExtension(ctx, id, n, u) })
		if err != nil {
			return nil, err
		}
		if !found {
			gap = n
			continue
		}
		e, _ := vote.ParseExtension(mem.Objects[docPath(id, name)])
		rep.Extensions, rep.ClosesAt = n, e.ClosesAt
	}
	found, err = put("results", true, func(u *Upload) (bool, error) { return s.putResults(ctx, id, u) })
	if err != nil {
		return nil, err
	}
	if found {
		if _, rep.Results, err = vote.Check(p.Service, mem.Objects[docPath(id, "results")],
			mem.Objects[docPath(id, "results")+".sig"], mem.Objects["v1/p/"+id+"/rows.json"]); err != nil {
			return nil, err
		}
	}
	// The entry, as the site would have it after these uploads: from the
	// archive, which isn't pruned (results may be anchored long after the
	// close, and their index update drops the vote).
	var es []IndexEntry
	if err := json.Unmarshal(mem.Objects[archivePath(p.OpensAt)], &es); err != nil || len(es) != 1 {
		return nil, fmt.Errorf("site: the check's own archive: %v", err)
	}
	for _, l := range []struct {
		name, path string
		pruned     bool
	}{{"index", indexPath, true}, {"archive", archivePath(p.OpensAt), false}} {
		b, err := fetch(ctx, l.path)
		if err != nil {
			return nil, err
		}
		rep.Listing = append(rep.Listing, compareListing(l.name, b, es[0], l.pruned, now)...)
	}
	return rep, nil
}

// compareListing compares a served list with the entry the documents
// show. A pruned list (the index) may lack an entry that closed more than
// IndexWindow before now.
func compareListing(name string, served []byte, want IndexEntry, pruned bool, now time.Time) []string {
	if served == nil {
		return []string{name + ": not published"}
	}
	var es []IndexEntry
	if err := json.Unmarshal(served, &es); err != nil {
		return []string{name + ": not a list of entries"}
	}
	var got *IndexEntry
	for i := range es {
		if es[i].ProposalID == want.ProposalID {
			if got != nil {
				return []string{name + ": listed twice"}
			}
			got = &es[i]
		}
	}
	if got == nil {
		if pruned && want.ClosesAt < now.Add(-IndexWindow).Unix() {
			return nil
		}
		return []string{name + ": missing"}
	}
	var out []string
	diff := func(field string, same bool) {
		if !same {
			out = append(out, name+": "+field)
		}
	}
	diff("service_id", got.ServiceID == want.ServiceID)
	diff("proposal_hash", bytes.Equal(got.ProposalHash, want.ProposalHash))
	diff("opens_at", got.OpensAt == want.OpensAt)
	diff("closes_at", got.ClosesAt == want.ClosesAt)
	diff("extended", got.Extended == want.Extended)
	diff("published", got.Published == want.Published)
	// An entry from before the site listed unhandled lacks it: only a
	// value that differs is reported.
	diff("unhandled", got.Unhandled == nil || want.Unhandled != nil && *got.Unhandled == *want.Unhandled)
	return out
}

// serviceOf is the identity key of a document's service: the proposal's
// own, or, for the documents after it, the proposal's.
func serviceOf(doc []byte, name string, rep *Report) []byte {
	if name == "proposal" {
		if p, err := vote.ParseProposal(doc); err == nil {
			return p.Service
		}
		return nil
	}
	return rep.serviceIK
}
