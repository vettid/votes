package site

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/vettid/service-vault/vote"
)

// An observer's check of a published vote (BALLOT-PROTOCOL §8.4): the
// documents the site serves are fetched and put, in the order they were
// published, through the upload API's own checks on an empty store, each
// with the clock at its anchor's time, as the site saw it. A vote that
// passes is one the site would accept again from nothing but its
// published files, the service list and the site's key.

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

	serviceIK []byte
}

// ErrNotPublished is a proposal the site doesn't serve.
var ErrNotPublished = errors.New("site: the proposal isn't published")

// Check checks proposal id as served by fetch, under the site's key.
func Check(ctx context.Context, fetch Fetcher, anchors *Anchors, siteKey []byte, id string) (*Report, error) {
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
	rep := &Report{ProposalID: id, Anchored: map[string]time.Time{}}
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
	for n := 1; ; n++ {
		name := "extension-" + strconv.Itoa(n)
		found, err := put(name, false, func(u *Upload) (bool, error) { return s.putExtension(ctx, id, n, u) })
		if err != nil {
			return nil, err
		}
		if !found {
			break
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
	return rep, nil
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
