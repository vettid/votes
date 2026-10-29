// Package site is votes.vettid.org's upload API (docs/VOTES-SITE.md;
// BALLOT-PROTOCOL §3.3): it checks each document a registered service
// uploads (its exact bytes, its signature, its Rekor anchor and its place
// in the vote) and publishes it once, never to change.
package site

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/vettid/service-vault/vote"
)

// MaxUpload bounds a request: Lambda's 6 MB, less the JSON around it.
const MaxUpload = 6<<20 - 64<<10

// Size caps per document (§4): a proposal's text is at most 16 KiB; an
// extension is a few hundred bytes; results carry the proposal, the
// extensions, roots and the tally; rows grow with the eligible members.
const (
	maxProposal  = 64 << 10
	maxExtension = 4 << 10
	maxResults   = 256 << 10
	maxBundle    = 64 << 10
)

// CollectMargin is how long after the final close the results may be
// published (BALLOT-PROTOCOL §7: collection ends a minute after it).
const CollectMargin = time.Minute

// IndexWindow keeps a closed proposal in the index this long (§3.3).
const IndexWindow = 30 * 24 * time.Hour

// Site serves the upload API.
type Site struct {
	Store   Storage
	Anchors *Anchors
	SiteKey ed25519.PublicKey // signs the service list
	Now     func() time.Time
	Log     *slog.Logger
}

// Upload is a request's body.
type Upload struct {
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle"`
	Rows   []byte          `json:"rows,omitempty"` // the results only
}

// Handler returns the routes.
func (s *Site) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/p/{id}/{name}", s.upload)
	return mux
}

var nameRe = regexp.MustCompile(`^(proposal|results|extension-([1-9][0-9]{0,2}))$`)

// refusal is a check that failed: an HTTP status and an error code.
type refusal struct {
	status int
	code   string
	why    string
}

func (r *refusal) Error() string { return r.code + ": " + r.why }

func refuse(status int, code, why string) error { return &refusal{status, code, why} }

func (s *Site) upload(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.PathValue("name")
	m := nameRe.FindStringSubmatch(name)
	if !vote.ValidProposalID(id) || m == nil {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxUpload+1))
	if err != nil || len(body) > MaxUpload {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	var u Upload
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&u) != nil || len(u.Doc) == 0 || len(u.Sig) != vote.SigLen || len(u.Bundle) == 0 || len(u.Bundle) > maxBundle {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	limit := map[bool]int{true: maxProposal, false: maxExtension}[name == "proposal"]
	if name == "results" {
		limit = maxResults
	}
	if len(u.Doc) > limit || (name != "results" && u.Rows != nil) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	var created bool
	switch {
	case name == "proposal":
		created, err = s.putProposal(r.Context(), id, &u)
	case name == "results":
		created, err = s.putResults(r.Context(), id, &u)
	default:
		n, _ := strconv.Atoi(m[2])
		created, err = s.putExtension(r.Context(), id, n, &u)
	}
	var rf *refusal
	switch {
	case errors.As(err, &rf):
		s.log().Info("upload refused", "proposal_id", id, "name", name, "code", rf.code)
		writeError(w, rf.status, rf.code)
	case err != nil:
		s.log().Error("upload", "proposal_id", id, "name", name, "err", err.Error())
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	case created:
		s.log().Info("published", "proposal_id", id, "name", name, "size", len(u.Doc))
		writeJSON(w, http.StatusCreated, map[string]string{"published": name})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"published": name})
	}
}

// Paths (docs/VOTES-SITE.md §3).
func docPath(id, name string) string { return "v1/p/" + id + "/" + name + ".json" }

const indexPath = "v1/index.json"

func archivePath(opensAt int64) string {
	return "v1/archive/" + time.Unix(opensAt, 0).UTC().Format("2006-01") + ".json"
}

// services reads and checks the service list.
func (s *Site) services(ctx context.Context) (*ServiceList, error) {
	data, _, err := s.Store.Get(ctx, "v1/services.json")
	if err != nil {
		return nil, fmt.Errorf("service list: %w", err)
	}
	sig, _, err := s.Store.Get(ctx, "v1/services.json.sig")
	if err != nil {
		return nil, fmt.Errorf("service list signature: %w", err)
	}
	return ParseServiceList(data, sig, s.SiteKey)
}

// anchor checks u's bundle under one of svc's anchor keys and returns the
// timestamp's time.
func (s *Site) anchor(svc *Service, u *Upload) (time.Time, error) {
	if err := checkProfile(u.Bundle); err != nil {
		return time.Time{}, refuse(http.StatusUnprocessableEntity, "bad_anchor", err.Error())
	}
	var last error = errors.New("no anchor key")
	for _, k := range svc.AnchorKeys {
		ts, err := s.Anchors.Verify(u.Bundle, u.Doc, k.Key)
		if err == nil {
			return ts, nil
		}
		last = err
	}
	return time.Time{}, refuse(http.StatusUnprocessableEntity, "bad_anchor", last.Error())
}

// published reads a document this site published, or nil.
func (s *Site) published(ctx context.Context, path string) ([]byte, error) {
	b, _, err := s.Store.Get(ctx, path)
	if errors.Is(err, ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// proposalOf reads the published proposal and its service.
func (s *Site) proposalOf(ctx context.Context, id string) ([]byte, *vote.Proposal, *Service, error) {
	doc, err := s.published(ctx, docPath(id, "proposal"))
	if err != nil {
		return nil, nil, nil, err
	}
	if doc == nil {
		return nil, nil, nil, refuse(http.StatusUnprocessableEntity, "unknown_proposal", "no proposal published")
	}
	p, err := vote.ParseProposal(doc)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := s.services(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	svc := l.ByIK(p.Service)
	if svc == nil {
		return nil, nil, nil, refuse(http.StatusUnprocessableEntity, "unknown_service", "the proposal's service is no longer listed")
	}
	return doc, p, svc, nil
}

func (s *Site) putProposal(ctx context.Context, id string, u *Upload) (bool, error) {
	p, err := vote.ParseProposal(u.Doc)
	if err != nil {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", err.Error())
	}
	if p.ProposalID != id {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", "another proposal's id")
	}
	l, err := s.services(ctx)
	if err != nil {
		return false, err
	}
	svc := l.ByIK(p.Service)
	if svc == nil {
		return false, refuse(http.StatusUnprocessableEntity, "unknown_service", "the service isn't registered")
	}
	if vote.Verify(p.Service, vote.LabelProposal, vote.ProposalSigMsg(u.Doc), u.Sig) != nil {
		return false, refuse(http.StatusUnprocessableEntity, "bad_signature", "proposal")
	}
	ts, err := s.anchor(svc, u)
	if err != nil {
		return false, err
	}
	// Published before the vote closes: members vote only under a
	// published proposal (BALLOT-PROTOCOL §3.3, §6). The same proposal
	// again (a retry) is accepted whenever, so that an index update a
	// failure left undone is finished.
	if prev, err := s.published(ctx, docPath(id, "proposal")); err != nil {
		return false, err
	} else if !bytes.Equal(prev, u.Doc) && (!ts.Before(time.Unix(p.ClosesAt, 0)) || !s.Now().Before(time.Unix(p.ClosesAt, 0))) {
		return false, refuse(http.StatusUnprocessableEntity, "too_late", "the vote has closed")
	}
	created, err := s.write(ctx, id, "proposal", u, nil, svc)
	if err != nil {
		return false, err
	}
	// The index changes are idempotent, so a retry also finishes one
	// that failed after the document was written.
	return created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		for _, e := range es {
			if e.ProposalID == id {
				return es
			}
		}
		return append(es, IndexEntry{ProposalID: id, ServiceID: svc.ServiceID, ProposalHash: sha(u.Doc),
			OpensAt: p.OpensAt, ClosesAt: p.ClosesAt})
	}, p.OpensAt)
}

func (s *Site) putExtension(ctx context.Context, id string, n int, u *Upload) (bool, error) {
	pdoc, p, svc, err := s.proposalOf(ctx, id)
	if err != nil {
		return false, err
	}
	e, err := vote.ParseExtension(u.Doc)
	if err != nil {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", err.Error())
	}
	if e.ProposalID != id || e.N != int64(n) {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", "another proposal's or number's extension")
	}
	m, _ := vote.DocSigMsg(sha(pdoc), u.Doc)
	if vote.Verify(p.Service, vote.LabelExtended, m, u.Sig) != nil {
		return false, refuse(http.StatusUnprocessableEntity, "bad_signature", "extension")
	}
	prev, err := s.published(ctx, docPath(id, "extension-"+strconv.Itoa(n)))
	if err != nil {
		return false, err
	}
	closes, err := s.closeInForce(ctx, id, p, n)
	if err != nil {
		return false, err
	}
	ts, err := s.anchor(svc, u)
	if err != nil {
		return false, err
	}
	if prev == nil {
		// Published and anchored before the close it extends, and never
		// once results are out (BALLOT-PROTOCOL §10.2): an extension kept
		// back and published after a look at the tally is refused.
		if res, err := s.published(ctx, docPath(id, "results")); err != nil {
			return false, err
		} else if res != nil {
			return false, refuse(http.StatusUnprocessableEntity, "too_late", "the results are published")
		}
		if !s.Now().Before(time.Unix(closes, 0)) {
			return false, refuse(http.StatusUnprocessableEntity, "too_late", "the close it extends has passed")
		}
	}
	switch {
	case !ts.Before(time.Unix(closes, 0)):
		return false, refuse(http.StatusUnprocessableEntity, "too_late", "anchored after the close it extends")
	case e.ClosesAt <= closes:
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", "the new close isn't later")
	case e.ClosesAt-p.ClosesAt > vote.MaxExtension:
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", "extensions over 24 h")
	}
	created, err := s.write(ctx, id, "extension-"+strconv.Itoa(n), u, nil, svc)
	if err != nil {
		return false, err
	}
	return created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		for i := range es {
			if es[i].ProposalID == id && e.ClosesAt > es[i].ClosesAt {
				es[i].ClosesAt, es[i].Extended = e.ClosesAt, n
			}
		}
		return es
	}, p.OpensAt)
}

// closeInForce is the close extension n extends: the proposal's, or
// extension n−1's, which must be published.
func (s *Site) closeInForce(ctx context.Context, id string, p *vote.Proposal, n int) (int64, error) {
	if n == 1 {
		return p.ClosesAt, nil
	}
	prev, err := s.published(ctx, docPath(id, "extension-"+strconv.Itoa(n-1)))
	if err != nil {
		return 0, err
	}
	if prev == nil {
		return 0, refuse(http.StatusUnprocessableEntity, "out_of_order", "the extension before isn't published")
	}
	e, err := vote.ParseExtension(prev)
	if err != nil {
		return 0, err
	}
	return e.ClosesAt, nil
}

func (s *Site) putResults(ctx context.Context, id string, u *Upload) (bool, error) {
	pdoc, p, svc, err := s.proposalOf(ctx, id)
	if err != nil {
		return false, err
	}
	if len(u.Rows) == 0 {
		return false, refuse(http.StatusBadRequest, "bad_request", "no rows")
	}
	// Every signature, the rows, the tags against record_root, each
	// ballot and the tally (the protocol's §8.4).
	_, res, err := vote.Check(p.Service, u.Doc, u.Sig, u.Rows)
	if err != nil {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", err.Error())
	}
	if res.ProposalID != id || !bytes.Equal(res.Proposal.Doc, pdoc) {
		return false, refuse(http.StatusUnprocessableEntity, "bad_document", "not the published proposal")
	}
	// The extensions are exactly the published ones.
	closes := p.ClosesAt
	for i := 1; ; i++ {
		ext, err := s.published(ctx, docPath(id, "extension-"+strconv.Itoa(i)))
		if err != nil {
			return false, err
		}
		if ext == nil {
			if len(res.Extensions) != i-1 {
				return false, refuse(http.StatusUnprocessableEntity, "bad_document", "extensions that weren't published")
			}
			break
		}
		if len(res.Extensions) < i || !bytes.Equal(res.Extensions[i-1].Doc, ext) {
			return false, refuse(http.StatusUnprocessableEntity, "bad_document", "not the published extensions")
		}
		e, _ := vote.ParseExtension(ext)
		closes = e.ClosesAt
	}
	end := time.Unix(closes, 0).Add(CollectMargin)
	if s.Now().Before(end) {
		return false, refuse(http.StatusUnprocessableEntity, "too_early", "the vote hasn't closed")
	}
	ts, err := s.anchor(svc, u)
	if err != nil {
		return false, err
	}
	if ts.Before(time.Unix(closes, 0)) {
		return false, refuse(http.StatusUnprocessableEntity, "bad_anchor", "results anchored before the close")
	}
	created, err := s.write(ctx, id, "results", u, u.Rows, svc)
	if err != nil {
		return false, err
	}
	return created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		for i := range es {
			if es[i].ProposalID == id {
				es[i].Published = true
			}
		}
		return es
	}, p.OpensAt)
}

// write publishes a checked document: its signature, bundle and any rows
// first, then the document, so that a document is never there without
// them. A retry finds the same document and fills in what is missing; a
// different document at the path is refused. A bundle already there for
// the same document is kept: another anchor of the same bytes is the
// same document (§8.5 "Rekor profile").
func (s *Site) write(ctx context.Context, id, name string, u *Upload, rows []byte, svc *Service) (bool, error) {
	path := docPath(id, name)
	if prev, err := s.published(ctx, path); err != nil {
		return false, err
	} else if prev != nil && !bytes.Equal(prev, u.Doc) {
		return false, refuse(http.StatusConflict, "differs", "another document is published there")
	}
	base := "v1/p/" + id + "/" + name
	parts := []struct {
		path, ctype string
		data        []byte
	}{
		{base + ".json.sig", "application/octet-stream", u.Sig},
		{base + ".json.sigstore.json", "application/json", u.Bundle},
	}
	if rows != nil {
		parts = append(parts, struct {
			path, ctype string
			data        []byte
		}{"v1/p/" + id + "/rows.json", "application/json", rows})
	}
	for i, p := range parts {
		err := s.Store.PutOnce(ctx, p.path, p.data, p.ctype)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrExists) {
			return false, err
		}
		// Something is already there (an earlier upload): it must belong
		// to this document. The signature and the rows must be the same
		// bytes; a bundle may be another anchor of the same document, and
		// is kept only if it verifies for this one.
		prev, err := s.published(ctx, p.path)
		if err != nil {
			return false, err
		}
		same := bytes.Equal(prev, p.data)
		if !same && i == 1 {
			_, err := s.anchor(svc, &Upload{Doc: u.Doc, Bundle: prev})
			same = err == nil
		}
		if !same {
			return false, refuse(http.StatusConflict, "differs", "an earlier upload left another document's "+p.path)
		}
	}
	err := s.Store.PutOnce(ctx, path, u.Doc, "application/json")
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrExists):
		prev, err := s.published(ctx, path)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(prev, u.Doc) {
			return false, refuse(http.StatusConflict, "differs", "another document is published there")
		}
		return false, nil
	default:
		return false, err
	}
}

// IndexEntry is one proposal in the index (docs/VOTES-SITE.md §3).
type IndexEntry struct {
	ProposalID   string `json:"proposal_id"`
	ServiceID    string `json:"service_id"`
	ProposalHash []byte `json:"proposal_hash"`
	OpensAt      int64  `json:"opens_at"`
	ClosesAt     int64  `json:"closes_at"` // as extended
	Extended     int    `json:"extended"`  // the number of extensions
	Published    bool   `json:"published"` // the results
}

// index applies change to the index and to the month's archive, each
// replaced only over the version read, retried on a race. The index drops
// proposals closed more than IndexWindow ago; the archive keeps them.
func (s *Site) index(ctx context.Context, change func([]IndexEntry) []IndexEntry, opensAt int64) error {
	cutoff := s.Now().Add(-IndexWindow).Unix()
	for _, f := range []struct {
		path  string
		prune bool
	}{{indexPath, true}, {archivePath(opensAt), false}} {
		var err error
		for range 5 {
			if err = s.updateList(ctx, f.path, func(es []IndexEntry) []IndexEntry {
				es = change(es)
				if f.prune {
					kept := es[:0]
					for _, e := range es {
						if e.ClosesAt >= cutoff {
							kept = append(kept, e)
						}
					}
					es = kept
				}
				sort.Slice(es, func(i, j int) bool {
					if es[i].OpensAt != es[j].OpensAt {
						return es[i].OpensAt < es[j].OpensAt
					}
					return es[i].ProposalID < es[j].ProposalID
				})
				return es
			}); !errors.Is(err, ErrChanged) {
				break
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Site) updateList(ctx context.Context, path string, change func([]IndexEntry) []IndexEntry) error {
	data, tag, err := s.Store.Get(ctx, path)
	var es []IndexEntry
	switch {
	case errors.Is(err, ErrNotExist):
		tag = ""
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(data, &es); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	es = change(es)
	if es == nil {
		es = []IndexEntry{}
	}
	out, err := json.Marshal(es)
	if err != nil {
		return err
	}
	return s.Store.PutIf(ctx, path, out, "application/json", tag)
}

func (s *Site) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// checkProfile holds a bundle to the protocol's Rekor profile (§8.5):
// v0.3, a SHA-256 message signature, exactly one hashedrekord 0.0.1 log
// entry and exactly one RFC 3161 timestamp, so that what is published is
// exactly what was verified.
func checkProfile(raw []byte) error {
	var b struct {
		MediaType            string `json:"mediaType"`
		VerificationMaterial struct {
			PublicKey   *struct{} `json:"publicKey"`
			TlogEntries []struct {
				KindVersion struct {
					Kind    string `json:"kind"`
					Version string `json:"version"`
				} `json:"kindVersion"`
			} `json:"tlogEntries"`
			TimestampVerificationData struct {
				RFC3161Timestamps []json.RawMessage `json:"rfc3161Timestamps"`
			} `json:"timestampVerificationData"`
		} `json:"verificationMaterial"`
		MessageSignature *struct {
			MessageDigest struct {
				Algorithm string `json:"algorithm"`
			} `json:"messageDigest"`
		} `json:"messageSignature"`
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return errors.New("bundle: not JSON")
	}
	vm := b.VerificationMaterial
	switch {
	case b.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json":
		return errors.New("bundle: not v0.3")
	case vm.PublicKey == nil || b.MessageSignature == nil || b.DSSEEnvelope != nil || b.MessageSignature.MessageDigest.Algorithm != "SHA2_256":
		return errors.New("bundle: not a key-based SHA-256 message signature")
	case len(vm.TlogEntries) != 1 || vm.TlogEntries[0].KindVersion.Kind != "hashedrekord" || vm.TlogEntries[0].KindVersion.Version != "0.0.1":
		return errors.New("bundle: not exactly one hashedrekord 0.0.1 entry")
	case len(vm.TimestampVerificationData.RFC3161Timestamps) != 1:
		return errors.New("bundle: not exactly one RFC 3161 timestamp")
	}
	return nil
}
