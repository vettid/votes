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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vettid/service-vault/vote"
)

// MaxUpload bounds a request: Lambda's 6 MB, less the JSON around it.
const MaxUpload = 6<<20 - 64<<10

// Size caps per document (§4): a proposal is at most 64 KiB; an
// extension is a few hundred bytes; results carry the proposal, the
// extensions, roots and the tally; rows grow with the eligible members.
const (
	maxProposal  = vote.MaxProposal // BALLOT-PROTOCOL §3.1, as a member's vault bounds it
	maxExtension = 4 << 10
	maxResults   = 512 << 10 // the proposal (in base64) and up to maxExtensions extensions
	maxBundle    = 64 << 10
	// maxExtensions bounds an extension's number: extensions add at most
	// 24 h in all, a whole hour at least each (BALLOT-PROTOCOL §10.2).
	maxExtensions = 24
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

	// The last service list that passed ParseServiceList, with the exact
	// bytes and the site key it was checked under: read-only once cached.
	listMu   sync.Mutex
	listData []byte
	listSig  []byte
	listKey  ed25519.PublicKey
	list     *ServiceList
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

var nameRe = regexp.MustCompile(`^(proposal|results|extension-([1-9][0-9]?))$`)

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
	if !validSlot(id, name) {
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
	if dec.Decode(&u) != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if status, code := uploadShape(name, &u, true); status != 0 {
		writeError(w, status, code)
		return
	}
	created, err := s.put(r.Context(), id, name, &u, nil)
	var rf *refusal
	var ie *indexError
	stale := false
	if errors.As(err, &ie) {
		// The document is written; only the index is behind. A retry of
		// the same upload (or its next write) finishes the index.
		s.log().Error("index update failed", "proposal_id", id, "name", name, "err", ie.err.Error())
		created, err, stale = ie.created, nil, true
	}
	switch {
	case errors.As(err, &rf):
		s.log().Info("upload refused", "proposal_id", id, "name", name, "code", rf.code)
		writeError(w, rf.status, rf.code)
	case err != nil:
		s.log().Error("upload", "proposal_id", id, "name", name, "err", err.Error())
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	case created:
		s.log().Info("published", "proposal_id", id, "name", name, "size", len(u.Doc))
		writeJSON(w, http.StatusCreated, map[string]any{"published": name, "index_updated": !stale})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"published": name, "index_updated": !stale})
	}
}

// validSlot is whether name is a document's name (proposal, results,
// extension-1 to extension-24) and id a proposal id.
func validSlot(id, name string) bool {
	m := nameRe.FindStringSubmatch(name)
	n, _ := strconv.Atoi(m2(m))
	return vote.ValidProposalID(id) && m != nil && n <= maxExtensions
}

// put runs an upload's checks and, unless dry, writes it. A dry run
// (Prepare) takes the time now for the anchor's, which a later anchor
// can only follow, and stops before the write.
func (s *Site) put(ctx context.Context, id, name string, u *Upload, dry *dryRun) (bool, error) {
	switch name {
	case "proposal":
		return s.putProposal(ctx, id, u, dry)
	case "results":
		return s.putResults(ctx, id, u, dry)
	default:
		n, _ := strconv.Atoi(m2(nameRe.FindStringSubmatch(name)))
		return s.putExtension(ctx, id, n, u, dry)
	}
}

// placeholderBundle stands in for a bundle of the largest size the site
// takes, for measuring a request before it has one.
var placeholderBundle = json.RawMessage(strconv.Quote(strings.Repeat("x", maxBundle-2)))

// Prepared is what Prepare found.
type Prepared struct {
	// Published is whether the site already holds these exact bytes
	// at the slot.
	Published bool
	// Held is whether the site holds a bundle for these bytes at the slot
	// (published, or an earlier partial upload's) that the checks took:
	// an upload keeps that bundle, so the signer uploads it and signs
	// nothing.
	Held bool
}

// Refusal is an upload's refusal: the HTTP status and the error code the
// site answers with.
type Refusal struct {
	Status int
	Code   string
}

func (r *Refusal) Error() string { return "site refuses: " + r.Code }

// PrepareOptions are a Prepare's inputs beyond the upload.
type PrepareOptions struct {
	// At is the anchor's time to judge by: the kept timestamp's time when
	// a signer resumes, or now plus its lead before it signs. Zero is now.
	At time.Time
	// AnchorKey is the SubjectPublicKeyInfo the document will be anchored
	// under: one the document's service doesn't list is refused
	// (bad_anchor), before anything is signed. Nil skips the check.
	AnchorKey []byte
	// ServiceIKs are the identity keys the signer anchors for (compiled
	// into it, GC #7638 item 1): a document whose service (the proposal's
	// `service`, or the published proposal's) isn't one of them is refused
	// (unknown_service), whatever the service list says. Nil skips the
	// check.
	ServiceIKs [][]byte
}

// Prepare runs every check an upload of doc, sig and rows to the slot
// (id, name) would get, except the anchor, and writes nothing: the
// signer's checks before it signs (key protection, GC #7406 §1). The
// anchor's time is opts.At, and its key must be one the service lists; the
// request is measured with the largest bundle the site takes. A document
// or a bundle the site already holds is judged with the bundle it holds. A
// refusal is a *Refusal; any other error is the store's.
func (s *Site) Prepare(ctx context.Context, id, name string, doc, sig, rows []byte, opts PrepareOptions) (Prepared, error) {
	if !validSlot(id, name) {
		return Prepared{}, &Refusal{http.StatusNotFound, "not_found"}
	}
	u := &Upload{Doc: doc, Sig: sig, Rows: rows}
	if status, code := uploadShape(name, u, false); status != 0 {
		return Prepared{}, &Refusal{status, code}
	}
	prev, err := s.published(ctx, docPath(id, name))
	if err != nil {
		return Prepared{}, err
	}
	if prev != nil && !bytes.Equal(prev, doc) {
		return Prepared{}, &Refusal{http.StatusConflict, "differs"}
	}
	// The request it will take, with the largest bundle the site takes:
	// the API measures the body as sent (as Check does).
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&Upload{Doc: doc, Sig: sig, Rows: rows, Bundle: placeholderBundle}); err != nil {
		return Prepared{}, &Refusal{http.StatusBadRequest, "bad_request"}
	}
	if body.Len()-1 > MaxUpload {
		return Prepared{}, &Refusal{http.StatusRequestEntityTooLarge, "too_large"}
	}
	// Parts an earlier upload left: the signature and rows must be these
	// bytes, as write requires.
	base := "v1/p/" + id + "/" + name
	left := []struct {
		path string
		data []byte
	}{{base + ".json.sig", sig}}
	if name == "results" {
		left = append(left, struct {
			path string
			data []byte
		}{"v1/p/" + id + "/rows.json", rows})
	}
	for _, l := range left {
		b, err := s.published(ctx, l.path)
		if err != nil {
			return Prepared{}, err
		}
		if b != nil && !bytes.Equal(b, l.data) {
			return Prepared{}, &Refusal{http.StatusConflict, "differs"}
		}
	}
	// A bundle there already (published, or a partial upload's) judges
	// the document, as a re-upload would be judged: write keeps it, and
	// refuses one that isn't this document's.
	held, err := s.published(ctx, base+".json.sigstore.json")
	if err != nil {
		return Prepared{}, err
	}
	u.Bundle = held
	if opts.ServiceIKs != nil {
		ik, err := s.docService(ctx, id, name, doc)
		if err != nil {
			return Prepared{}, err
		}
		if ik != nil && !slices.ContainsFunc(opts.ServiceIKs, func(k []byte) bool { return bytes.Equal(k, ik) }) {
			return Prepared{}, &Refusal{http.StatusUnprocessableEntity, "unknown_service"}
		}
	}
	if _, err := s.put(ctx, id, name, u, &dryRun{at: opts.At, key: opts.AnchorKey}); err != nil {
		var rf *refusal
		if errors.As(err, &rf) {
			return Prepared{}, &Refusal{rf.status, rf.code}
		}
		return Prepared{}, err
	}
	return Prepared{Published: prev != nil, Held: held != nil}, nil
}

// docService is the identity key a document to (id, name) is under: a
// proposal's own `service`, or the published proposal's for the others;
// nil when it can't be read (the checks that follow refuse it).
func (s *Site) docService(ctx context.Context, id, name string, doc []byte) ([]byte, error) {
	if name == "proposal" {
		if p, err := vote.ParseProposal(doc); err == nil {
			return p.Service, nil
		}
		return nil, nil
	}
	pdoc, err := s.published(ctx, docPath(id, "proposal"))
	if err != nil || pdoc == nil {
		return nil, err
	}
	if p, err := vote.ParseProposal(pdoc); err == nil {
		return p.Service, nil
	}
	return nil, nil
}

// lists is whether svc lists the anchor key spki.
func lists(svc *Service, spki []byte) bool {
	for _, k := range svc.AnchorKeys {
		if bytes.Equal(k.Key, spki) {
			return true
		}
	}
	return false
}

// dryRun is a run of the checks with nothing written (Prepare).
type dryRun struct {
	at  time.Time // the anchor's time; zero is now
	key []byte    // the anchor key, which the service must list; nil skips it
}

// anchorAt is the anchor's time, or, in a dry run without a bundle, the
// run's time, under a key the service lists.
func (s *Site) anchorAt(dry *dryRun, svc *Service, u *Upload) (time.Time, error) {
	if dry != nil && len(u.Bundle) == 0 {
		if dry.key != nil && !lists(svc, dry.key) {
			return time.Time{}, refuse(http.StatusUnprocessableEntity, "bad_anchor", "the signer's key isn't one of the service's anchor keys")
		}
		if dry.at.IsZero() {
			return s.Now(), nil
		}
		return dry.at, nil
	}
	return s.anchor(svc, u)
}

// indexError is an index update that failed after the document was
// written; created is whether this upload wrote it.
type indexError struct {
	err     error
	created bool
}

func (e *indexError) Error() string { return "index: " + e.err.Error() }
func (e *indexError) Unwrap() error { return e.err }

// indexed passes the result of the index update on: a failure becomes an
// indexError so that the upload still answers for the written document.
func (s *Site) indexed(created bool, err error) (bool, error) {
	if err != nil {
		return created, &indexError{err, created}
	}
	return created, nil
}

// Paths (docs/VOTES-SITE.md §3).
func docPath(id, name string) string { return "v1/p/" + id + "/" + name + ".json" }

const indexPath = "v1/index.json"

func archivePath(opensAt int64) string {
	return "v1/archive/" + time.Unix(opensAt, 0).UTC().Format("2006-01") + ".json"
}

// services reads and checks the service list. Both objects are read on
// every call, so a new list counts at once; the check and parse (up to
// MaxServiceList bytes) are skipped when the pair is byte for byte the
// one checked last, under the same site key. Only a pair that passed is kept.
func (s *Site) services(ctx context.Context) (*ServiceList, error) {
	data, _, err := s.Store.Get(ctx, "v1/services.json")
	if err != nil {
		return nil, fmt.Errorf("service list: %w", err)
	}
	sig, _, err := s.Store.Get(ctx, "v1/services.json.sig")
	if err != nil {
		return nil, fmt.Errorf("service list signature: %w", err)
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	if s.list != nil && bytes.Equal(data, s.listData) && bytes.Equal(sig, s.listSig) && s.SiteKey.Equal(s.listKey) {
		return s.list, nil
	}
	l, err := ParseServiceList(data, sig, s.SiteKey)
	if err != nil {
		return nil, err
	}
	s.listData, s.listSig, s.listKey, s.list = data, sig, bytes.Clone(s.SiteKey), l
	return l, nil
}

// anchor checks u's bundle under one of svc's anchor keys and returns the
// timestamp's time.
func (s *Site) anchor(svc *Service, u *Upload) (time.Time, error) {
	t, err := s.anchorTimes(svc, u)
	return t.TSA, err
}

// anchorTimes is anchor, returning the bundle's Rekor time too.
func (s *Site) anchorTimes(svc *Service, u *Upload) (AnchorTimes, error) {
	if err := checkProfile(u.Bundle); err != nil {
		return AnchorTimes{}, refuse(http.StatusUnprocessableEntity, "bad_anchor", err.Error())
	}
	var last error = errors.New("no anchor key")
	for _, k := range svc.AnchorKeys {
		t, err := s.Anchors.VerifyTimes(u.Bundle, u.Doc, k.Key)
		if err == nil {
			return t, nil
		}
		last = err
	}
	return AnchorTimes{}, refuse(http.StatusUnprocessableEntity, "bad_anchor", last.Error())
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

func (s *Site) putProposal(ctx context.Context, id string, u *Upload, dry *dryRun) (bool, error) {
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
	ts, err := s.anchorAt(dry, svc, u)
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
	if dry != nil {
		return false, nil
	}
	created, err := s.write(ctx, id, "proposal", u, nil, svc)
	if err != nil {
		return false, err
	}
	// The index changes are idempotent, so a retry also finishes one
	// that failed after the document was written.
	return s.indexed(created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		for _, e := range es {
			if e.ProposalID == id {
				return es
			}
		}
		return append(es, IndexEntry{ProposalID: id, ServiceID: svc.ServiceID, ProposalHash: sha(u.Doc),
			OpensAt: p.OpensAt, ClosesAt: p.ClosesAt})
	}, p.OpensAt))
}

// withEntry adds the proposal's entry, as its proposal upload would have,
// when the index lacks it (an earlier index update failed), so that the
// next write repairs the index.
func withEntry(es []IndexEntry, id string, svc *Service, pdoc []byte, p *vote.Proposal) []IndexEntry {
	for _, e := range es {
		if e.ProposalID == id {
			return es
		}
	}
	return append(es, IndexEntry{ProposalID: id, ServiceID: svc.ServiceID, ProposalHash: sha(pdoc),
		OpensAt: p.OpensAt, ClosesAt: p.ClosesAt})
}

func (s *Site) putExtension(ctx context.Context, id string, n int, u *Upload, dry *dryRun) (bool, error) {
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
	ts, err := s.anchorAt(dry, svc, u)
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
	if dry != nil {
		return false, nil
	}
	created, err := s.write(ctx, id, "extension-"+strconv.Itoa(n), u, nil, svc)
	if err != nil {
		return false, err
	}
	// The close in force and the number of extensions are the published
	// ones, so that a re-upload of an earlier extension (or a rebuilt
	// entry) never moves either backwards.
	cl, cnt := e.ClosesAt, n
	for i := n + 1; i <= maxExtensions; i++ {
		raw, err := s.published(ctx, docPath(id, "extension-"+strconv.Itoa(i)))
		if err != nil {
			return created, err
		}
		if raw == nil {
			break
		}
		if x, err := vote.ParseExtension(raw); err == nil && x.ClosesAt > cl {
			cl = x.ClosesAt
		}
		cnt = i
	}
	return s.indexed(created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		es = withEntry(es, id, svc, pdoc, p)
		for i := range es {
			if es[i].ProposalID == id {
				es[i].ClosesAt, es[i].Extended = max(es[i].ClosesAt, cl), max(es[i].Extended, cnt)
			}
		}
		return es
	}, p.OpensAt))
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

func (s *Site) putResults(ctx context.Context, id string, u *Upload, dry *dryRun) (bool, error) {
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
	// The signatures they carry are the published ones too, byte for
	// byte: another valid signature of the same document is still not
	// what members and observers were served.
	if err := s.samePublishedSig(ctx, id, "proposal", res.Proposal.Sig); err != nil {
		return false, err
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
		if err := s.samePublishedSig(ctx, id, "extension-"+strconv.Itoa(i), res.Extensions[i-1].Sig); err != nil {
			return false, err
		}
		e, _ := vote.ParseExtension(ext)
		closes = e.ClosesAt
	}
	end := time.Unix(closes, 0).Add(CollectMargin)
	if s.Now().Before(end) {
		return false, refuse(http.StatusUnprocessableEntity, "too_early", "the vote hasn't closed")
	}
	ts, err := s.anchorAt(dry, svc, u)
	if err != nil {
		return false, err
	}
	if ts.Before(end) {
		// Collection ends a minute after the close (§7): results anchored
		// sooner were counted before it ended.
		return false, refuse(http.StatusUnprocessableEntity, "bad_anchor", "results anchored before collection ended")
	}
	if dry != nil {
		return false, nil
	}
	created, err := s.write(ctx, id, "results", u, u.Rows, svc)
	if err != nil {
		return false, err
	}
	unhandled := res.Counts.Unhandled
	return s.indexed(created, s.index(ctx, func(es []IndexEntry) []IndexEntry {
		es = withEntry(es, id, svc, pdoc, p)
		for i := range es {
			if es[i].ProposalID == id {
				// The results are checked against the published
				// extensions: the close in force and their number.
				es[i].ClosesAt, es[i].Extended = max(es[i].ClosesAt, closes), max(es[i].Extended, len(res.Extensions))
				es[i].Published, es[i].Unhandled = true, &unhandled
			}
		}
		return es
	}, p.OpensAt))
}

// samePublishedSig refuses a signature the results embed for a published
// document (name) that isn't byte for byte its published .sig.
func (s *Site) samePublishedSig(ctx context.Context, id, name string, sig []byte) error {
	pub, err := s.published(ctx, docPath(id, name)+".sig")
	if err != nil {
		return err
	}
	if pub == nil || !bytes.Equal(pub, sig) {
		return refuse(http.StatusUnprocessableEntity, "sig_mismatch",
			"the results' signature of "+name+" isn't the published "+name+".json.sig")
	}
	return nil
}

// uploadShape applies the upload's request-level rules to a decoded
// upload of a document called name: the parts present, the signature's
// length and each part's size limit. It returns 0 when they hold.
func uploadShape(name string, u *Upload, bundled bool) (status int, code string) {
	if len(u.Doc) == 0 || len(u.Sig) != vote.SigLen || bundled && len(u.Bundle) == 0 || len(u.Bundle) > maxBundle ||
		name != "results" && u.Rows != nil {
		return http.StatusBadRequest, "bad_request"
	}
	limit := map[bool]int{true: maxProposal, false: maxExtension}[name == "proposal"]
	if name == "results" {
		limit = maxResults
	}
	if len(u.Doc) > limit {
		return http.StatusRequestEntityTooLarge, "too_large"
	}
	return 0, ""
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
	// Unhandled is the results' counts.unhandled, once they are published:
	// messages the count went ahead without (BALLOT-PROTOCOL §7), for
	// readers to weigh without fetching the results.
	Unhandled *int64 `json:"unhandled,omitempty"`
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

// m2 is the extension number a name match holds, or "".
func m2(m []string) string {
	if len(m) > 2 {
		return m[2]
	}
	return ""
}
