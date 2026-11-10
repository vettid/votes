// Package signer is the AnchorSigner function's logic (key protection,
// phase 1, GC #7406 §1–§3): it anchors one vote document under the
// service's anchor key, which only this function may use, and publishes
// it on the votes site. It signs only what it publishes: a document the
// site's own checks accept (site.Prepare), for a slot whose claim names
// that document's digest.
//
// Each step's result is kept in the claim before the next network call
// (the signature, then the RFC 3161 token, then the Rekor entry), so a
// retry resumes and never signs or timestamps again, and never pairs one
// attempt's time with another's. A short lease in the claim keeps two
// calls for one slot from both signing.
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/vettid/votes/site"
)

// Request is one call: a document for one slot, with its IK signature,
// and the rows for results.
type Request struct {
	ProposalID string `json:"proposal_id"`
	Name       string `json:"name"`
	Doc        []byte `json:"doc"`
	Sig        []byte `json:"sig"`
	Rows       []byte `json:"rows,omitempty"`
}

// Result is the call's answer: the site's answer to the upload (Status,
// Code, IndexUpdated), or the signer's own refusal. Bundle is the bundle
// the site holds when it answered 200 or 201.
type Result struct {
	Status       int             `json:"status"`
	Code         string          `json:"code,omitempty"`
	Bundle       json.RawMessage `json:"bundle,omitempty"`
	IndexUpdated bool            `json:"index_updated"`
}

// Claim is a slot's record (GC #7406 §2): created once for a digest, each
// artifact set once.
type Claim struct {
	Slot       string
	Digest     []byte
	LeaseUntil time.Time // a call is signing until then
	Sig        []byte    // ASN.1 DER ECDSA signature
	R          []byte    // its r, big-endian, without leading zeros
	RequestID  string    // KMS's request id for the Sign
	Journaled  bool      // the sign entry is in the journal
	TSAToken   []byte    // RFC 3161 TimeStampResp
	RekorEntry json.RawMessage
	Created    time.Time
}

// Claim store errors.
var (
	// ErrExists: Create found a claim for the slot.
	ErrExists = errors.New("signer: claim exists")
	// ErrSet: a write's condition failed (the field set already, a live
	// lease, another digest or r, or no claim).
	ErrSet = errors.New("signer: claim condition failed")
)

// Retryable failures, before anything is signed.
var (
	// ErrBusy: another call holds the slot's signing lease.
	ErrBusy = errors.New("signer: another call is signing this slot")
	// ErrNoTime: too little of the call's time is left to sign and keep
	// the signature.
	ErrNoTime = errors.New("signer: too little time left to sign")
)

// Claims is the claim table, which only the signer may write.
type Claims interface {
	// Get returns the slot's claim, or nil.
	Get(ctx context.Context, slot string) (*Claim, error)
	// Create makes the slot's claim for digest, only if there is none
	// (ErrExists otherwise).
	Create(ctx context.Context, slot string, digest []byte, at time.Time) error
	// Lease sets the signing lease to until, only if the claim names
	// digest, has no signature, and has no lease live at now.
	Lease(ctx context.Context, slot string, digest []byte, until, now time.Time) error
	// SetSig sets the signature, its r and KMS's request id, only if the
	// claim names digest and has no signature.
	SetSig(ctx context.Context, slot string, digest, sig, r []byte, requestID string) error
	// SetJournaled, SetToken and SetEntry set one artifact each, only if
	// it is unset and the claim names digest and r: never on another
	// attempt's signature.
	SetJournaled(ctx context.Context, slot string, digest, r []byte) error
	SetToken(ctx context.Context, slot string, digest, r, token []byte) error
	SetEntry(ctx context.Context, slot string, digest, r []byte, entry json.RawMessage) error
}

// SignEntry is the journal's record of a sign (GC #7406 §3): ids, hashes
// and codes only, never text from the input. A sign may be journaled more
// than once (a retry after a lost mark); the reconciler counts it by
// (digest, r).
type SignEntry struct {
	KMSRequestID string    `json:"kms_request_id"`
	At           time.Time `json:"at"`
	ProposalID   string    `json:"proposal_id"`
	Name         string    `json:"name"`
	Digest       []byte    `json:"digest"`
	Signature    []byte    `json:"signature"`
	R            []byte    `json:"r"`
}

// CompletionEntry is the journal's record of the call's end.
type CompletionEntry struct {
	At          time.Time `json:"at"`
	ProposalID  string    `json:"proposal_id"`
	Name        string    `json:"name"`
	Digest      []byte    `json:"digest"`
	R           []byte    `json:"r,omitempty"`
	TSATime     time.Time `json:"tsa_time,omitzero"`
	RekorIndex  int64     `json:"rekor_index,omitempty"`
	Integrated  time.Time `json:"integrated,omitzero"`
	SiteStatus  int       `json:"site_status"`
	SiteCode    string    `json:"site_code,omitempty"`
	Resumed     bool      `json:"resumed,omitempty"`
	AlreadyHeld bool      `json:"already_held,omitempty"`
}

// Journal is the signer's append-only log.
type Journal interface {
	Sign(ctx context.Context, e SignEntry) error
	Complete(ctx context.Context, e CompletionEntry) error
}

// Anchor is the anchoring steps (service-vault's anchor.Anchorer, with a
// KMS-backed DigestSigner). Sign checks the signature against the anchor
// key before it returns. Enter must be safe to call again for the same
// signature: when Rekor already holds the entry (a retry after the entry
// wasn't kept), it returns that entry, or a slot could never go on.
type Anchor interface {
	Sign(ctx context.Context, doc []byte) (digest, sig []byte, err error)
	Timestamp(ctx context.Context, sig []byte) ([]byte, error)
	Enter(ctx context.Context, digest, sig []byte) (json.RawMessage, error)
	Bundle(digest, sig, ts []byte, entry json.RawMessage) (json.RawMessage, error)
	PublicKeyDER() []byte
}

// Site is the votes site as the signer sees it.
type Site interface {
	// Prepare runs the upload's checks without an anchor, taking the
	// anchor's time as lead after now (site.Prepare).
	Prepare(ctx context.Context, id, name string, doc, sig, rows []byte, lead time.Duration) (site.Prepared, error)
	// Bundle returns the bundle the site holds for a slot, or nil.
	Bundle(ctx context.Context, id, name string) ([]byte, error)
	// Upload posts the upload and returns the site's status, code and
	// index_updated.
	Upload(ctx context.Context, id, name string, u *site.Upload) (status int, code string, indexUpdated bool, err error)
	// Times verifies a bundle for doc under the anchor key and returns
	// its RFC 3161 time, its Rekor integrated time and log index.
	Times(bundle, doc, spki []byte) (tsa, integrated time.Time, index int64, err error)
}

// Deadlines bound each hop (GC #7406 §1, "Timeouts").
type Deadlines struct {
	Claims, Key, TSA, Rekor, Site time.Duration
	// Margin is kept back for the writes after a sign.
	Margin time.Duration
}

// Worst is the longest a call can take with every hop at its deadline.
func (d Deadlines) Worst() time.Duration {
	// Prepare and the held-bundle read, the claim (read, create, read),
	// the lease, the sign, its keeping, journal and mark, the TSA and its
	// keeping, Rekor and its keeping, the upload, the completion.
	return 2*d.Site + 3*d.Claims + d.Claims + d.Key + 3*d.Claims + d.TSA + d.Claims + d.Rekor + d.Claims + d.Site + d.Claims
}

// signWindow is how much of the call's time a sign needs: the KMS call and
// keeping its result, with the margin.
func (d Deadlines) signWindow() time.Duration { return d.Key + 3*d.Claims + d.Margin }

// DefaultDeadlines fit the function's 120 s timeout (Worst is under it).
var DefaultDeadlines = Deadlines{Claims: 3 * time.Second, Key: 10 * time.Second, TSA: 15 * time.Second,
	Rekor: 20 * time.Second, Site: 10 * time.Second, Margin: 5 * time.Second}

// DefaultLead is how much later than its checks a document is taken to be
// anchored: the claim, the lease, the sign and its keeping, and the TSA,
// at their deadlines, rounded up.
const DefaultLead = time.Minute

// Signer anchors and publishes documents.
type Signer struct {
	Claims    Claims
	Journal   Journal
	Anchor    Anchor
	Site      Site
	Now       func() time.Time
	Log       *slog.Logger
	Deadlines Deadlines
	Lead      time.Duration
}

// Refusal codes the signer answers with itself, before anything is
// signed.
const (
	// CodeClaimConflict: the slot's claim names another document. It is
	// never signed, and it alarms.
	CodeClaimConflict = "claim_conflict"
	// CodeBadRequest: the call itself is malformed.
	CodeBadRequest = "bad_request"
	// CodeClaimStuck: the alarm for a claim whose kept steps make no
	// bundle.
	CodeClaimStuck = "claim_stuck"
)

// requestIDKey is the context key under which Handle puts a *string for
// the KMS signer to record its request id in, for the journal.
type requestIDKey struct{}

// WithRequestIDSink returns ctx with p as the place a KMS signer records
// its request id in.
func WithRequestIDSink(ctx context.Context, p *string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, p)
}

// RequestIDSink returns where a KMS signer records the request id of the
// Sign call made under ctx, or nil.
func RequestIDSink(ctx context.Context) *string {
	p, _ := ctx.Value(requestIDKey{}).(*string)
	return p
}

// Handle runs one call. An error is a failure the caller retries (the
// task treats it as not published); a refusal is a Result.
func (s *Signer) Handle(ctx context.Context, req Request) (Result, error) {
	if req.ProposalID == "" || req.Name == "" || len(req.Doc) == 0 {
		return Result{Status: http.StatusBadRequest, Code: CodeBadRequest}, nil
	}
	slot := req.ProposalID + "/" + req.Name

	// 1. The site's checks, before anything else.
	var prep site.Prepared
	err := s.hop(ctx, s.Deadlines.Site, func(ctx context.Context) error {
		var err error
		prep, err = s.Site.Prepare(ctx, req.ProposalID, req.Name, req.Doc, req.Sig, req.Rows, s.lead())
		return err
	})
	var rf *site.Refusal
	if errors.As(err, &rf) {
		s.log().Info("refused before signing", "proposal_id", req.ProposalID, "name", req.Name, "code", rf.Code)
		return Result{Status: rf.Status, Code: rf.Code}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("signer: prepare: %w", err)
	}
	digest := sha256.Sum256(req.Doc)

	// 2. The claim: this slot is this document's, or nothing is signed.
	c, err := s.claim(ctx, slot, digest[:])
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(c.Digest, digest[:]) {
		s.log().Error("claim names another document", "alarm", CodeClaimConflict,
			"proposal_id", req.ProposalID, "name", req.Name)
		return Result{Status: http.StatusConflict, Code: CodeClaimConflict}, nil
	}

	// 3. Already published: the same upload again with the bundle the site
	// holds, never a new sign, so that an index a failure left undone is
	// finished, and the answer is the site's.
	if prep.Published {
		var b []byte
		err := s.hop(ctx, s.Deadlines.Site, func(ctx context.Context) error {
			var err error
			b, err = s.Site.Bundle(ctx, req.ProposalID, req.Name)
			return err
		})
		if err != nil {
			return Result{}, fmt.Errorf("signer: published bundle: %w", err)
		}
		if b != nil {
			return s.upload(ctx, req, c, b, false, true)
		}
		// Held without a bundle can't be: the site writes the document
		// last. Go on, and the upload of the same bytes fills it in.
	}
	resumed := c.Sig != nil

	// 4. The steps, each kept before the next network call.
	if c.Sig == nil {
		if c, err = s.sign(ctx, req, slot, c); err != nil {
			return Result{}, err
		}
	}
	if !c.Journaled {
		if err := s.journalSign(ctx, req, slot, c, true); err != nil {
			return Result{}, err
		}
	}
	if c.TSAToken == nil {
		var tok []byte
		if err := s.hop(ctx, s.Deadlines.TSA, func(ctx context.Context) error {
			var err error
			tok, err = s.Anchor.Timestamp(ctx, c.Sig)
			return err
		}); err != nil {
			return Result{}, fmt.Errorf("signer: timestamp: %w", err)
		}
		if c, err = s.keep(ctx, slot, c, func(ctx context.Context) error {
			return s.Claims.SetToken(ctx, slot, c.Digest, c.R, tok)
		}, func(k *Claim) bool { return k.TSAToken != nil }); err != nil {
			return Result{}, fmt.Errorf("signer: keep the token: %w", err)
		}
		if c.TSAToken == nil {
			c.TSAToken = tok
		}
	}
	if c.RekorEntry == nil {
		var entry json.RawMessage
		if err := s.hop(ctx, s.Deadlines.Rekor, func(ctx context.Context) error {
			var err error
			entry, err = s.Anchor.Enter(ctx, c.Digest, c.Sig)
			return err
		}); err != nil {
			return Result{}, fmt.Errorf("signer: rekor: %w", err)
		}
		if c, err = s.keep(ctx, slot, c, func(ctx context.Context) error {
			return s.Claims.SetEntry(ctx, slot, c.Digest, c.R, entry)
		}, func(k *Claim) bool { return k.RekorEntry != nil }); err != nil {
			return Result{}, fmt.Errorf("signer: keep the entry: %w", err)
		}
		if c.RekorEntry == nil {
			c.RekorEntry = entry
		}
	}
	bundle, err := s.Anchor.Bundle(c.Digest, c.Sig, c.TSAToken, c.RekorEntry)
	if err != nil {
		// The kept steps make no bundle (a timestamp and an entry too far
		// apart, say): every retry finds the same. The claim is stuck,
		// which only the owner's break-glass release clears (GC #7406 §1).
		s.log().Error("the kept steps make no bundle", "alarm", CodeClaimStuck,
			"proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
		return Result{}, fmt.Errorf("signer: bundle: %w", err)
	}

	// 5. The upload.
	return s.upload(ctx, req, c, bundle, resumed, false)
}

// upload posts the document with bundle and journals the site's answer.
func (s *Signer) upload(ctx context.Context, req Request, c *Claim, bundle []byte, resumed, held bool) (Result, error) {
	var status int
	var code string
	var indexed bool
	if err := s.hop(ctx, s.Deadlines.Site, func(ctx context.Context) error {
		var err error
		status, code, indexed, err = s.Site.Upload(ctx, req.ProposalID, req.Name,
			&site.Upload{Doc: req.Doc, Sig: req.Sig, Bundle: bundle, Rows: req.Rows})
		return err
	}); err != nil {
		return Result{}, fmt.Errorf("signer: upload: %w", err)
	}
	if status >= 500 || status == http.StatusTooManyRequests {
		// Not an answer on the document (the site failed, or a rate
		// limit in front of it): the caller retries, and the claim makes
		// the retry a resume.
		return Result{}, fmt.Errorf("signer: upload: the site answered %d %s", status, code)
	}
	s.complete(ctx, req, c, bundle, status, code, resumed, held)
	r := Result{Status: status, Code: code, IndexUpdated: indexed}
	if status == http.StatusOK || status == http.StatusCreated {
		r.Bundle = bundle
	}
	return r, nil
}

// claim returns the slot's claim, creating it for digest if there is none.
func (s *Signer) claim(ctx context.Context, slot string, digest []byte) (*Claim, error) {
	var c *Claim
	err := s.hop(ctx, 3*s.Deadlines.Claims, func(ctx context.Context) error {
		var err error
		if c, err = s.Claims.Get(ctx, slot); err != nil || c != nil {
			return err
		}
		switch err := s.Claims.Create(ctx, slot, digest, s.Now()); {
		case errors.Is(err, ErrExists):
			// Another call made it in between.
		case err != nil:
			return err
		}
		c, err = s.Claims.Get(ctx, slot)
		if err == nil && c == nil {
			err = errors.New("the claim is gone after its creation")
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("signer: claim: %w", err)
	}
	return c, nil
}

// reload reads the slot's claim again.
func (s *Signer) reload(ctx context.Context, slot string) (*Claim, error) {
	var c *Claim
	err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		var err error
		c, err = s.Claims.Get(ctx, slot)
		if err == nil && c == nil {
			err = errors.New("the claim is gone")
		}
		return err
	})
	return c, err
}

// sign takes the signing lease, signs the document with KMS, and keeps the
// signature in the claim and the journal before anything else happens. It
// returns the claim as it now is.
func (s *Signer) sign(ctx context.Context, req Request, slot string, c *Claim) (*Claim, error) {
	// Enough time left to sign and keep it, or nothing is signed.
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < s.Deadlines.signWindow() {
		return nil, ErrNoTime
	}
	now := s.Now()
	err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.Lease(ctx, slot, c.Digest, now.Add(s.Deadlines.signWindow()), now)
	})
	if errors.Is(err, ErrSet) {
		// Another call is signing, or has signed since we read.
		k, rerr := s.reload(ctx, slot)
		if rerr == nil && k.Sig != nil && bytes.Equal(k.Digest, c.Digest) {
			return k, nil
		}
		return nil, ErrBusy
	}
	if err != nil {
		return nil, fmt.Errorf("signer: lease: %w", err)
	}

	var digest, sig []byte
	var reqID string
	err = s.hop(ctx, s.Deadlines.Key, func(ctx context.Context) error {
		var err error
		digest, sig, err = s.Anchor.Sign(WithRequestIDSink(ctx, &reqID), req.Doc)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("signer: sign: %w", err)
	}
	if !bytes.Equal(digest, c.Digest) {
		return nil, errors.New("signer: sign: the digest isn't the claim's")
	}
	r, err := RFromDER(sig)
	if err != nil {
		return nil, fmt.Errorf("signer: sign: %w", err)
	}
	// From here the signature exists: it is kept and journaled whatever
	// happens to the call's own context.
	keepCtx := context.WithoutCancel(ctx)
	signed := &Claim{Slot: slot, Digest: c.Digest, Sig: sig, R: r, RequestID: reqID}
	if err := s.hop(keepCtx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.SetSig(ctx, slot, c.Digest, sig, r, reqID)
	}); err != nil {
		// Signed but not kept: the journal still says so (without marking
		// a claim that lacks the signature), then the call fails; a retry
		// signs again (a second sign for the digest, which the reconciler
		// reports as a notice).
		_ = s.journalSign(keepCtx, req, slot, signed, false)
		return nil, fmt.Errorf("signer: keep the signature: %w", err)
	}
	c2 := *c
	c2.Sig, c2.R, c2.RequestID = sig, r, reqID
	if err := s.journalSign(keepCtx, req, slot, &c2, true); err != nil {
		return nil, err
	}
	return &c2, nil
}

// journalSign writes the sign entry and, if mark, marks it in the claim.
func (s *Signer) journalSign(ctx context.Context, req Request, slot string, c *Claim, mark bool) error {
	e := SignEntry{KMSRequestID: c.RequestID, At: s.Now().UTC(), ProposalID: req.ProposalID, Name: req.Name,
		Digest: c.Digest, Signature: c.Sig, R: c.R}
	if err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error { return s.Journal.Sign(ctx, e) }); err != nil {
		return fmt.Errorf("signer: journal: %w", err)
	}
	if !mark {
		return nil
	}
	err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.SetJournaled(ctx, slot, c.Digest, c.R)
	})
	if err != nil && !errors.Is(err, ErrSet) { // ErrSet: another call marked it
		return fmt.Errorf("signer: mark journaled: %w", err)
	}
	c.Journaled = true
	return nil
}

// keep runs a claim write. On ErrSet (a concurrent call kept the field
// first) it reads the claim again and goes on with the kept value, if it
// is there for the same signature.
func (s *Signer) keep(ctx context.Context, slot string, c *Claim, write func(context.Context) error, isSet func(*Claim) bool) (*Claim, error) {
	err := s.hop(ctx, s.Deadlines.Claims, write)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrSet) {
		return nil, err
	}
	k, rerr := s.reload(ctx, slot)
	if rerr != nil {
		return nil, rerr
	}
	if !bytes.Equal(k.Digest, c.Digest) || !bytes.Equal(k.R, c.R) || !isSet(k) {
		return nil, err
	}
	return k, nil
}

// complete writes the completion entry. A failure is logged, not
// returned: the document's fate is the site's answer, and the reconciler
// finds a sign without a completion by its publication.
func (s *Signer) complete(ctx context.Context, req Request, c *Claim, bundle []byte, status int, code string, resumed, held bool) {
	e := CompletionEntry{At: s.Now().UTC(), ProposalID: req.ProposalID, Name: req.Name, Digest: c.Digest, R: c.R,
		SiteStatus: status, SiteCode: code, Resumed: resumed, AlreadyHeld: held}
	if tsa, integrated, idx, err := s.Site.Times(bundle, req.Doc, s.Anchor.PublicKeyDER()); err == nil {
		e.TSATime, e.Integrated, e.RekorIndex = tsa.UTC(), integrated.UTC(), idx
	} else {
		s.log().Warn("bundle times", "proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
	}
	if err := s.hop(context.WithoutCancel(ctx), s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Journal.Complete(ctx, e)
	}); err != nil {
		s.log().Error("journal completion", "proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
	}
}

// hop runs f under its own deadline within ctx's.
func (s *Signer) hop(ctx context.Context, d time.Duration, f func(context.Context) error) error {
	if d <= 0 {
		return f(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return f(ctx)
}

func (s *Signer) lead() time.Duration {
	if s.Lead > 0 {
		return s.Lead
	}
	return DefaultLead
}

func (s *Signer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// RFromDER is an ASN.1 DER ECDSA signature's r, big-endian without
// leading zeros (GC #7406 §2).
func RFromDER(sig []byte) ([]byte, error) {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 {
		return nil, errors.New("not a DER ECDSA signature")
	}
	return v.R.Bytes(), nil
}
