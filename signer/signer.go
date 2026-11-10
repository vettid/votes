// Package signer is the AnchorSigner function's logic (key protection,
// phase 1, GC #7406 §1–§3): it anchors one vote document under the
// service's anchor key, which only this function may use, and publishes
// it on the votes site. It signs only what it publishes: a document the
// site's own checks accept (site.Prepare), under a key the service lists,
// for a slot whose claim names that document's digest.
//
// Each step's result is kept in the claim before the next network call
// (the signature, then the RFC 3161 token, then the Rekor entry), so a
// retry resumes and never signs again. A short lease in the claim keeps
// two calls for one slot from both signing. A kept token too old to pair
// with an entry is replaced by a fresh one for the same signature (at most
// once in a call) before the entry is asked for, and a token an entry was
// integrated too late for is replaced right after it: a timestamp, never a
// second sign.
package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"sync/atomic"
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
	// AnchorKey is the anchor key's SubjectPublicKeyInfo, on every answer:
	// the service lists it (with its certificate) without reading the key
	// itself (GC #7648 item 3).
	AnchorKey []byte `json:"anchor_key"`
}

// Claim is a slot's record (GC #7406 §2): created once for a digest, each
// artifact set once (the token replaced at most while no entry may exist).
type Claim struct {
	Slot           string
	Digest         []byte
	LeaseUntil     time.Time // a call is signing until then
	LeaseOwner     string    // that call's attempt id
	Sig            []byte    // ASN.1 DER ECDSA signature
	R              []byte    // its r, big-endian, without leading zeros
	RequestID      string    // KMS's request id for the Sign
	Journaled      bool      // the sign entry is in the journal
	TSAToken       []byte    // RFC 3161 TimeStampResp
	EnterAttempted bool      // an entry may exist in Rekor: the token is never replaced after
	RekorEntry     json.RawMessage
	Created        time.Time
}

// Claim store errors.
var (
	// ErrExists: Create found a claim for the slot.
	ErrExists = errors.New("signer: claim exists")
	// ErrSet: a write's condition failed (the field set already, a live
	// lease, another digest or r, or no claim).
	ErrSet = errors.New("signer: claim condition failed")
)

// KeyMismatchError is a signature that doesn't verify under the anchor
// key read at start: the key behind the alias changed. It is journaled
// (sign_unkept, with the signature), it alarms (key_mismatch), and the
// process signs nothing more.
type KeyMismatchError struct{ Sig []byte }

func (e *KeyMismatchError) Error() string {
	return "signer: the signature doesn't verify under the anchor key read at start"
}

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
	// Lease sets the signing lease to until for owner, only if the claim
	// names digest, has no signature, and has no lease live at now.
	Lease(ctx context.Context, slot string, digest []byte, owner string, until, now time.Time) error
	// SetSig sets the signature, its r and KMS's request id, only if the
	// claim names digest, has no signature, and its lease is owner's: the
	// kept signature is always the lease holder's.
	SetSig(ctx context.Context, slot string, digest, sig, r []byte, requestID, owner string) error
	// SetJournaled, SetToken, SetEnterAttempted and SetEntry set one
	// artifact each, only if it is unset and the claim names digest and r:
	// never on another attempt's signature.
	SetJournaled(ctx context.Context, slot string, digest, r []byte) error
	SetToken(ctx context.Context, slot string, digest, r, token []byte) error
	SetEnterAttempted(ctx context.Context, slot string, digest, r []byte) error
	SetEntry(ctx context.Context, slot string, digest, r []byte, entry json.RawMessage) error
	// ReplaceToken puts token in place of old, only if the claim names
	// digest and r, holds old, and has neither an entry nor an attempt at
	// one.
	ReplaceToken(ctx context.Context, slot string, digest, r, old, token []byte) error
	// ReplaceLateToken puts token in place of old, only if the claim names
	// digest and r, holds old, and holds exactly entry: an entry that was
	// integrated too late for old.
	ReplaceLateToken(ctx context.Context, slot string, digest, r, old []byte, entry json.RawMessage, token []byte) error
}

// SignEntry is the journal's record of a sign (GC #7406 §3): ids, hashes
// and codes only, never text from the input. A sign may be journaled more
// than once (a retry after a lost mark); the reconciler counts it by
// (digest, r).
type SignEntry struct {
	KMSRequestID string    `json:"kms_request_id"`
	AttemptID    string    `json:"attempt_id,omitempty"`
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

// Note kinds.
const (
	// NoteIntent is written before every KMS Sign: a CloudTrail Sign in
	// its lease window with no sign entry (an answer lost) is a notice for
	// the reconciler, not an unattributed sign.
	NoteIntent = "sign_intent"
	// NoteOutcomeUnknown: the Sign call failed in a way that doesn't say
	// whether KMS signed.
	NoteOutcomeUnknown = "sign_outcome_unknown"
	// NoteUnkept: a signature KMS gave that the claim doesn't hold (it
	// didn't verify as the claim's, or wasn't kept).
	NoteUnkept = "sign_unkept"
	// NoteRetimestamp: the kept token was replaced by a fresh one for the
	// same signature.
	NoteRetimestamp = "retimestamp"
)

// NoteEntry is the journal's record of anything else about a sign.
type NoteEntry struct {
	Kind         string    `json:"note"`
	At           time.Time `json:"at"`
	ProposalID   string    `json:"proposal_id"`
	Name         string    `json:"name"`
	Digest       []byte    `json:"digest"`
	AttemptID    string    `json:"attempt_id,omitempty"`
	LeaseUntil   time.Time `json:"lease_until,omitzero"`
	KMSRequestID string    `json:"kms_request_id,omitempty"`
	Signature    []byte    `json:"signature,omitempty"`
	R            []byte    `json:"r,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	OldTSATime   time.Time `json:"old_tsa_time,omitzero"`
	NewTSATime   time.Time `json:"new_tsa_time,omitzero"`
}

// Journal is the signer's append-only log.
type Journal interface {
	Sign(ctx context.Context, e SignEntry) error
	Complete(ctx context.Context, e CompletionEntry) error
	Note(ctx context.Context, e NoteEntry) error
}

// Anchor is the anchoring steps (service-vault's anchor.Anchorer, with a
// KMS-backed DigestSigner). Sign checks the signature against the anchor
// key before it returns. Enter must be safe to call again for the same
// signature: when Rekor already holds the entry (a retry after the entry
// wasn't kept), it returns that entry, or a slot could never go on.
// TokenTime reads a token's time (its genTime), unverified: it decides
// only whether to ask for a fresh one.
type Anchor interface {
	Sign(ctx context.Context, doc []byte) (digest, sig []byte, err error)
	Timestamp(ctx context.Context, sig []byte) ([]byte, error)
	TokenTime(token []byte) (time.Time, error)
	// EntryTime reads an entry's Rekor integrated time, unverified.
	EntryTime(entry json.RawMessage) (time.Time, error)
	Enter(ctx context.Context, digest, sig []byte) (json.RawMessage, error)
	Bundle(digest, sig, ts []byte, entry json.RawMessage) (json.RawMessage, error)
	PublicKeyDER() []byte
}

// Site is the votes site as the signer sees it.
type Site interface {
	// Prepare runs the upload's checks without an anchor (site.Prepare).
	Prepare(ctx context.Context, id, name string, doc, sig, rows []byte, opts site.PrepareOptions) (site.Prepared, error)
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
	// Margin is kept back for the writes after a sign, and at the end.
	Margin time.Duration
}

// Worst is the longest a call can take with every hop at its deadline. A
// call asks the TSA at most twice: a token it takes itself is never stale
// or late in the same call (an entry it gets is integrated within the
// call), so a call makes at most one of the stale and late replacements,
// each a TSA call, a conditional write and a note, which the counts below
// cover.
func (d Deadlines) Worst() time.Duration {
	return 3*d.Site + // Prepare, the held bundle, the upload
		17*d.Claims + // the first read, the claim (3), the lease and its reload, the intent, keeping, journaling and marking the sign, the token, its replacement and note, the attempt mark, the entry, two reloads, the completion
		d.Key + 2*d.TSA + d.Rekor + d.Margin
}

// Lead is how much later than the time it reads a document is taken to
// be anchored when nothing is kept yet: Prepare itself, the claim, the
// lease, the intent, the sign and its keeping, and the TSA, at their
// deadlines, with the margin.
func (d Deadlines) Lead() time.Duration {
	return d.Site + 9*d.Claims + d.Key + d.TSA + d.Margin
}

// toMark is the longest from the first read to the entry attempt mark
// when a token is kept: Prepare, the claim, journaling a kept signature,
// and replacing the token.
func (d Deadlines) toMark() time.Duration {
	return d.Site + 6*d.Claims + d.TSA + d.Margin
}

// lateWindow is how soon after an entry's integration a fresh token must
// be for the pair to make a bundle (service-vault anchor: the entry at
// most 60 s before the token).
const lateWindow = 60 * time.Second

// RetimestampAfter is the age past which a kept token is replaced before
// the entry is asked for: an entry integrated more than 600 s after the
// token makes no bundle (service-vault anchor, the −60..600 s window), and
// the attempt mark, Rekor, the keeping and a reload come between, with the
// margin and a 30 s guard for the clocks.
func (d Deadlines) RetimestampAfter() time.Duration {
	return 600*time.Second - d.Rekor - 3*d.Claims - d.Margin - 30*time.Second
}

// signWindow is how much of the call's time a sign needs: the intent, the
// KMS call and keeping its result, with the margin.
func (d Deadlines) signWindow() time.Duration { return d.Key + 4*d.Claims + d.Margin }

// DefaultDeadlines fit the function's 120 s timeout (Worst is under it,
// with the second the runtime keeps back and some slack).
var DefaultDeadlines = Deadlines{Claims: 2 * time.Second, Key: 8 * time.Second, TSA: 10 * time.Second,
	Rekor: 15 * time.Second, Site: 10 * time.Second, Margin: 5 * time.Second}

// Signer anchors and publishes documents.
type Signer struct {
	Claims    Claims
	Journal   Journal
	Anchor    Anchor
	Site      Site
	Now       func() time.Time
	Log       *slog.Logger
	Deadlines Deadlines
	// ServiceIKs are the identity keys this signer anchors for, compiled
	// into it; a document under any other is refused (unknown_service).
	// None: nothing is signed.
	ServiceIKs [][]byte

	halted atomic.Bool // a key mismatch was seen: nothing more is signed
}

// stuck alarms claim_stuck for a kept artifact that can't be read, and
// returns the error to retry: a retry finds the same, until the owner's
// break-glass release.
func (s *Signer) stuck(req Request, what string, err error) error {
	s.log().Error(what, "alarm", CodeClaimStuck, "proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
	return fmt.Errorf("signer: %s: %w", what, err)
}

// Codes the signer answers or alarms with itself.
const (
	// CodeClaimConflict: the slot's claim names another document. It is
	// never signed, and it alarms.
	CodeClaimConflict = "claim_conflict"
	// CodeBadRequest: the call itself is malformed.
	CodeBadRequest = "bad_request"
	// CodeClaimStuck: the alarm for a claim whose kept steps make no
	// bundle.
	CodeClaimStuck = "claim_stuck"
	// CodeJournalFailed: the alarm for a journal write that failed after a
	// sign.
	CodeJournalFailed = "journal_failed"
	// CodeKeyMismatch: the alarm for a signature under another key than
	// the one read at start.
	CodeKeyMismatch = "key_mismatch"
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
	r, err := s.handle(ctx, req)
	if err == nil {
		r.AnchorKey = s.Anchor.PublicKeyDER()
	}
	return r, err
}

func (s *Signer) handle(ctx context.Context, req Request) (Result, error) {
	if s.halted.Load() {
		return Result{}, errors.New("signer: halted after a key mismatch: nothing more is signed by this process")
	}
	if len(s.ServiceIKs) == 0 {
		return Result{}, errors.New("signer: no service identity keys compiled in: nothing is signed")
	}
	if req.ProposalID == "" || req.Name == "" || len(req.Doc) == 0 {
		return Result{Status: http.StatusBadRequest, Code: CodeBadRequest}, nil
	}
	slot := req.ProposalID + "/" + req.Name
	digest := sha256.Sum256(req.Doc)

	// 1. The time to judge by: a token kept for this document, which the
	// bundle will carry, or else now plus the lead.
	var pre *Claim
	if err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		var err error
		pre, err = s.Claims.Get(ctx, slot)
		return err
	}); err != nil {
		return Result{}, fmt.Errorf("signer: claim: %w", err)
	}
	// Staleness is decided here, once, for the time of the attempt mark,
	// so that Prepare and the bundle judge by the same token.
	at := s.Now().Add(s.Deadlines.Lead())
	var staleToken []byte
	if pre != nil && bytes.Equal(pre.Digest, digest[:]) && pre.TSAToken != nil {
		t, err := s.Anchor.TokenTime(pre.TSAToken)
		if err != nil {
			return Result{}, s.stuck(req, "the kept token doesn't parse", err)
		}
		late := false
		if pre.RekorEntry != nil {
			it, err := s.Anchor.EntryTime(pre.RekorEntry)
			if err != nil {
				return Result{}, s.stuck(req, "the kept entry doesn't parse", err)
			}
			late = it.Sub(t) > 600*time.Second
		}
		switch {
		case late:
			// lateEntry will take a fresh token after the checks: judge by
			// about when, so a too_late comes before any work.
			at = s.Now().Add(s.Deadlines.toMark())
		case pre.EnterAttempted || s.Now().Add(s.Deadlines.toMark()).Sub(t) < s.Deadlines.RetimestampAfter():
			at = t
		default:
			staleToken = pre.TSAToken
		}
	}

	// 2. The site's checks, under this signer's key, before anything else.
	var prep site.Prepared
	err := s.hop(ctx, s.Deadlines.Site, func(ctx context.Context) error {
		var err error
		prep, err = s.Site.Prepare(ctx, req.ProposalID, req.Name, req.Doc, req.Sig, req.Rows,
			site.PrepareOptions{At: at, AnchorKey: s.Anchor.PublicKeyDER(), ServiceIKs: s.ServiceIKs})
		return err
	})
	var rf *site.Refusal
	if errors.As(err, &rf) {
		// The request isn't known to be well-formed: its code only.
		s.log().Info("refused before signing", "code", rf.Code)
		return Result{Status: rf.Status, Code: rf.Code}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("signer: prepare: %w", err)
	}

	// 3. The claim: this slot is this document's, or nothing is signed.
	c, err := s.claim(ctx, slot, digest[:])
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(c.Digest, digest[:]) {
		s.log().Error("claim names another document", "alarm", CodeClaimConflict,
			"proposal_id", req.ProposalID, "name", req.Name)
		return Result{Status: http.StatusConflict, Code: CodeClaimConflict}, nil
	}
	// A kept signature the journal may lack is journaled before anything
	// else, whichever way the call goes.
	if c.Sig != nil && !c.Journaled {
		if err := s.journalSign(ctx, req, slot, c, true); err != nil {
			return Result{}, err
		}
	}

	// 4. Already published, or a bundle the site holds for these bytes
	// (an earlier partial upload's, which the upload would keep): the same
	// upload again with that bundle, never a sign, so that an index a
	// failure left undone is finished, and the answer is the site's.
	if prep.Published || prep.Held {
		var b []byte
		err := s.hop(ctx, s.Deadlines.Site, func(ctx context.Context) error {
			var err error
			b, err = s.Site.Bundle(ctx, req.ProposalID, req.Name)
			return err
		})
		if err != nil {
			return Result{}, fmt.Errorf("signer: held bundle: %w", err)
		}
		if b == nil {
			// The site writes the bundle before the document: a held
			// document with no bundle is a read to retry, never a reason
			// to sign.
			return Result{}, errors.New("signer: the site holds the document but no bundle was read")
		}
		return s.upload(ctx, req, c, b, false, true)
	}
	resumed := c.Sig != nil

	// 5. The steps, each kept before the next network call.
	if c.Sig == nil {
		if c, err = s.sign(ctx, req, slot, c); err != nil {
			return Result{}, err
		}
	}
	if c.TSAToken == nil {
		tok, err := s.timestamp(ctx, c.Sig)
		if err != nil {
			return Result{}, err
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
		if !c.EnterAttempted {
			if bytes.Equal(c.TSAToken, staleToken) {
				if c, err = s.retimestamp(ctx, req, slot, c); err != nil {
					return Result{}, err
				}
			}
			// From here an entry may exist for the token: it is never
			// replaced again.
			if c, err = s.keep(ctx, slot, c, func(ctx context.Context) error {
				return s.Claims.SetEnterAttempted(ctx, slot, c.Digest, c.R)
			}, func(k *Claim) bool { return k.EnterAttempted }); err != nil {
				return Result{}, fmt.Errorf("signer: mark the entry attempt: %w", err)
			}
			c.EnterAttempted = true
		}
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
	if c, err = s.lateEntry(ctx, req, slot, c); err != nil {
		return Result{}, err
	}
	bundle, err := s.Anchor.Bundle(c.Digest, c.Sig, c.TSAToken, c.RekorEntry)
	if err != nil {
		// Once more from the claim as kept (another call may have kept
		// other artifacts), then it is stuck: every retry finds the same,
		// and only the owner's break-glass release clears it (GC #7406 §1).
		if k, rerr := s.reload(ctx, slot); rerr == nil && bytes.Equal(k.Digest, c.Digest) && k.Sig != nil &&
			k.TSAToken != nil && k.RekorEntry != nil {
			bundle, err = s.Anchor.Bundle(k.Digest, k.Sig, k.TSAToken, k.RekorEntry)
			c = k
		}
		if err != nil {
			s.log().Error("the kept steps make no bundle", "alarm", CodeClaimStuck,
				"proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
			return Result{}, fmt.Errorf("signer: bundle: %w", err)
		}
	}

	// 6. The upload.
	return s.upload(ctx, req, c, bundle, resumed, false)
}

// timestamp asks the TSA for a token for sig.
func (s *Signer) timestamp(ctx context.Context, sig []byte) ([]byte, error) {
	var tok []byte
	if err := s.hop(ctx, s.Deadlines.TSA, func(ctx context.Context) error {
		var err error
		tok, err = s.Anchor.Timestamp(ctx, sig)
		return err
	}); err != nil {
		return nil, fmt.Errorf("signer: timestamp: %w", err)
	}
	return tok, nil
}

// retimestamp replaces a kept token too old to pair with an entry by a
// fresh one for the same signature, and journals it. It runs only while
// no entry may exist (no attempt mark).
func (s *Signer) retimestamp(ctx context.Context, req Request, slot string, c *Claim) (*Claim, error) {
	old, err := s.Anchor.TokenTime(c.TSAToken)
	if err != nil {
		return nil, fmt.Errorf("signer: the kept token: %w", err)
	}
	tok, err := s.timestamp(ctx, c.Sig)
	if err != nil {
		return nil, err
	}
	newT, _ := s.Anchor.TokenTime(tok)
	err = s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.ReplaceToken(ctx, slot, c.Digest, c.R, c.TSAToken, tok)
	})
	if errors.Is(err, ErrSet) {
		// Another call replaced it (or marked an attempt) first: go on
		// with the claim as it now is.
		k, rerr := s.reload(ctx, slot)
		if rerr != nil {
			return nil, rerr
		}
		if !bytes.Equal(k.Digest, c.Digest) || !bytes.Equal(k.R, c.R) {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("signer: replace the token: %w", err)
	}
	s.note(context.WithoutCancel(ctx), NoteEntry{Kind: NoteRetimestamp, Reason: "stale_token", ProposalID: req.ProposalID,
		Name: req.Name, Digest: c.Digest, R: c.R, OldTSATime: old.UTC(), NewTSATime: newT.UTC()})
	c2 := *c
	c2.TSAToken = tok
	return &c2, nil
}

// lateEntry replaces the kept token when the kept entry was integrated
// more than 600 s after it (Rekor slow, or down for a while): a fresh token
// for the same signature, taken now, pairs with the entry if it is within
// 60 s of the integration, and is kept only on the claim that holds that
// entry. Otherwise the claim is left as it is (and Bundle says so).
func (s *Signer) lateEntry(ctx context.Context, req Request, slot string, c *Claim) (*Claim, error) {
	old, err := s.Anchor.TokenTime(c.TSAToken)
	if err != nil {
		return nil, s.stuck(req, "the kept token doesn't parse", err)
	}
	integrated, err := s.Anchor.EntryTime(c.RekorEntry)
	if err != nil {
		return nil, s.stuck(req, "the kept entry doesn't parse", err)
	}
	if integrated.Sub(old) <= 600*time.Second || s.Now().Sub(integrated) > lateWindow-s.Deadlines.TSA {
		return c, nil
	}
	tok, err := s.timestamp(ctx, c.Sig)
	if err != nil {
		return nil, err
	}
	newT, err := s.Anchor.TokenTime(tok)
	if err != nil || newT.Sub(integrated) > lateWindow {
		return c, nil // too late for this one as well: Bundle refuses, and it alarms
	}
	err = s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.ReplaceLateToken(ctx, slot, c.Digest, c.R, c.TSAToken, c.RekorEntry, tok)
	})
	if errors.Is(err, ErrSet) {
		k, rerr := s.reload(ctx, slot)
		if rerr != nil {
			return nil, rerr
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("signer: replace the late token: %w", err)
	}
	s.note(context.WithoutCancel(ctx), NoteEntry{Kind: NoteRetimestamp, Reason: "late_entry", ProposalID: req.ProposalID,
		Name: req.Name, Digest: c.Digest, R: c.R, OldTSATime: old.UTC(), NewTSATime: newT.UTC()})
	c2 := *c
	c2.TSAToken = tok
	return &c2, nil
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
		// Not an answer on the document. awsio.Site already makes these
		// errors; this keeps any other Site from turning one into a final
		// answer.
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

// sign takes the signing lease, journals the intent, signs the document
// with KMS, and keeps the signature in the claim and the journal before
// anything else happens. Whatever KMS answers is journaled. It returns the
// claim as it now is.
func (s *Signer) sign(ctx context.Context, req Request, slot string, c *Claim) (*Claim, error) {
	// Enough time left to sign and keep it, or nothing is signed.
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < s.Deadlines.signWindow() {
		return nil, ErrNoTime
	}
	attempt, err := attemptID()
	if err != nil {
		return nil, err
	}
	now := s.Now()
	until := now.Add(s.Deadlines.signWindow())
	err = s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.Lease(ctx, slot, c.Digest, attempt, until, now)
	})
	if errors.Is(err, ErrSet) {
		// Another call is signing, or has signed since we read.
		k, rerr := s.reload(ctx, slot)
		switch {
		case rerr != nil:
			return nil, fmt.Errorf("signer: lease: %w", rerr)
		case k.Sig != nil && bytes.Equal(k.Digest, c.Digest):
			return k, nil
		}
		return nil, ErrBusy
	}
	if err != nil {
		return nil, fmt.Errorf("signer: lease: %w", err)
	}
	base := NoteEntry{ProposalID: req.ProposalID, Name: req.Name, Digest: c.Digest, AttemptID: attempt, LeaseUntil: until.UTC()}
	intent := base
	intent.Kind = NoteIntent
	intent.At = s.Now().UTC()
	if err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error { return s.Journal.Note(ctx, intent) }); err != nil {
		return nil, fmt.Errorf("signer: journal the intent: %w", err)
	}

	var digest, sig []byte
	var reqID string
	err = s.hop(ctx, s.Deadlines.Key, func(ctx context.Context) error {
		var err error
		digest, sig, err = s.Anchor.Sign(WithRequestIDSink(ctx, &reqID), req.Doc)
		return err
	})
	// From here KMS may have signed: what it answered is journaled, and
	// kept, whatever happens to the call's own context.
	keepCtx := context.WithoutCancel(ctx)
	var km *KeyMismatchError
	if errors.As(err, &km) {
		s.halted.Store(true)
		n := base
		n.Kind, n.KMSRequestID, n.Signature = NoteUnkept, reqID, km.Sig
		n.R, _ = RFromDER(km.Sig)
		s.note(keepCtx, n)
		s.log().Error("a signature under another key", "alarm", CodeKeyMismatch, "proposal_id", req.ProposalID,
			"name", req.Name, "kms_request_id", reqID)
		return nil, km
	}
	if err != nil {
		n := base
		n.Kind, n.KMSRequestID = NoteOutcomeUnknown, reqID
		s.note(keepCtx, n)
		return nil, fmt.Errorf("signer: sign: %w", err)
	}
	r, rerr := RFromDER(sig)
	if !bytes.Equal(digest, c.Digest) || rerr != nil {
		n := base
		n.Kind, n.KMSRequestID, n.Signature, n.R = NoteUnkept, reqID, sig, r
		s.note(keepCtx, n)
		if rerr != nil {
			return nil, fmt.Errorf("signer: sign: %w", rerr)
		}
		return nil, errors.New("signer: sign: the digest isn't the claim's")
	}
	if err := s.hop(keepCtx, s.Deadlines.Claims, func(ctx context.Context) error {
		return s.Claims.SetSig(ctx, slot, c.Digest, sig, r, reqID, attempt)
	}); err != nil {
		// Signed but not kept: the journal still counts the sign (without
		// marking a claim that lacks it), then the call fails; a retry
		// signs again (a second sign for the digest, a notice).
		_ = s.journalSign(keepCtx, req, slot, &Claim{Digest: c.Digest, Sig: sig, R: r, RequestID: reqID, LeaseOwner: attempt}, false)
		return nil, fmt.Errorf("signer: keep the signature: %w", err)
	}
	c2 := *c
	c2.Sig, c2.R, c2.RequestID, c2.LeaseOwner = sig, r, reqID, attempt
	if err := s.journalSign(keepCtx, req, slot, &c2, true); err != nil {
		return nil, err
	}
	return &c2, nil
}

// journalSign writes the sign entry and, if mark, marks it in the claim. A
// failed write alarms, with KMS's request id.
func (s *Signer) journalSign(ctx context.Context, req Request, slot string, c *Claim, mark bool) error {
	e := SignEntry{KMSRequestID: c.RequestID, AttemptID: c.LeaseOwner, At: s.Now().UTC(), ProposalID: req.ProposalID,
		Name: req.Name, Digest: c.Digest, Signature: c.Sig, R: c.R}
	if err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error { return s.Journal.Sign(ctx, e) }); err != nil {
		s.log().Error("journal the sign", "alarm", CodeJournalFailed, "proposal_id", req.ProposalID, "name", req.Name,
			"kms_request_id", c.RequestID, "err", err.Error())
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

// note writes a note; a failure alarms, and the call goes on (the note is
// evidence, not a step).
func (s *Signer) note(ctx context.Context, e NoteEntry) {
	if e.At.IsZero() {
		e.At = s.Now().UTC()
	}
	if err := s.hop(ctx, s.Deadlines.Claims, func(ctx context.Context) error { return s.Journal.Note(ctx, e) }); err != nil {
		s.log().Error("journal a note", "alarm", CodeJournalFailed, "note", e.Kind, "proposal_id", e.ProposalID,
			"name", e.Name, "kms_request_id", e.KMSRequestID, "err", err.Error())
	}
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
// finds a sign without a completion by its publication. A held bundle
// under an older listed key isn't this key's: its times are left out.
func (s *Signer) complete(ctx context.Context, req Request, c *Claim, bundle []byte, status int, code string, resumed, held bool) {
	e := CompletionEntry{At: s.Now().UTC(), ProposalID: req.ProposalID, Name: req.Name, Digest: c.Digest, R: c.R,
		SiteStatus: status, SiteCode: code, Resumed: resumed, AlreadyHeld: held}
	if tsa, integrated, idx, err := s.Site.Times(bundle, req.Doc, s.Anchor.PublicKeyDER()); err == nil {
		e.TSATime, e.Integrated, e.RekorIndex = tsa.UTC(), integrated.UTC(), idx
	} else if !held {
		s.log().Warn("bundle times", "proposal_id", req.ProposalID, "name", req.Name, "err", err.Error())
	}
	// Within the call's own time, less a margin, so that the call still
	// answers before Lambda's deadline.
	d := s.Deadlines.Claims
	if dl, ok := ctx.Deadline(); ok {
		d = min(d, time.Until(dl)-time.Second)
	}
	if d <= 0 {
		s.log().Error("journal completion: no time left", "proposal_id", req.ProposalID, "name", req.Name)
		return
	}
	if err := s.hop(context.WithoutCancel(ctx), d, func(ctx context.Context) error {
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

func (s *Signer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// attemptID names one sign attempt: the lease's owner and the journal's
// intent, sign and outcome entries.
func attemptID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
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
