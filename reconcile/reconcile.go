// Package reconcile is the AnchorSigner's reconciler (key protection, the
// design of record's §6): an hourly, read-only pass that accounts for
// every sign. It holds no keys and changes nothing. It reads the signer's
// journal, KMS's own record of Sign calls (the trail), the claim table
// (the long-term record of each slot's kept signature and its KMS request
// id), what the votes site holds, the anchor key and the signer function,
// and reports what it can't account for.
//
// Run is pure: the reading is the adapters' (cmd/anchor-reconciler).
// What it can't confirm it reports: an input it wasn't given is never
// taken as fine.
//
// Times: nothing the signer role writes gates a check. A sign's age is
// KMS's own time for its request id, else the entry's ingestion time;
// the entry's At is only compared with them. The one role-set time left is
// a log event's timestamp, which decides which runs read an entry at all:
// moving it can only shift findings between runs (a KMS Sign seen without
// its entry is unattributed_sign), never remove them. Don't start trusting
// it.
package reconcile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/vettid/votes/signer"
)

// Rules: an alarm is a security alarm; a notice is reported, not alarmed.
const (
	// RuleUnattributed: a KMS Sign the journal doesn't account for: no
	// sign entry of its request id, another key, principal, algorithm or
	// message type. A Sign a note of its request id names (the outcome
	// unknown, or a signature not kept), or one inside a sign_intent's
	// lease whose attempt has no sign entry (each intent excusing one), is
	// a notice.
	RuleUnattributed = "unattributed_sign"
	// RuleSignRefused: a failed Sign by another principal than the signer
	// role: a probe (notice).
	RuleSignRefused = "sign_refused"
	// RuleTrailMissing: a journaled sign with no KMS Sign of its request
	// id in the trail, once the trail has had time to deliver it.
	RuleTrailMissing = "trail_missing"
	// RuleTrailDelivery: the trail isn't logging, or isn't delivering to
	// its log group.
	RuleTrailDelivery = "trail_delivery"
	// RuleJournalConflict: journal entries that disagree with each other
	// or with the claim: one request id for two signatures, one signature
	// under two request ids, a kept signature journaled under another
	// request id than the claim's, a sign for another digest than the
	// slot's claim. A copied or forged entry.
	RuleJournalConflict = "journal_conflict"
	// RuleUnclaimed: a journaled sign for a slot with no claim.
	RuleUnclaimed = "unclaimed_sign"
	// RuleUnkept: a journaled sign for a claim that holds no signature, an
	// hour on: a live anchor signature that will never be published.
	RuleUnkept = "unkept_sign"
	// RuleSignatureMismatch: a journaled signature that doesn't verify
	// under the anchor key, or whose r isn't the journaled r; a site bundle
	// that doesn't verify, or whose signature isn't its slot's claim's.
	RuleSignatureMismatch = "signature_mismatch"
	// RuleUnpublished: a kept sign with no published document holding it,
	// an hour on. An extension the site refused as too_late, its lateness
	// verified, is a notice.
	RuleUnpublished = "unpublished_sign"
	// RuleSecondSign: another signature (another r) for a digest already
	// signed, not kept: a notice, one per extra r.
	RuleSecondSign = "second_sign"
	// RuleKeyDrift: the alias doesn't resolve to the compiled anchor key,
	// or the key isn't the compiled public key.
	RuleKeyDrift = "key_drift"
	// RuleCodeDrift and RulePolicyDrift: the signer function's code,
	// versions or aliases, or its resource policy, aren't the release's.
	RuleCodeDrift   = "code_drift"
	RulePolicyDrift = "policy_drift"
	// RuleIncomplete: an input the pass needs couldn't be read; nothing
	// it would have checked is taken as fine.
	RuleIncomplete = "reconcile_incomplete"
)

// Severity of a finding.
type Severity string

const (
	Alarm  Severity = "alarm"
	Notice Severity = "notice"
)

// Finding is one thing the pass can't account for. It carries ids,
// hashes and codes only.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	// Slot is proposal_id/name, when the finding is about one.
	Slot      string `json:"slot,omitempty"`
	Digest    string `json:"digest,omitempty"` // hex
	R         string `json:"r,omitempty"`      // hex
	RequestID string `json:"kms_request_id,omitempty"`
	Detail    string `json:"detail"`
	// Acknowledged: listed in the acknowledged signs (reported, not alarmed).
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// KMSSign is one KMS Sign call, from the trail.
type KMSSign struct {
	RequestID   string
	At          time.Time
	KeyARN      string // the resource's ARN
	Principal   string // the session issuer's role ARN, or the caller's ARN
	Algorithm   string // requestParameters.signingAlgorithm
	MessageType string // requestParameters.messageType
	ErrorCode   string // set: the call failed, and signed nothing
}

// Claim is a slot's claim, as read: Exists false for a slot with none.
type Claim struct {
	Exists    bool
	Digest    []byte
	Sig       []byte // the kept signature, if any
	R         []byte
	RequestID string
}

// Published is what the site holds for a slot.
type Published struct {
	Held bool
	// Signature is the held bundle's message signature, as verified by
	// the adapter under the anchor key; VerifyErr when it didn't verify.
	Signature []byte
	VerifyErr string
}

// Release is the signer function as deployed, against its release record.
type Release struct {
	WantCodeSha256, GotCodeSha256 string
	WantPolicy, GotPolicy         string // the resource policy, canonical JSON
	// Versions and Aliases other than $LATEST: a release has none.
	Versions, Aliases []string
}

// Acknowledgement excuses one finding (by rule, slot, digest and r), listed
// in the reviewed file monitor/acknowledged-signs-<env>.json.
type Acknowledgement struct {
	Rule   string `json:"rule"`
	Slot   string `json:"slot"`
	Digest string `json:"digest"` // hex
	R      string `json:"r"`      // hex; "" for a finding with none
	Reason string `json:"reason"`
}

// Input is everything one pass reads.
type Input struct {
	Now time.Time
	// From..To is the period of the journal and the trail read. Signs in
	// the trail after To-TrailLag, and journal signs before From+TrailLag,
	// are left for the pass that sees both sides.
	From, To time.Time
	// TrailLag is how long the trail may take to show a call.
	TrailLag time.Duration

	Signs []signer.SignEntry
	// Ingested is each sign entry's ingestion time (by SignKey), set by
	// CloudWatch Logs: the entry's own At is the writer's, and the writer
	// is the role the pass watches.
	Ingested    map[string]time.Time
	Completions []signer.CompletionEntry
	Notes       []signer.NoteEntry
	KMSSigns    []KMSSign
	// KeyARN is the anchor key (compiled in); SignerRole the signer role.
	KeyARN, SignerRole string
	// AnchorSPKI is the anchor key (DER SubjectPublicKeyInfo).
	AnchorSPKI []byte
	// Claims holds the claim of every slot in the journal and on the site;
	// a slot missing from it was not read.
	Claims map[string]Claim
	// Published holds what the site holds, for every slot in the journal
	// and every slot the site holds; a slot missing from it was not read.
	Published map[string]Published
	// LateVerified lists slots whose too_late refusal the adapter verified
	// (its bundle time at or after the close).
	LateVerified map[string]bool
	Release      *Release // nil: not read
	// KeyProblem and TrailProblem: what the adapter found wrong with the
	// key (the alias, the public key) or the trail's delivery.
	KeyProblem, TrailProblem string
	Acks                     []Acknowledgement
	// Incomplete names inputs that couldn't be read.
	Incomplete []string
}

// SignKey names one sign entry: its request id and signature.
func SignKey(s signer.SignEntry) string {
	return s.KMSRequestID + "/" + hex.EncodeToString(s.Signature)
}

// ClockSkew is how far a sign entry's At may be from KMS's own time for
// its request id (or from now, ahead of it) before it's a conflict.
const ClockSkew = 5 * time.Minute

// UnpublishedAfter is how long a kept sign may wait for its publication
// (the design of record, §6).
const UnpublishedAfter = time.Hour

// LostAnswerSeverity is how a KMS Sign with no journal sign entry is
// reported when a note of its attempt explains it and its slot's claim
// bears the note out (an answer lost): the trail doesn't record what was
// signed, and the note is written by the role the pass watches, so it
// stays an alarm until the owner acknowledges it (the owner's decision,
// GC #8202).
const LostAnswerSeverity = Alarm

// Run checks one pass's input and returns its findings, sorted.
func Run(in Input) []Finding {
	var out []Finding
	add := func(f Finding) { out = append(out, f) }
	h := hex.EncodeToString
	for _, what := range in.Incomplete {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "could not read " + what})
	}
	if in.KeyProblem != "" {
		add(Finding{Rule: RuleKeyDrift, Severity: Alarm, Detail: in.KeyProblem})
	}
	if in.TrailProblem != "" {
		add(Finding{Rule: RuleTrailDelivery, Severity: Alarm, Detail: in.TrailProblem})
	}
	pub, err := anchorKey(in.AnchorSPKI)
	if err != nil {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "the anchor key: " + err.Error()})
	}

	// The journal's signs, each distinct entry once; then the entries'
	// agreement with each other and with the claims.
	type ident struct{ id, digest, r, sig string }
	var signs []signer.SignEntry
	seen := map[ident]bool{}
	for _, s := range in.Signs {
		k := ident{s.KMSRequestID, h(s.Digest), h(s.R), h(s.Signature)}
		if !seen[k] {
			seen[k] = true
			signs = append(signs, s)
		}
	}
	byID := map[string][]signer.SignEntry{}
	byDR := map[string][]signer.SignEntry{}
	for _, s := range signs {
		slot := s.ProposalID + "/" + s.Name
		byID[s.KMSRequestID] = append(byID[s.KMSRequestID], s)
		dr := h(s.Digest) + "/" + h(s.R)
		byDR[dr] = append(byDR[dr], s)
		if s.KMSRequestID == "" {
			add(Finding{Rule: RuleJournalConflict, Severity: Alarm, Slot: slot, Digest: h(s.Digest), R: h(s.R), Detail: "a sign entry with no request id"})
		}
		if pub != nil {
			if err := verifySign(pub, s); err != nil {
				add(Finding{Rule: RuleSignatureMismatch, Severity: Alarm, Slot: slot, Digest: h(s.Digest), R: h(s.R), RequestID: s.KMSRequestID,
					Detail: "the journaled signature: " + err.Error()})
			}
		}
	}
	for _, id := range sortedKeys(byID) {
		if es := byID[id]; id != "" && len(es) > 1 {
			add(Finding{Rule: RuleJournalConflict, Severity: Alarm, Slot: es[0].ProposalID + "/" + es[0].Name, RequestID: id,
				Detail: fmt.Sprintf("one request id journaled for %d signatures", len(es))})
		}
	}
	for _, dr := range sortedKeys(byDR) {
		if es := byDR[dr]; len(es) > 1 {
			add(Finding{Rule: RuleJournalConflict, Severity: Alarm, Slot: es[0].ProposalID + "/" + es[0].Name, Digest: h(es[0].Digest), R: h(es[0].R),
				Detail: fmt.Sprintf("one signature journaled %d ways (request ids or signatures differ)", len(es))})
		}
	}

	// Each sign's time, from what the signer role can't write: KMS's own
	// time for its request id, else the entry's ingestion time. Its At must
	// agree, and isn't ahead of now: a forward-dated entry would otherwise
	// put off every age check.
	kmsAt := map[string]time.Time{}
	for _, k := range in.KMSSigns {
		if k.ErrorCode == "" {
			kmsAt[k.RequestID] = k.At
		}
	}
	signedAt := func(s signer.SignEntry) (time.Time, bool) {
		if t, ok := kmsAt[s.KMSRequestID]; ok {
			return t, true
		}
		t, ok := in.Ingested[SignKey(s)]
		return t, ok && !t.IsZero()
	}
	for _, s := range signs {
		f := Finding{Rule: RuleJournalConflict, Severity: Alarm, Slot: s.ProposalID + "/" + s.Name, Digest: h(s.Digest), R: h(s.R), RequestID: s.KMSRequestID}
		if t, ok := kmsAt[s.KMSRequestID]; ok && (s.At.Sub(t) > ClockSkew || t.Sub(s.At) > ClockSkew) {
			f.Detail = fmt.Sprintf("a sign entry dated %s, its KMS Sign at %s", s.At.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
			add(f)
		} else if s.At.Sub(in.Now) > ClockSkew {
			f.Detail = "a sign entry dated ahead of now"
			add(f)
		}
		if _, ok := signedAt(s); !ok {
			add(Finding{Rule: RuleIncomplete, Severity: Alarm, Slot: f.Slot, RequestID: s.KMSRequestID, Detail: "no trusted time for a sign entry (neither KMS's nor its ingestion's)"})
		}
	}
	age := func(s signer.SignEntry) time.Duration {
		if t, ok := signedAt(s); ok {
			return in.Now.Sub(t)
		}
		return in.Now.Sub(s.At) // reported incomplete above
	}

	// Each sign against its slot's claim, the long-term record: the kept
	// signature must be journaled under the claim's request id; any sign
	// is for the claim's digest.
	kept := map[string]bool{}        // h(signature) of journaled signs that are their slot's kept one
	secondNoted := map[string]bool{} // slot/r already reported as a second sign
	for _, s := range signs {
		slot := s.ProposalID + "/" + s.Name
		f := Finding{Slot: slot, Digest: h(s.Digest), R: h(s.R), RequestID: s.KMSRequestID}
		c, read := in.Claims[slot]
		switch {
		case !read:
			f.Rule, f.Severity, f.Detail = RuleIncomplete, Alarm, "the claim of a journaled slot was not read"
		case !c.Exists:
			f.Rule, f.Severity, f.Detail = RuleUnclaimed, Alarm, "a journaled sign for a slot with no claim"
		case !bytes.Equal(c.Digest, s.Digest):
			f.Rule, f.Severity, f.Detail = RuleJournalConflict, Alarm, "a sign for another digest than the slot's claim"
		case bytes.Equal(c.R, s.R) && (c.RequestID != s.KMSRequestID || !bytes.Equal(c.Sig, s.Signature)):
			f.Rule, f.Severity, f.Detail = RuleJournalConflict, Alarm, "the kept signature journaled under another request id or signature than the claim's"
		case bytes.Equal(c.R, s.R):
			kept[h(s.Signature)] = true
			continue
		case len(c.Sig) > 0:
			// The slot kept another signature of this digest: this one is a
			// second sign, reported from the claim (whatever the period),
			// once per slot and r.
			if k := slot + "/" + h(s.R); !secondNoted[k] {
				secondNoted[k] = true
				f.Rule, f.Severity, f.Detail = RuleSecondSign, Notice, "a signature of the slot's digest other than the one its claim kept"
				break
			}
			continue
		case age(s) >= UnpublishedAfter:
			// A claim holding no signature an hour after a sign: the sign was
			// never kept, and never will be published. It's a live anchor
			// signature nobody accounts for.
			f.Rule, f.Severity, f.Detail = RuleUnkept, Alarm, "a sign for a claim that holds no signature, an hour on"
		default:
			continue
		}
		add(f)
	}

	// unattributed_sign: every KMS Sign accounted for, one to one.
	settled := in.To.Add(-in.TrailLag)
	attemptSigned := map[string]bool{}
	for _, s := range signs {
		if s.AttemptID != "" {
			attemptSigned[s.AttemptID] = true
		}
	}
	usedNote := map[int]bool{}
	for _, k := range in.KMSSigns {
		if k.At.After(settled) {
			continue
		}
		if k.ErrorCode != "" {
			if k.Principal != in.SignerRole {
				add(Finding{Rule: RuleSignRefused, Severity: Notice, RequestID: k.RequestID, Detail: "a refused Sign by another principal than the signer: " + k.ErrorCode})
			}
			continue
		}
		f := Finding{Rule: RuleUnattributed, Severity: Alarm, RequestID: k.RequestID}
		switch {
		case k.KeyARN != in.KeyARN:
			f.Detail = "a Sign on another key than the anchor key"
		case k.Principal != in.SignerRole:
			f.Detail = "a Sign by another principal than the signer role"
		case k.Algorithm != "ECDSA_SHA_256" || k.MessageType != "DIGEST":
			f.Detail = fmt.Sprintf("a Sign with %s/%s", k.Algorithm, k.MessageType)
		case len(byID[k.RequestID]) > 0:
			continue
		default:
			i, ok := noteNaming(in.Notes, k.RequestID, usedNote)
			how := ""
			if ok {
				how = "its call journaled it as " + in.Notes[i].Kind
			} else if i, ok = loneIntent(in.Notes, k.At, attemptSigned, usedNote); ok {
				how = "inside a sign_intent's lease whose attempt has no sign entry"
			}
			if !ok {
				f.Detail = "a Sign with no journal entry"
				break
			}
			n := in.Notes[i]
			useAttempt(in.Notes, n, usedNote, i)
			f.Slot, f.Digest = n.ProposalID+"/"+n.Name, h(n.Digest)
			// A note is written by the role the pass watches, so it's taken
			// only as far as the claim bears it out: the note's slot has a
			// claim, for the note's digest. Even then the trail doesn't say
			// what was signed, so the Sign is reported at LostAnswerSeverity.
			c, read := in.Claims[f.Slot]
			switch {
			case !read:
				f.Rule, f.Detail = RuleIncomplete, "the claim of a note's slot was not read"
			case !c.Exists || !bytes.Equal(c.Digest, n.Digest):
				f.Detail = "a Sign a note explains, for a slot whose claim doesn't bear the note out (" + how + ")"
			case n.Kind == signer.NoteUnkept && (pub == nil || len(n.Signature) == 0 || !ecdsa.VerifyASN1(pub, c.Digest, n.Signature)):
				f.Rule, f.Detail = RuleSignatureMismatch, "a signature journaled as not kept that doesn't verify over its slot's digest"
			default:
				f.Severity = LostAnswerSeverity
				f.Detail = "a Sign the journal has no entry for, " + how + " (an answer lost): what it signed isn't known"
			}
		}
		add(f)
	}

	// trail_missing: every journaled sign in the trail.
	kmsByID := map[string]bool{}
	for _, k := range in.KMSSigns {
		if k.ErrorCode == "" {
			kmsByID[k.RequestID] = true
		}
	}
	trailFrom := in.From.Add(in.TrailLag)
	for _, s := range signs {
		// The window by the entry's ingestion (the writer can't set it); an
		// entry without one is checked, never skipped on its own At.
		if kmsByID[s.KMSRequestID] {
			continue
		}
		if t, ok := in.Ingested[SignKey(s)]; ok && (t.Before(trailFrom) || t.After(settled)) {
			continue
		}
		add(Finding{Rule: RuleTrailMissing, Severity: Alarm, Slot: s.ProposalID + "/" + s.Name,
			Digest: h(s.Digest), R: h(s.R), RequestID: s.KMSRequestID, Detail: "a journaled sign the trail doesn't show"})
	}

	// unpublished_sign: each kept sign, an hour on, held by the site.
	for _, s := range signs {
		slot := s.ProposalID + "/" + s.Name
		if !kept[h(s.Signature)] || age(s) < UnpublishedAfter {
			continue
		}
		p, read := in.Published[slot]
		if !read {
			add(Finding{Rule: RuleIncomplete, Severity: Alarm, Slot: slot, Detail: "the site's holding for a journaled slot was not read"})
			continue
		}
		if p.Held && bytes.Equal(p.Signature, s.Signature) {
			continue
		}
		f := Finding{Rule: RuleUnpublished, Severity: Alarm, Slot: slot, Digest: h(s.Digest), R: h(s.R), RequestID: s.KMSRequestID,
			Detail: "a kept sign with no published document holding it"}
		if tooLate(in.Completions, s) && in.LateVerified[slot] {
			f.Severity, f.Detail = Notice, "an extension the site refused as too_late, its lateness verified"
		}
		add(f)
	}

	// Every bundle the site holds: verified, and its slot's kept signature.
	for _, slot := range sortedKeys(in.Published) {
		p := in.Published[slot]
		if !p.Held {
			continue
		}
		f := Finding{Rule: RuleSignatureMismatch, Severity: Alarm, Slot: slot}
		c, read := in.Claims[slot]
		switch {
		case p.VerifyErr != "":
			f.Detail = "the site's bundle doesn't verify: " + p.VerifyErr
		case !read:
			f.Rule, f.Detail = RuleIncomplete, "the claim of a slot the site holds was not read"
		case !c.Exists || !bytes.Equal(c.Sig, p.Signature):
			f.Detail = "the site's bundle signature isn't its slot's kept signature"
			if c.Exists {
				f.Digest, f.R = h(c.Digest), h(c.R)
			}
		default:
			continue
		}
		add(f)
	}

	// The function as released.
	if in.Release == nil {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "the signer function's code and policy were not read"})
	} else {
		r := in.Release
		if r.WantCodeSha256 == "" || r.GotCodeSha256 != r.WantCodeSha256 {
			add(Finding{Rule: RuleCodeDrift, Severity: Alarm, Detail: "CodeSha256 " + r.GotCodeSha256 + ", not the release's " + r.WantCodeSha256})
		}
		if len(r.Versions) > 0 || len(r.Aliases) > 0 {
			add(Finding{Rule: RuleCodeDrift, Severity: Alarm, Detail: fmt.Sprintf("the function has versions %v and aliases %v; a release has none", r.Versions, r.Aliases)})
		}
		if r.WantPolicy == "" || r.GotPolicy != r.WantPolicy {
			add(Finding{Rule: RulePolicyDrift, Severity: Alarm, Detail: "the function's resource policy isn't the release's"})
		}
	}

	acknowledge(out, in.Acks)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Slot != b.Slot {
			return a.Slot < b.Slot
		}
		return a.RequestID < b.RequestID
	})
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// noteNaming finds an unused sign_outcome_unknown or sign_unkept note of
// the request id.
func noteNaming(notes []signer.NoteEntry, id string, used map[int]bool) (int, bool) {
	for i, n := range notes {
		if !used[i] && id != "" && n.KMSRequestID == id && (n.Kind == signer.NoteOutcomeUnknown || n.Kind == signer.NoteUnkept) {
			return i, true
		}
	}
	return 0, false
}

// useAttempt marks a note used, and every note of its attempt: one
// attempt excuses one Sign.
func useAttempt(notes []signer.NoteEntry, n signer.NoteEntry, used map[int]bool, i int) {
	used[i] = true
	if n.AttemptID == "" {
		return
	}
	for j, o := range notes {
		if o.AttemptID == n.AttemptID {
			used[j] = true
		}
	}
}

// loneIntent finds an unused sign_intent whose lease window holds t and
// whose attempt has no sign entry.
func loneIntent(notes []signer.NoteEntry, t time.Time, attemptSigned map[string]bool, used map[int]bool) (int, bool) {
	for i, n := range notes {
		if !used[i] && n.Kind == signer.NoteIntent && n.AttemptID != "" && !attemptSigned[n.AttemptID] &&
			!t.Before(n.At) && !t.After(n.LeaseUntil) {
			return i, true
		}
	}
	return 0, false
}

// tooLate reports whether the sign's call ended with the site refusing it
// as too_late.
func tooLate(cs []signer.CompletionEntry, s signer.SignEntry) bool {
	for _, c := range cs {
		if c.ProposalID == s.ProposalID && c.Name == s.Name && bytes.Equal(c.Digest, s.Digest) &&
			bytes.Equal(c.R, s.R) && c.SiteCode == "too_late" {
			return true
		}
	}
	return false
}

func anchorKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 {
		return nil, errors.New("not read")
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return pub, nil
}

// verifySign checks a journaled signature over its digest, and that r is
// its r (big-endian, no leading zeros).
func verifySign(pub *ecdsa.PublicKey, s signer.SignEntry) error {
	if len(s.Digest) != 32 {
		return errors.New("the digest isn't 32 bytes")
	}
	if !ecdsa.VerifyASN1(pub, s.Digest, s.Signature) {
		return errors.New("doesn't verify under the anchor key")
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(s.Signature, &sig); err != nil || len(rest) != 0 {
		return errors.New("isn't one DER signature")
	}
	if !bytes.Equal(sig.R.Bytes(), s.R) {
		return errors.New("its r isn't the journaled r")
	}
	return nil
}

// acknowledge marks the findings an acknowledgement lists (rule, slot,
// digest and r all equal): they stay in the report, as notices.
func acknowledge(fs []Finding, acks []Acknowledgement) {
	for i := range fs {
		for _, a := range acks {
			if a.Slot != "" && a.Rule == fs[i].Rule && a.Slot == fs[i].Slot && a.Digest == fs[i].Digest && a.R == fs[i].R {
				fs[i].Acknowledged, fs[i].Severity = true, Notice
			}
		}
	}
}
