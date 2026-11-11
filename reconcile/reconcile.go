// Package reconcile is the AnchorSigner's reconciler (key protection,
// docs: the design of record's §6): an hourly, read-only pass that
// accounts for every sign. It holds no keys and changes nothing; it reads
// the signer's journal, KMS's own record of Sign calls (the trail), what
// the votes site holds, and the anchor key, and reports what it can't
// account for.
//
// Run is pure: the reading is the adapters' (cmd/anchor-reconciler).
// What it can't confirm it reports: an input it wasn't given is not taken
// as fine.
package reconcile

import (
	"bytes"
	"crypto/ecdsa"
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
	// RuleUnattributed: a KMS Sign with no journal sign entry of its
	// request id, or by another principal, algorithm or message type. A
	// lone Sign inside a sign_intent's lease window, with no sign entry,
	// is a notice instead (an answer lost).
	RuleUnattributed = "unattributed_sign"
	// RuleTrailMissing: a journaled sign with no KMS Sign of its request
	// id in the trail, once the trail has had time to deliver it.
	RuleTrailMissing = "trail_missing"
	// RuleSignatureMismatch: a journaled signature that doesn't verify
	// under the anchor key, or whose r isn't the journaled r; or a bundle
	// on the site whose signature is no journaled sign.
	RuleSignatureMismatch = "signature_mismatch"
	// RuleUnpublished: a journaled sign with no published document holding
	// it, an hour on. An extension the site refused as too_late, its
	// lateness verified, is a notice.
	RuleUnpublished = "unpublished_sign"
	// RuleSecondSign: a second signature (another r) for a digest already
	// signed: a notice.
	RuleSecondSign = "second_sign"
	// RuleCodeDrift and RulePolicyDrift: the signer function's code or
	// resource policy isn't the release's.
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
	RequestID string `json:"kms_request_id,omitempty"`
	Detail    string `json:"detail"`
	// Acknowledged: listed in the acknowledged signs (reported, not alarmed).
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// KMSSign is one KMS Sign call on the anchor key, from the trail.
type KMSSign struct {
	RequestID   string
	At          time.Time
	Principal   string // the session issuer's role ARN, or the caller's ARN
	Algorithm   string // requestParameters.signingAlgorithm
	MessageType string // requestParameters.messageType
	ErrorCode   string // set: the call failed, and signed nothing
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
}

// Acknowledgement excuses one finding (by rule, slot and digest), listed
// in the reviewed file monitor/acknowledged-signs-<env>.json.
type Acknowledgement struct {
	Rule   string `json:"rule"`
	Slot   string `json:"slot"`
	Digest string `json:"digest"` // hex
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

	Signs       []signer.SignEntry
	Completions []signer.CompletionEntry
	Notes       []signer.NoteEntry
	KMSSigns    []KMSSign
	// SignerRole is the signer role's ARN: KMS Signs by anything else are
	// unattributed.
	SignerRole string
	// AnchorSPKI is the anchor key (DER SubjectPublicKeyInfo).
	AnchorSPKI []byte
	// Published holds what the site holds, for every slot in the journal
	// and every slot the site shows in the period; a slot missing from it
	// was not read.
	Published map[string]Published
	// LateVerified lists slots whose too_late refusal the adapter verified
	// (its bundle time at or after the close).
	LateVerified map[string]bool
	Release      *Release // nil: not read
	Acks         []Acknowledgement
	// Incomplete names inputs that couldn't be read.
	Incomplete []string
}

// UnpublishedAfter is how long a journaled sign may wait for its
// publication (the design of record, §6).
const UnpublishedAfter = time.Hour

// Run checks one pass's input and returns its findings, sorted.
func Run(in Input) []Finding {
	var out []Finding
	add := func(f Finding) { out = append(out, f) }
	for _, what := range in.Incomplete {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "could not read " + what})
	}

	pub, err := anchorKey(in.AnchorSPKI)
	if err != nil {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "the anchor key: " + err.Error()})
	}

	signsByID := map[string]signer.SignEntry{}
	// One sign per (digest, r): the journal may hold it more than once.
	type dr struct{ digest, r string }
	seen := map[dr]bool{}
	rsByDigest := map[string]map[string]bool{}
	journaledSigs := map[string]bool{} // hex signature
	for _, s := range in.Signs {
		if s.KMSRequestID != "" {
			signsByID[s.KMSRequestID] = s
		}
		key := dr{hex.EncodeToString(s.Digest), hex.EncodeToString(s.R)}
		if seen[key] {
			continue
		}
		seen[key] = true
		journaledSigs[hex.EncodeToString(s.Signature)] = true
		slot := s.ProposalID + "/" + s.Name
		if rsByDigest[key.digest] == nil {
			rsByDigest[key.digest] = map[string]bool{}
		}
		rsByDigest[key.digest][key.r] = true
		if len(rsByDigest[key.digest]) == 2 {
			add(Finding{Rule: RuleSecondSign, Severity: Notice, Slot: slot, Digest: key.digest,
				Detail: "a second signature for a digest already signed"})
		}
		if pub != nil {
			if err := verifySign(pub, s); err != nil {
				add(Finding{Rule: RuleSignatureMismatch, Severity: Alarm, Slot: slot, Digest: key.digest, RequestID: s.KMSRequestID,
					Detail: "the journaled signature: " + err.Error()})
			}
		}
	}

	// unattributed_sign: every KMS Sign accounted for by a sign entry.
	settled := in.To.Add(-in.TrailLag)
	for _, k := range in.KMSSigns {
		if k.ErrorCode != "" || k.At.After(settled) {
			continue
		}
		f := Finding{Rule: RuleUnattributed, Severity: Alarm, RequestID: k.RequestID}
		switch {
		case k.Principal != in.SignerRole:
			f.Detail = "a Sign by another principal than the signer role"
		case k.Algorithm != "ECDSA_SHA_256" || k.MessageType != "DIGEST":
			f.Detail = fmt.Sprintf("a Sign with %s/%s", k.Algorithm, k.MessageType)
		default:
			if _, ok := signsByID[k.RequestID]; ok {
				continue
			}
			if n, ok := intentCovering(in.Notes, k.At); ok {
				f.Severity, f.Slot, f.Digest = Notice, n.ProposalID+"/"+n.Name, hex.EncodeToString(n.Digest)
				f.Detail = "a Sign inside a sign_intent's lease with no sign entry (an answer lost)"
			} else {
				f.Detail = "a Sign with no journal entry"
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
	for _, s := range dedupe(in.Signs) {
		if s.At.Before(trailFrom) || s.At.After(settled) {
			continue
		}
		if !kmsByID[s.KMSRequestID] {
			add(Finding{Rule: RuleTrailMissing, Severity: Alarm, Slot: s.ProposalID + "/" + s.Name,
				Digest: hex.EncodeToString(s.Digest), RequestID: s.KMSRequestID, Detail: "a journaled sign the trail doesn't show"})
		}
	}

	// unpublished_sign, and bundles that are no journaled sign.
	for _, s := range dedupe(in.Signs) {
		slot := s.ProposalID + "/" + s.Name
		p, read := in.Published[slot]
		if !read {
			add(Finding{Rule: RuleIncomplete, Severity: Alarm, Slot: slot, Detail: "the site's holding for a journaled slot was not read"})
			continue
		}
		if p.Held && bytes.Equal(p.Signature, s.Signature) {
			continue
		}
		if in.Now.Sub(s.At) < UnpublishedAfter {
			continue
		}
		f := Finding{Rule: RuleUnpublished, Severity: Alarm, Slot: slot, Digest: hex.EncodeToString(s.Digest), RequestID: s.KMSRequestID,
			Detail: "a journaled sign with no published document holding it"}
		if p.Held {
			f.Detail = "the slot holds another signature than this journaled sign"
		}
		if tooLate(in.Completions, s) && in.LateVerified[slot] {
			f.Severity, f.Detail = Notice, "an extension the site refused as too_late, its lateness verified"
		}
		add(f)
	}
	slots := make([]string, 0, len(in.Published))
	for slot := range in.Published {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	for _, slot := range slots {
		p := in.Published[slot]
		if !p.Held {
			continue
		}
		if p.VerifyErr != "" {
			add(Finding{Rule: RuleSignatureMismatch, Severity: Alarm, Slot: slot, Detail: "the site's bundle doesn't verify: " + p.VerifyErr})
			continue
		}
		if !journaledSigs[hex.EncodeToString(p.Signature)] {
			add(Finding{Rule: RuleSignatureMismatch, Severity: Alarm, Slot: slot, Detail: "the site's bundle signature is no journaled sign"})
		}
	}

	// The function as released.
	if in.Release == nil {
		add(Finding{Rule: RuleIncomplete, Severity: Alarm, Detail: "the signer function's code and policy were not read"})
	} else {
		if in.Release.WantCodeSha256 == "" || in.Release.GotCodeSha256 != in.Release.WantCodeSha256 {
			add(Finding{Rule: RuleCodeDrift, Severity: Alarm, Detail: "CodeSha256 " + in.Release.GotCodeSha256 + ", not the release's " + in.Release.WantCodeSha256})
		}
		if in.Release.WantPolicy == "" || in.Release.GotPolicy != in.Release.WantPolicy {
			add(Finding{Rule: RulePolicyDrift, Severity: Alarm, Detail: "the function's resource policy isn't the release's"})
		}
	}

	acknowledge(out, in.Acks)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].Slot != out[j].Slot {
			return out[i].Slot < out[j].Slot
		}
		return out[i].RequestID < out[j].RequestID
	})
	return out
}

// dedupe keeps the first journal entry of each (digest, r).
func dedupe(signs []signer.SignEntry) []signer.SignEntry {
	seen := map[string]bool{}
	var out []signer.SignEntry
	for _, s := range signs {
		k := hex.EncodeToString(s.Digest) + "/" + hex.EncodeToString(s.R)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// intentCovering finds a sign_intent whose lease window holds t.
func intentCovering(notes []signer.NoteEntry, t time.Time) (signer.NoteEntry, bool) {
	for _, n := range notes {
		if n.Kind == signer.NoteIntent && !t.Before(n.At) && !t.After(n.LeaseUntil) {
			return n, true
		}
	}
	return signer.NoteEntry{}, false
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
	if !ok {
		return nil, errors.New("not an ECDSA key")
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

// acknowledge marks the findings an acknowledgement lists (rule, slot and
// digest all equal): they stay in the report, as notices.
func acknowledge(fs []Finding, acks []Acknowledgement) {
	for i := range fs {
		for _, a := range acks {
			if a.Rule == fs[i].Rule && a.Slot == fs[i].Slot && a.Digest == fs[i].Digest && a.Slot != "" {
				fs[i].Acknowledged, fs[i].Severity = true, Notice
			}
		}
	}
}
