package reconcile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/vettid/votes/signer"
)

const (
	role   = "arn:aws:iam::444455556666:role/vettid-anchor-signer-staging"
	keyARN = "arn:aws:kms:us-east-1:444455556666:key/abc"
)

// testKey is the anchor key, from a fixed public test seed.
func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("vettid/test/reconcile/anchor-key"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, spki
}

type fixture struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	spki []byte
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	k, spki := testKey(t)
	return &fixture{t: t, key: k, spki: spki, now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
}

// sign makes a journal sign entry for doc in slot id/name, at.
func (f *fixture) sign(id, name, doc, reqID, attempt string, at time.Time) signer.SignEntry {
	d := sha256.Sum256([]byte(doc))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, d[:])
	if err != nil {
		f.t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		f.t.Fatal(err)
	}
	return signer.SignEntry{KMSRequestID: reqID, AttemptID: attempt, At: at, ProposalID: id, Name: name, Digest: d[:], Signature: sig, R: rs.R.Bytes()}
}

func (f *fixture) kms(reqID string, at time.Time) KMSSign {
	return KMSSign{RequestID: reqID, At: at, KeyARN: keyARN, Principal: role, Algorithm: "ECDSA_SHA_256", MessageType: "DIGEST"}
}

func claimOf(s signer.SignEntry) Claim {
	return Claim{Exists: true, Digest: s.Digest, Sig: s.Signature, R: s.R, RequestID: s.KMSRequestID}
}

// clean is a pass with one sign, accounted for on every side.
func (f *fixture) clean() Input {
	s := f.sign("p1", "proposal", "doc one", "req-1", "a1", f.now.Add(-90*time.Minute))
	return Input{
		Now: f.now, From: f.now.Add(-3 * time.Hour), To: f.now, TrailLag: 20 * time.Minute,
		Signs:    []signer.SignEntry{s},
		KMSSigns: []KMSSign{f.kms("req-1", s.At.Add(-time.Second))},
		KeyARN:   keyARN, SignerRole: role, AnchorSPKI: f.spki,
		Claims:    map[string]Claim{"p1/proposal": claimOf(s)},
		Published: map[string]Published{"p1/proposal": {Held: true, Signature: s.Signature}},
		Release:   &Release{WantCodeSha256: "abc", GotCodeSha256: "abc", WantPolicy: "{}", GotPolicy: "{}"},
	}
}

func rules(fs []Finding) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range fs {
		if prev, ok := m[f.Rule]; !ok || prev == Notice {
			m[f.Rule] = f.Severity
		}
	}
	return m
}

func count(fs []Finding, rule string) int {
	n := 0
	for _, f := range fs {
		if f.Rule == rule {
			n++
		}
	}
	return n
}

func TestClean(t *testing.T) {
	f := newFixture(t)
	if fs := Run(f.clean()); len(fs) != 0 {
		t.Fatalf("findings on a clean pass: %+v", fs)
	}
	// An old document the site holds, signed long before the period: its
	// claim accounts for it, with nothing in this period's journal.
	in := f.clean()
	old := f.sign("p0", "proposal", "old doc", "req-0", "a0", f.now.Add(-30*24*time.Hour))
	in.Claims["p0/proposal"] = claimOf(old)
	in.Published["p0/proposal"] = Published{Held: true, Signature: old.Signature}
	if fs := Run(in); len(fs) != 0 {
		t.Fatalf("an old document: %+v", fs)
	}
}

// A stolen-credential Sign hidden behind a copy of a real, published sign
// entry under the attacker's request id (review H1): the claim holds the
// kept signature's own request id.
func TestCopiedEntryUnderAnotherRequestID(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	copied := in.Signs[0]
	copied.KMSRequestID = "req-attacker"
	copied.At = f.now.Add(-time.Hour)
	in.Signs = append(in.Signs, copied)
	in.KMSSigns = append(in.KMSSigns, f.kms("req-attacker", copied.At))
	if r := rules(Run(in)); r[RuleJournalConflict] != Alarm {
		t.Fatalf("a copied entry: %v", r)
	}
	// The copy alone, the original outside the period: the claim still
	// says whose request id the kept signature is.
	in.Signs = []signer.SignEntry{copied}
	in.KMSSigns = []KMSSign{f.kms("req-attacker", copied.At)}
	if r := rules(Run(in)); r[RuleJournalConflict] != Alarm {
		t.Fatalf("a copied entry alone: %v", r)
	}
	// One request id journaled for two signatures.
	in = f.clean()
	other := f.sign("p2", "proposal", "doc two", "req-1", "a2", in.Signs[0].At)
	in.Signs = append(in.Signs, other)
	in.Claims["p2/proposal"] = claimOf(other)
	in.Published["p2/proposal"] = Published{Held: true, Signature: other.Signature}
	if fs := Run(in); count(fs, RuleJournalConflict) == 0 {
		t.Fatalf("one request id for two signatures: %+v", fs)
	}
	// An entry with no request id.
	in = f.clean()
	in.Signs[0].KMSRequestID = ""
	in.Claims["p1/proposal"] = Claim{Exists: true, Digest: in.Signs[0].Digest, Sig: in.Signs[0].Signature, R: in.Signs[0].R}
	if r := rules(Run(in)); r[RuleJournalConflict] != Alarm {
		t.Fatalf("no request id: %v", r)
	}
}

func TestClaims(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.Claims["p1/proposal"] = Claim{}
	if r := rules(Run(in)); r[RuleUnclaimed] != Alarm {
		t.Fatalf("no claim: %v", r)
	}
	in = f.clean()
	other := sha256.Sum256([]byte("another doc"))
	in.Claims["p1/proposal"] = Claim{Exists: true, Digest: other[:], Sig: in.Signs[0].Signature, R: in.Signs[0].R, RequestID: "req-1"}
	if r := rules(Run(in)); r[RuleJournalConflict] != Alarm {
		t.Fatalf("another digest's claim: %v", r)
	}
	in = f.clean()
	delete(in.Claims, "p1/proposal")
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("a claim not read: %v", r)
	}
}

func TestUnattributed(t *testing.T) {
	f := newFixture(t)
	at := f.now.Add(-time.Hour)

	in := f.clean()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	if r := rules(Run(in)); r[RuleUnattributed] != Alarm {
		t.Fatalf("a Sign with no entry: %v", r)
	}

	// A Sign a note explains, its slot's claim bearing the note out (an
	// answer lost): reported at LostAnswerSeverity (an alarm: the trail
	// doesn't say what was signed). One attempt excuses one Sign.
	d2 := sha256.Sum256([]byte("doc two"))
	intent := signer.NoteEntry{Kind: signer.NoteIntent, At: at.Add(-5 * time.Second), LeaseUntil: at.Add(30 * time.Second),
		ProposalID: "p2", Name: "proposal", AttemptID: "a-lost", Digest: d2[:]}
	withClaim := func() Input {
		in := f.clean()
		in.Claims["p2/proposal"] = Claim{Exists: true, Digest: d2[:]}
		return in
	}
	lost := func(fs []Finding) *Finding {
		for i := range fs {
			if fs[i].Rule == RuleUnattributed && strings.Contains(fs[i].Detail, "an answer lost") {
				return &fs[i]
			}
		}
		return nil
	}
	in = withClaim()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	in.Notes = []signer.NoteEntry{intent}
	fs := Run(in)
	if l := lost(fs); l == nil || l.Severity != LostAnswerSeverity || count(fs, RuleUnattributed) != 1 {
		t.Fatalf("a Sign in a lone intent's lease: %+v", fs)
	}
	if LostAnswerSeverity != Alarm {
		t.Fatal("a lost answer must stay an alarm until the owner acknowledges it")
	}
	// A second Sign in the same lease isn't excused.
	in.KMSSigns = append(in.KMSSigns, f.kms("req-y", at.Add(time.Second)))
	if fs := Run(in); count(fs, RuleUnattributed) != 2 || lost(fs) == nil {
		t.Fatalf("two Signs on one intent: %+v", fs)
	}
	for _, x := range Run(in) {
		if x.RequestID == "req-y" && strings.Contains(x.Detail, "an answer lost") {
			t.Fatalf("the second Sign excused too: %+v", x)
		}
	}
	// The intent and the outcome note of one attempt excuse one Sign, not two.
	in = withClaim()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at), f.kms("req-y", at.Add(time.Second)))
	in.Notes = []signer.NoteEntry{intent, {Kind: signer.NoteOutcomeUnknown, At: at, KMSRequestID: "req-x", ProposalID: "p2", Name: "proposal",
		AttemptID: "a-lost", Digest: d2[:]}}
	excused := 0
	for _, x := range Run(in) {
		if strings.Contains(x.Detail, "an answer lost") {
			excused++
		}
	}
	if excused != 1 {
		t.Fatalf("one attempt excused %d Signs", excused)
	}
	// An intent whose attempt has its own sign entry excuses nothing.
	in = withClaim()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	signedIntent := intent
	signedIntent.AttemptID = "a1"
	in.Notes = []signer.NoteEntry{signedIntent}
	if fs := Run(in); lost(fs) != nil || count(fs, RuleUnattributed) != 1 {
		t.Fatalf("an intent whose attempt signed: %+v", fs)
	}
	// Another kind of note doesn't excuse it.
	in.Notes[0].Kind, in.Notes[0].AttemptID = signer.NoteRetimestamp, "a-lost"
	if fs := Run(in); lost(fs) != nil {
		t.Fatalf("a Sign inside a non-intent note: %+v", fs)
	}
	// A note whose slot has no claim, or whose digest isn't the claim's
	// (a note forged by the role the pass watches): not borne out.
	for _, c := range []Claim{{}, {Exists: true, Digest: []byte("another")}} {
		in = withClaim()
		in.Claims["p2/proposal"] = c
		in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
		in.Notes = []signer.NoteEntry{intent}
		if fs := Run(in); lost(fs) != nil || rules(fs)[RuleUnattributed] != Alarm {
			t.Fatalf("a note its claim doesn't bear out (%+v): %+v", c, fs)
		}
	}
	// The note's claim not read: incomplete.
	in = f.clean()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	in.Notes = []signer.NoteEntry{intent}
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("a note's claim not read: %v", r)
	}
	// A not-kept signature over another digest than its slot's: an alarm.
	in = withClaim()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	unkept := f.sign("p2", "proposal", "doc two", "req-x", "a3", at)
	in.Notes = []signer.NoteEntry{{Kind: signer.NoteUnkept, At: at, KMSRequestID: "req-x", ProposalID: "p2", Name: "proposal",
		Digest: d2[:], Signature: unkept.Signature, R: unkept.R}}
	if fs := Run(in); lost(fs) == nil {
		t.Fatalf("an unkept Sign over its slot's digest: %+v", fs)
	}
	attacker := f.sign("p2", "proposal", "the attacker's digest", "req-x", "a3", at)
	in.Notes[0].Signature = attacker.Signature
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("an unkept signature over another digest: %v", r)
	}

	// Another key, principal, algorithm or message type: an alarm, even
	// with a sign entry of its request id.
	for _, mod := range []func(*KMSSign){
		func(k *KMSSign) { k.KeyARN = "arn:aws:kms:us-east-1:444455556666:key/other" },
		func(k *KMSSign) { k.Principal = "arn:aws:iam::444455556666:role/break-glass" },
		func(k *KMSSign) { k.Algorithm = "ECDSA_SHA_384" },
		func(k *KMSSign) { k.MessageType = "RAW" },
	} {
		in = f.clean()
		mod(&in.KMSSigns[0])
		if r := rules(Run(in)); r[RuleUnattributed] != Alarm {
			t.Fatalf("a Sign off the signer's terms: %v", r)
		}
	}

	// A failed Sign by the signer signed nothing; by anyone else it's a
	// probe. A Sign too recent for the journal is left for the next pass.
	in = f.clean()
	failed := f.kms("req-f", at)
	failed.ErrorCode = "KMSInternalException"
	in.KMSSigns = append(in.KMSSigns, failed, f.kms("req-new", f.now.Add(-5*time.Minute)))
	if fs := Run(in); len(fs) != 0 {
		t.Fatalf("a failed or too recent Sign: %+v", fs)
	}
	probe := f.kms("req-p", at)
	probe.ErrorCode, probe.Principal = "AccessDeniedException", "arn:aws:iam::444455556666:role/someone"
	in.KMSSigns = append(in.KMSSigns, probe)
	if r := rules(Run(in)); r[RuleSignRefused] != Notice {
		t.Fatalf("a refused Sign by another principal: %v", r)
	}
}

func TestTrail(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.KMSSigns = nil
	if r := rules(Run(in)); r[RuleTrailMissing] != Alarm {
		t.Fatalf("a journaled sign the trail doesn't show: %v", r)
	}
	in.KMSSigns = []KMSSign{f.kms("req-1", in.Signs[0].At)}
	in.KMSSigns[0].ErrorCode = "KMSInternalException"
	if r := rules(Run(in)); r[RuleTrailMissing] != Alarm {
		t.Fatalf("only a failed call in the trail: %v", r)
	}
	// Too recent, or at the start of the period: the next or last pass's.
	in = f.clean()
	in.KMSSigns = nil
	in.Signs[0].At = f.now.Add(-10 * time.Minute)
	if r := rules(Run(in)); r[RuleTrailMissing] != "" {
		t.Fatalf("a sign too recent for the trail: %v", r)
	}
	in.Signs[0].At = in.From.Add(5 * time.Minute)
	if r := rules(Run(in)); r[RuleTrailMissing] != "" {
		t.Fatalf("a sign at the period's start: %v", r)
	}
	// The trail's own status.
	in = f.clean()
	in.TrailProblem = "the trail isn't logging"
	if r := rules(Run(in)); r[RuleTrailDelivery] != Alarm {
		t.Fatalf("the trail's status: %v", r)
	}
}

func TestSignatureMismatch(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.Signs[0].R = append([]byte{1}, in.Signs[0].R...)
	in.Claims["p1/proposal"] = claimOf(in.Signs[0])
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a wrong r: %v", r)
	}
	// A site bundle whose signature isn't its slot's claim's, however old.
	in = f.clean()
	stray := f.sign("p9", "proposal", "stray", "req-9", "a9", f.now.Add(-48*time.Hour))
	in.Claims["p9/proposal"] = Claim{Exists: true, Digest: stray.Digest, R: []byte{7}, Sig: []byte{7}, RequestID: "req-old"}
	in.Published["p9/proposal"] = Published{Held: true, Signature: stray.Signature}
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a bundle its claim doesn't hold: %v", r)
	}
	in.Claims["p9/proposal"] = Claim{}
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a bundle with no claim: %v", r)
	}
	delete(in.Claims, "p9/proposal")
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("a bundle whose claim wasn't read: %v", r)
	}
	in = f.clean()
	in.Published["p1/proposal"] = Published{Held: true, Signature: in.Signs[0].Signature, VerifyErr: "bad bundle"}
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a bundle that doesn't verify: %v", r)
	}
}

func TestUnpublished(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.Published["p1/proposal"] = Published{}
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("an hour on, not published: %v", r)
	}
	in = f.clean()
	in.Signs[0].At = f.now.Add(-30 * time.Minute)
	in.KMSSigns[0].At = in.Signs[0].At
	in.Published["p1/proposal"] = Published{}
	if r := rules(Run(in)); r[RuleUnpublished] != "" {
		t.Fatalf("within the hour: %v", r)
	}
	in = f.clean()
	in.Published["p1/proposal"] = Published{}
	s := in.Signs[0]
	in.Completions = []signer.CompletionEntry{{ProposalID: "p1", Name: "proposal", Digest: s.Digest, R: s.R, SiteStatus: 409, SiteCode: "too_late"}}
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("too_late, not verified: %v", r)
	}
	in.LateVerified = map[string]bool{"p1/proposal": true}
	if r := rules(Run(in)); r[RuleUnpublished] != Notice {
		t.Fatalf("too_late, verified: %v", r)
	}
	in.Completions[0].R = []byte{9}
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("too_late of another signature: %v", r)
	}
}

func TestSecondSign(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.Signs = append(in.Signs, in.Signs[0]) // journaled twice, identically
	if fs := Run(in); len(fs) != 0 {
		t.Fatalf("a sign journaled twice: %+v", fs)
	}
	// Signatures 2 and 3 for the digest, not kept: a notice each.
	for i, id := range []string{"req-2", "req-3"} {
		again := f.sign("p1", "proposal", "doc one", id, "b"+id, in.Signs[0].At.Add(time.Duration(i+1)*time.Minute))
		in.Signs = append(in.Signs, again)
		in.KMSSigns = append(in.KMSSigns, f.kms(id, again.At))
	}
	fs := Run(in)
	if n := count(fs, RuleSecondSign); n != 2 {
		t.Fatalf("%d second-sign notices, want 2: %+v", n, fs)
	}
	if r := rules(fs); r[RuleSecondSign] != Notice || r[RuleJournalConflict] != "" || r[RuleUnpublished] != "" {
		t.Fatalf("unkept signatures: %v", r)
	}
}

func TestKeyAndRelease(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.KeyProblem = "the alias resolves elsewhere"
	if r := rules(Run(in)); r[RuleKeyDrift] != Alarm {
		t.Fatalf("key drift: %v", r)
	}
	in = f.clean()
	in.AnchorSPKI = nil
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("no anchor key: %v", r)
	}
	in = f.clean()
	in.Incomplete = []string{"the trail"}
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("an input not read: %v", r)
	}
	in = f.clean()
	in.Release = nil
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("the release not read: %v", r)
	}
	in = f.clean()
	in.Release.GotCodeSha256, in.Release.GotPolicy = "def", `{"x":1}`
	if r := rules(Run(in)); r[RuleCodeDrift] != Alarm || r[RulePolicyDrift] != Alarm {
		t.Fatalf("drift: %v", r)
	}
	in = f.clean()
	in.Release.Versions = []string{"1"}
	if r := rules(Run(in)); r[RuleCodeDrift] != Alarm {
		t.Fatalf("a published version: %v", r)
	}
	in = f.clean()
	in.Release.Aliases = []string{"live"}
	if r := rules(Run(in)); r[RuleCodeDrift] != Alarm {
		t.Fatalf("an alias: %v", r)
	}
	in = f.clean()
	in.Release = &Release{}
	if r := rules(Run(in)); r[RuleCodeDrift] != Alarm || r[RulePolicyDrift] != Alarm {
		t.Fatalf("an empty release record: %v", r)
	}
}

func TestAcknowledged(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.Published["p1/proposal"] = Published{}
	s := in.Signs[0]
	in.Acks = []Acknowledgement{{Rule: RuleUnpublished, Slot: "p1/proposal", Digest: hex.EncodeToString(s.Digest), R: hex.EncodeToString(s.R), Reason: "a test"}}
	fs := Run(in)
	if len(fs) != 1 || !fs[0].Acknowledged || fs[0].Severity != Notice {
		t.Fatalf("an acknowledged finding: %+v", fs)
	}
	// Another r of the same digest is not acknowledged (review L2).
	in.Acks[0].R = "00"
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("an acknowledgement of another r: %v", r)
	}
}

func TestAnchorKeyP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := anchorKey(spki); err == nil {
		t.Fatal("a P-384 key accepted")
	}
}

// A sign that isn't its slot's kept one (review N1): the attacker makes
// a claim for their own digest with the signer's own Create, signs it and
// journals it. It never passes silently.
func TestNotKeptSigns(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	evil := f.sign("pQ", "proposal", "the attacker's digest", "req-e", "ae", f.now.Add(-90*time.Minute))
	in.Signs = append(in.Signs, evil)
	in.KMSSigns = append(in.KMSSigns, f.kms("req-e", evil.At))
	in.Claims["pQ/proposal"] = Claim{Exists: true, Digest: evil.Digest} // no signature kept
	in.Published["pQ/proposal"] = Published{}
	if r := rules(Run(in)); r[RuleUnkept] != Alarm {
		t.Fatalf("a sign for a claim holding no signature, an hour on: %v", r)
	}
	// Within the hour: not yet (the call may still be keeping it).
	in.Signs[1].At, in.KMSSigns[1].At = f.now.Add(-30*time.Minute), f.now.Add(-30*time.Minute)
	if r := rules(Run(in)); r[RuleUnkept] != "" {
		t.Fatalf("within the hour: %v", r)
	}
	// The claim kept another signature of the digest: a second sign,
	// reported from the claim even with the kept one outside the period.
	in = f.clean()
	kept := in.Signs[0]
	again := f.sign("p1", "proposal", "doc one", "req-2", "a2", kept.At.Add(time.Minute))
	in.Signs = []signer.SignEntry{again}
	in.KMSSigns = []KMSSign{f.kms("req-2", again.At)}
	fs := Run(in)
	if r := rules(fs); r[RuleSecondSign] != Notice || count(fs, RuleSecondSign) != 1 {
		t.Fatalf("a second sign, the kept one outside the period: %+v", fs)
	}
}

// Every age check by a time the signer role can't write (review T1): a
// forward-dated entry for a self-made claim is a conflict, and still ages
// by KMS's own time.
func TestTrustedTime(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	evil := f.sign("pQ", "proposal", "the attacker's digest", "req-e", "ae", time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC))
	signedAt := f.now.Add(-90 * time.Minute)
	in.Signs = append(in.Signs, evil)
	in.KMSSigns = append(in.KMSSigns, f.kms("req-e", signedAt))
	in.Claims["pQ/proposal"] = Claim{Exists: true, Digest: evil.Digest}
	in.Published["pQ/proposal"] = Published{}
	r := rules(Run(in))
	if r[RuleJournalConflict] != Alarm || r[RuleUnkept] != Alarm {
		t.Fatalf("a forward-dated entry: %v", r)
	}
	// With no KMS time (the trail not read), the ingestion time.
	in.KMSSigns = in.KMSSigns[:1]
	in.Ingested = map[string]time.Time{SignKey(in.Signs[0]): in.Signs[0].At, SignKey(evil): signedAt}
	r = rules(Run(in))
	if r[RuleJournalConflict] != Alarm || r[RuleUnkept] != Alarm {
		t.Fatalf("a forward-dated entry, by ingestion: %v", r)
	}
	// A kept sign, forward-dated: unpublished still fires by KMS's time.
	in = f.clean()
	in.Signs[0].At = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	in.Claims["p1/proposal"] = claimOf(in.Signs[0])
	in.Published["p1/proposal"] = Published{}
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm || r[RuleJournalConflict] != Alarm {
		t.Fatalf("a kept sign forward-dated: %v", r)
	}
	// An entry dated far from its KMS Sign.
	in = f.clean()
	in.KMSSigns[0].At = in.Signs[0].At.Add(-20 * time.Minute)
	if r := rules(Run(in)); r[RuleJournalConflict] != Alarm {
		t.Fatalf("an entry 20 minutes from its KMS Sign: %v", r)
	}
	// No trusted time at all: incomplete.
	in = f.clean()
	in.KMSSigns = nil
	if fs := Run(in); count(fs, RuleIncomplete) != 1 {
		t.Fatalf("no trusted time: %+v", fs)
	}
}
