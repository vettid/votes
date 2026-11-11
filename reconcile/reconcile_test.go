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
	"testing"
	"time"

	"github.com/vettid/votes/signer"
)

const role = "arn:aws:iam::444455556666:role/vettid-anchor-signer-staging"

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
func (f *fixture) sign(id, name, doc, reqID string, at time.Time) signer.SignEntry {
	d := sha256.Sum256([]byte(doc))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, d[:])
	if err != nil {
		f.t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		f.t.Fatal(err)
	}
	return signer.SignEntry{KMSRequestID: reqID, At: at, ProposalID: id, Name: name, Digest: d[:], Signature: sig, R: rs.R.Bytes()}
}

func (f *fixture) kms(reqID string, at time.Time) KMSSign {
	return KMSSign{RequestID: reqID, At: at, Principal: role, Algorithm: "ECDSA_SHA_256", MessageType: "DIGEST"}
}

// clean is a pass with one sign, accounted for on every side.
func (f *fixture) clean() Input {
	s := f.sign("p1", "proposal", "doc one", "req-1", f.now.Add(-90*time.Minute))
	return Input{
		Now: f.now, From: f.now.Add(-3 * time.Hour), To: f.now, TrailLag: 20 * time.Minute,
		Signs:      []signer.SignEntry{s},
		KMSSigns:   []KMSSign{f.kms("req-1", s.At.Add(-time.Second))},
		SignerRole: role, AnchorSPKI: f.spki,
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

func TestClean(t *testing.T) {
	f := newFixture(t)
	if fs := Run(f.clean()); len(fs) != 0 {
		t.Fatalf("findings on a clean pass: %+v", fs)
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

	// Inside a sign_intent's lease, with no sign entry: a notice.
	in = f.clean()
	in.KMSSigns = append(in.KMSSigns, f.kms("req-x", at))
	in.Notes = []signer.NoteEntry{{Kind: signer.NoteIntent, At: at.Add(-5 * time.Second), LeaseUntil: at.Add(30 * time.Second), ProposalID: "p2", Name: "proposal"}}
	fs := Run(in)
	if r := rules(fs); r[RuleUnattributed] != Notice {
		t.Fatalf("a Sign inside an intent's lease: %v", r)
	}
	// Another kind of note doesn't excuse it.
	in.Notes[0].Kind = signer.NoteRetimestamp
	if r := rules(Run(in)); r[RuleUnattributed] != Alarm {
		t.Fatalf("a Sign inside a non-intent note: %v", r)
	}

	// Another principal, or another algorithm or message type: an alarm,
	// even with a sign entry of its request id.
	for _, mod := range []func(*KMSSign){
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

	// A failed Sign signed nothing; a Sign too recent for the journal's
	// side is left for the next pass.
	in = f.clean()
	failed := f.kms("req-f", at)
	failed.ErrorCode = "AccessDeniedException"
	in.KMSSigns = append(in.KMSSigns, failed, f.kms("req-new", f.now.Add(-5*time.Minute)))
	if fs := Run(in); len(fs) != 0 {
		t.Fatalf("a failed or too recent Sign: %+v", fs)
	}
}

func TestTrailMissing(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	in.KMSSigns = nil
	if r := rules(Run(in)); r[RuleTrailMissing] != Alarm {
		t.Fatalf("a journaled sign the trail doesn't show: %v", r)
	}
	// A failed call of the same id isn't the sign.
	in.KMSSigns = []KMSSign{f.kms("req-1", in.Signs[0].At)}
	in.KMSSigns[0].ErrorCode = "KMSInternalException"
	if r := rules(Run(in)); r[RuleTrailMissing] != Alarm {
		t.Fatalf("only a failed call in the trail: %v", r)
	}
	// Too recent, or at the start of the period: the next or last pass's.
	in = f.clean()
	in.KMSSigns = nil
	in.Signs[0].At = f.now.Add(-10 * time.Minute)
	in.Published["p1/proposal"] = Published{Held: true, Signature: in.Signs[0].Signature}
	if r := rules(Run(in)); r[RuleTrailMissing] != "" {
		t.Fatalf("a sign too recent for the trail: %v", r)
	}
	in.Signs[0].At = in.From.Add(5 * time.Minute)
	if r := rules(Run(in)); r[RuleTrailMissing] != "" {
		t.Fatalf("a sign at the period's start: %v", r)
	}
}

func TestSignatureMismatch(t *testing.T) {
	f := newFixture(t)
	// A journaled r that isn't the signature's.
	in := f.clean()
	in.Signs[0].R = append([]byte{1}, in.Signs[0].R...)
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a wrong r: %v", r)
	}
	// A signature over another digest.
	in = f.clean()
	other := sha256.Sum256([]byte("another doc"))
	in.Signs[0].Digest = other[:]
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a signature over another digest: %v", r)
	}
	// A site bundle whose signature is no journaled sign.
	in = f.clean()
	stray := f.sign("p9", "proposal", "stray", "req-9", f.now)
	in.Published["p9/proposal"] = Published{Held: true, Signature: stray.Signature}
	if r := rules(Run(in)); r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("a bundle no sign accounts for: %v", r)
	}
	// A bundle that doesn't verify.
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
	// Another signature held in the slot.
	in = f.clean()
	other := f.sign("p1", "proposal", "doc one", "req-2", f.now)
	in.Published["p1/proposal"] = Published{Held: true, Signature: other.Signature}
	fs := Run(in)
	if r := rules(fs); r[RuleUnpublished] != Alarm || r[RuleSignatureMismatch] != Alarm {
		t.Fatalf("another signature in the slot: %v", r)
	}
	// Within the hour: not yet.
	in = f.clean()
	in.Signs[0].At = f.now.Add(-30 * time.Minute)
	in.KMSSigns[0].At = in.Signs[0].At
	in.Published["p1/proposal"] = Published{}
	if r := rules(Run(in)); r[RuleUnpublished] != "" {
		t.Fatalf("within the hour: %v", r)
	}
	// too_late: a notice only once the adapter verified its lateness.
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
	// A too_late completion of another r doesn't excuse this one.
	in.Completions[0].R = []byte{9}
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("too_late of another signature: %v", r)
	}
}

func TestSecondSign(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	// The same sign journaled twice (a retry after a lost mark): counted once.
	in.Signs = append(in.Signs, in.Signs[0])
	if fs := Run(in); len(fs) != 0 {
		t.Fatalf("a sign journaled twice: %+v", fs)
	}
	// Another signature for the same digest: a notice (and unpublished,
	// since the slot holds the first).
	again := f.sign("p1", "proposal", "doc one", "req-2", in.Signs[0].At.Add(time.Minute))
	in.Signs = append(in.Signs, again)
	in.KMSSigns = append(in.KMSSigns, f.kms("req-2", again.At))
	if r := rules(Run(in)); r[RuleSecondSign] != Notice || r[RuleUnpublished] != Alarm {
		t.Fatalf("a second signature: %v", r)
	}
}

func TestIncompleteAndRelease(t *testing.T) {
	f := newFixture(t)
	in := f.clean()
	delete(in.Published, "p1/proposal")
	if r := rules(Run(in)); r[RuleIncomplete] != Alarm {
		t.Fatalf("a journaled slot not read on the site: %v", r)
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
	in.Release.GotCodeSha256 = "def"
	in.Release.GotPolicy = `{"x":1}`
	if r := rules(Run(in)); r[RuleCodeDrift] != Alarm || r[RulePolicyDrift] != Alarm {
		t.Fatalf("drift: %v", r)
	}
	// A release record with nothing in it isn't a match.
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
	d := hex.EncodeToString(in.Signs[0].Digest)
	in.Acks = []Acknowledgement{{Rule: RuleUnpublished, Slot: "p1/proposal", Digest: d, Reason: "a test"}}
	fs := Run(in)
	if len(fs) != 1 || !fs[0].Acknowledged || fs[0].Severity != Notice {
		t.Fatalf("an acknowledged finding: %+v", fs)
	}
	// Another digest in the same slot is not acknowledged.
	in.Acks[0].Digest = "00"
	if r := rules(Run(in)); r[RuleUnpublished] != Alarm {
		t.Fatalf("an acknowledgement of another digest: %v", r)
	}
}
