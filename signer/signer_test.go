package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/vettid/votes/site"
)

// memClaims is the claim table in memory, with the table's conditions.
type memClaims struct {
	mu     sync.Mutex
	c      map[string]*Claim
	failOn string             // a write to fail once ("sig", "journaled", "token", "entry")
	before func(which string) // runs before each conditional write, unlocked
}

func (m *memClaims) Get(_ context.Context, slot string) (*Claim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.c[slot]
	if c == nil {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (m *memClaims) Create(_ context.Context, slot string, digest []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.c == nil {
		m.c = map[string]*Claim{}
	}
	if m.c[slot] != nil {
		return ErrExists
	}
	m.c[slot] = &Claim{Slot: slot, Digest: bytes.Clone(digest), Created: at}
	return nil
}

func (m *memClaims) set(slot string, digest []byte, which string, ok func(*Claim) bool, apply func(*Claim)) error {
	if m.before != nil {
		m.before(which)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn == which {
		m.failOn = ""
		return errors.New("the table is down")
	}
	c := m.c[slot]
	if c == nil || !bytes.Equal(c.Digest, digest) || !ok(c) {
		return ErrSet
	}
	apply(c)
	return nil
}

func (m *memClaims) Lease(_ context.Context, slot string, digest []byte, until, now time.Time) error {
	return m.set(slot, digest, "lease", func(c *Claim) bool { return c.Sig == nil && !c.LeaseUntil.After(now) },
		func(c *Claim) { c.LeaseUntil = until })
}

func (m *memClaims) SetSig(_ context.Context, slot string, digest, sig, r []byte, id string) error {
	return m.set(slot, digest, "sig", func(c *Claim) bool { return c.Sig == nil },
		func(c *Claim) { c.Sig, c.R, c.RequestID = sig, r, id })
}

func (m *memClaims) SetJournaled(_ context.Context, slot string, digest, r []byte) error {
	return m.set(slot, digest, "journaled", func(c *Claim) bool { return bytes.Equal(c.R, r) && !c.Journaled },
		func(c *Claim) { c.Journaled = true })
}

func (m *memClaims) SetToken(_ context.Context, slot string, digest, r, tok []byte) error {
	return m.set(slot, digest, "token", func(c *Claim) bool { return bytes.Equal(c.R, r) && c.TSAToken == nil },
		func(c *Claim) { c.TSAToken = tok })
}

func (m *memClaims) SetEntry(_ context.Context, slot string, digest, r []byte, e json.RawMessage) error {
	return m.set(slot, digest, "entry", func(c *Claim) bool { return bytes.Equal(c.R, r) && c.RekorEntry == nil },
		func(c *Claim) { c.RekorEntry = e })
}

type memJournal struct {
	mu       sync.Mutex
	signs    []SignEntry
	done     []CompletionEntry
	failSign int // fail this many Sign writes
}

func (j *memJournal) Sign(_ context.Context, e SignEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failSign > 0 {
		j.failSign--
		return errors.New("the log is down")
	}
	j.signs = append(j.signs, e)
	return nil
}

func (j *memJournal) Complete(_ context.Context, e CompletionEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = append(j.done, e)
	return nil
}

// fakeAnchor signs with a key in memory and makes up the token and entry,
// counting each step and failing one on request.
type fakeAnchor struct {
	mu                    sync.Mutex
	key                   *ecdsa.PrivateKey
	signs, stamps, enters int
	failStamp, failEnter  int
	blockStamp            bool
	wrongDigest           bool
	signGate              chan struct{} // if set, Sign waits on it
}

func (a *fakeAnchor) Sign(ctx context.Context, doc []byte) ([]byte, []byte, error) {
	if a.signGate != nil {
		<-a.signGate
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signs++
	d := sha256.Sum256(doc)
	if a.wrongDigest {
		d[0] ^= 1
	}
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, d[:])
	if p := RequestIDSink(ctx); p != nil {
		*p = "req-" + strconv.Itoa(a.signs)
	}
	return d[:], sig, err
}

func (a *fakeAnchor) Timestamp(ctx context.Context, sig []byte) ([]byte, error) {
	a.mu.Lock()
	a.stamps++
	n, block, fail := a.stamps, a.blockStamp, a.failStamp > 0
	if fail {
		a.failStamp--
	}
	a.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fail {
		return nil, errors.New("TSA down")
	}
	return []byte("token:" + strconv.Itoa(n)), nil
}

func (a *fakeAnchor) Enter(_ context.Context, digest, sig []byte) (json.RawMessage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enters++
	if a.failEnter > 0 {
		a.failEnter--
		return nil, errors.New("Rekor down")
	}
	return json.RawMessage(`{"logIndex":"7"}`), nil
}

func (a *fakeAnchor) Bundle(digest, sig, ts []byte, entry json.RawMessage) (json.RawMessage, error) {
	b, _ := json.Marshal(map[string]any{"digest": digest, "sig": sig, "ts": ts, "entry": entry})
	return b, nil
}

func (a *fakeAnchor) PublicKeyDER() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	return der
}

type fakeSite struct {
	mu        sync.Mutex
	refuse    *site.Refusal
	published bool
	held      []byte
	answers   []answer // answers to uploads, in turn; then 201, indexed
	uploads   []site.Upload
	lead      time.Duration
}

type answer struct {
	status  int
	code    string
	indexed bool
}

func (f *fakeSite) Prepare(_ context.Context, _, _ string, _, _, _ []byte, lead time.Duration) (site.Prepared, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lead = lead
	if f.refuse != nil {
		return site.Prepared{}, f.refuse
	}
	return site.Prepared{Published: f.published}, nil
}

func (f *fakeSite) Bundle(context.Context, string, string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held, nil
}

func (f *fakeSite) Upload(_ context.Context, _, _ string, u *site.Upload) (int, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads = append(f.uploads, *u)
	if len(f.answers) > 0 {
		a := f.answers[0]
		f.answers = f.answers[1:]
		return a.status, a.code, a.indexed, nil
	}
	return http.StatusCreated, "", true, nil
}

func (f *fakeSite) Times([]byte, []byte, []byte) (time.Time, time.Time, int64, error) {
	return time.Unix(100, 0), time.Unix(101, 0), 7, nil
}

type harness struct {
	s  *Signer
	c  *memClaims
	j  *memJournal
	a  *fakeAnchor
	st *fakeSite
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{c: &memClaims{}, j: &memJournal{}, a: &fakeAnchor{key: k}, st: &fakeSite{}}
	h.s = &Signer{Claims: h.c, Journal: h.j, Anchor: h.a, Site: h.st, Now: time.Now, Deadlines: DefaultDeadlines}
	return h
}

var req = Request{ProposalID: "01KC0000000000000000000001", Name: "proposal", Doc: []byte(`{"v":1}`), Sig: make([]byte, 64)}

const slot = "01KC0000000000000000000001/proposal"

func (h *harness) counts(t *testing.T, signs, stamps, enters, uploads int) {
	t.Helper()
	if h.a.signs != signs || h.a.stamps != stamps || h.a.enters != enters || len(h.st.uploads) != uploads {
		t.Fatalf("signs %d stamps %d enters %d uploads %d, want %d %d %d %d",
			h.a.signs, h.a.stamps, h.a.enters, len(h.st.uploads), signs, stamps, enters, uploads)
	}
}

func TestPublish(t *testing.T) {
	h := newHarness(t)
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 201 || r.Bundle == nil || !r.IndexUpdated {
		t.Fatalf("%+v %v", r, err)
	}
	if h.st.lead != DefaultLead {
		t.Fatalf("Prepare's lead %v", h.st.lead)
	}
	h.counts(t, 1, 1, 1, 1)
	c, _ := h.c.Get(context.Background(), slot)
	if c.Sig == nil || c.TSAToken == nil || c.RekorEntry == nil || !c.Journaled || c.RequestID != "req-1" || c.LeaseUntil.IsZero() {
		t.Fatalf("claim %+v", c)
	}
	if len(h.j.signs) != 1 || h.j.signs[0].KMSRequestID != "req-1" || !bytes.Equal(h.j.signs[0].R, c.R) {
		t.Fatalf("journal %+v", h.j.signs)
	}
	if len(h.j.done) != 1 || h.j.done[0].SiteStatus != 201 || h.j.done[0].RekorIndex != 7 || h.j.done[0].Resumed {
		t.Fatalf("completion %+v", h.j.done)
	}
}

// A published document whose index the site didn't update: the retry
// uploads the same bytes with the held bundle, signs nothing, and passes
// on the site's answer.
func TestPublishedIndex(t *testing.T) {
	h := newHarness(t)
	h.st.answers = []answer{{201, "", false}, {200, "", false}, {200, "", true}}
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 201 || r.IndexUpdated {
		t.Fatalf("%+v %v", r, err)
	}
	h.st.published, h.st.held = true, r.Bundle
	for _, wantIndexed := range []bool{false, true} {
		r2, err := h.s.Handle(context.Background(), req)
		if err != nil || r2.Status != 200 || r2.IndexUpdated != wantIndexed || !bytes.Equal(r2.Bundle, r.Bundle) {
			t.Fatalf("%+v %v", r2, err)
		}
	}
	h.counts(t, 1, 1, 1, 3)
	if !bytes.Equal(h.st.uploads[2].Bundle, r.Bundle) {
		t.Fatal("the retry uploaded another bundle")
	}
	if n := len(h.j.done); n != 3 || !h.j.done[2].AlreadyHeld {
		t.Fatalf("completions %+v", h.j.done)
	}
}

// A retry resumes after each hop's failure and never repeats a step it
// kept.
func TestResume(t *testing.T) {
	h := newHarness(t)
	h.a.failStamp, h.a.failEnter = 1, 1
	h.st.answers = []answer{{503, "unavailable", false}, {429, "rate_limited", false}}
	for i, want := range []struct{ signs, stamps, enters, uploads int }{
		{1, 1, 0, 0}, // the TSA fails
		{1, 2, 1, 0}, // Rekor fails
		{1, 2, 2, 1}, // the site answers 503
		{1, 2, 2, 2}, // a rate limit answers 429
		{1, 2, 2, 3}, // published
	} {
		r, err := h.s.Handle(context.Background(), req)
		if (i < 4) != (err != nil) {
			t.Fatalf("attempt %d: %+v %v", i, r, err)
		}
		h.counts(t, want.signs, want.stamps, want.enters, want.uploads)
	}
	if len(h.j.signs) != 1 || len(h.j.done) != 1 || !h.j.done[0].Resumed {
		t.Fatalf("journal %+v %+v", h.j.signs, h.j.done)
	}
	if !bytes.Equal(h.st.uploads[0].Bundle, h.st.uploads[2].Bundle) {
		t.Fatal("a retry uploaded another bundle")
	}
}

// Nothing is signed for a refused document, another document's claim,
// or a published one.
func TestNoSign(t *testing.T) {
	h := newHarness(t)
	h.st.refuse = &site.Refusal{Status: 422, Code: "too_late"}
	if r, err := h.s.Handle(context.Background(), req); err != nil || r.Status != 422 || r.Code != "too_late" {
		t.Fatalf("%+v %v", r, err)
	}
	if len(h.c.c) != 0 {
		t.Fatal("a refused document was claimed")
	}
	h.st.refuse = nil
	_ = h.c.Create(context.Background(), slot, make([]byte, 32), time.Unix(1, 0))
	if r, err := h.s.Handle(context.Background(), req); err != nil || r.Status != 409 || r.Code != CodeClaimConflict {
		t.Fatalf("%+v %v", r, err)
	}
	h2 := newHarness(t)
	h2.st.published, h2.st.held = true, []byte(`{"held":1}`)
	if r, err := h2.s.Handle(context.Background(), req); err != nil || r.Status != 201 || string(r.Bundle) != `{"held":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	h.counts(t, 0, 0, 0, 0)
	h2.counts(t, 0, 0, 0, 1)
	if r, err := h.s.Handle(context.Background(), Request{Name: "proposal"}); err != nil || r.Code != CodeBadRequest {
		t.Fatalf("%+v %v", r, err)
	}
}

// A signer that answers for another digest stops the call before the
// signature is kept.
func TestWrongDigest(t *testing.T) {
	h := newHarness(t)
	h.a.wrongDigest = true
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	if c, _ := h.c.Get(context.Background(), slot); c.Sig != nil {
		t.Fatal("another digest's signature was kept")
	}
	h.counts(t, 1, 0, 0, 0)
}

// Two calls at once for one slot sign once: the second finds the lease
// and fails to be retried, or finds the signature and goes on.
func TestConcurrent(t *testing.T) {
	h := newHarness(t)
	h.a.signGate = make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = h.s.Handle(context.Background(), req)
		}()
	}
	// Let the lease holder sign once both have had time to try.
	time.Sleep(100 * time.Millisecond)
	close(h.a.signGate)
	wg.Wait()
	if h.a.signs != 1 {
		t.Fatalf("%d signs", h.a.signs)
	}
	busy := 0
	for _, err := range errs {
		if errors.Is(err, ErrBusy) {
			busy++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if busy != 1 || len(h.j.signs) != 1 {
		t.Fatalf("busy %d, journal %d", busy, len(h.j.signs))
	}
	// The retry goes on from the kept signature.
	if r, err := h.s.Handle(context.Background(), req); err != nil || (r.Status != 201 && r.Status != 200) {
		t.Fatalf("%+v %v", r, err)
	}
	if h.a.signs != 1 {
		t.Fatalf("%d signs", h.a.signs)
	}
}

// A token another call kept first is the one used.
func TestKeptByAnother(t *testing.T) {
	h := newHarness(t)
	h.c.before = func(which string) {
		if which != "token" {
			return
		}
		h.c.before = nil
		h.c.mu.Lock()
		h.c.c[slot].TSAToken = []byte("token:other")
		h.c.mu.Unlock()
	}
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var b map[string][]byte
	_ = json.Unmarshal(h.st.uploads[0].Bundle, &b)
	if string(b["ts"]) != "token:other" {
		t.Fatalf("the bundle carries %q, not the kept token", b["ts"])
	}
}

// Too little time left: nothing is signed.
func TestNoTime(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), h.s.Deadlines.signWindow()-time.Second)
	defer cancel()
	if _, err := h.s.Handle(ctx, req); !errors.Is(err, ErrNoTime) {
		t.Fatalf("err %v", err)
	}
	h.counts(t, 0, 0, 0, 0)
}

// The deadlines fit the function's 120 s, less the second the runtime
// loop keeps back.
func TestDeadlinesFit(t *testing.T) {
	if w := DefaultDeadlines.Worst(); w > 119*time.Second {
		t.Fatalf("worst case %v", w)
	}
	if DefaultLead < DefaultDeadlines.Site+3*DefaultDeadlines.Claims+DefaultDeadlines.signWindow()+DefaultDeadlines.TSA {
		t.Fatal("the lead is shorter than the steps before the TSA")
	}
}

// A sign the journal didn't take is journaled on the retry, without a
// second sign; one the claim didn't keep is journaled anyway.
func TestJournal(t *testing.T) {
	h := newHarness(t)
	h.j.failSign = 1
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error with the journal down")
	}
	h.counts(t, 1, 0, 0, 0)
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	h.counts(t, 1, 1, 1, 1)
	if len(h.j.signs) != 1 || h.j.signs[0].KMSRequestID != "req-1" {
		t.Fatalf("journal %+v", h.j.signs)
	}

	h = newHarness(t)
	h.c.failOn = "sig"
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error with the signature unkept")
	}
	if len(h.j.signs) != 1 {
		t.Fatalf("an unkept sign wasn't journaled: %+v", h.j.signs)
	}
	// The lease is still live: the retry waits it out.
	if _, err := h.s.Handle(context.Background(), req); !errors.Is(err, ErrBusy) {
		t.Fatalf("err %v", err)
	}
	h.c.mu.Lock()
	h.c.c[slot].LeaseUntil = time.Time{}
	h.c.mu.Unlock()
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	h.counts(t, 2, 1, 1, 1)
	if len(h.j.signs) != 2 || bytes.Equal(h.j.signs[0].R, h.j.signs[1].R) {
		t.Fatalf("journal %+v", h.j.signs)
	}
}

// The site's refusal after signing is the answer, journaled with its code.
func TestRefusedAfterSigning(t *testing.T) {
	h := newHarness(t)
	h.st.answers = []answer{{422, "too_late", false}}
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 422 || r.Code != "too_late" || r.Bundle != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if len(h.j.done) != 1 || h.j.done[0].SiteCode != "too_late" {
		t.Fatalf("completion %+v", h.j.done)
	}
}

// Each hop has its own deadline.
func TestHopDeadline(t *testing.T) {
	h := newHarness(t)
	h.a.blockStamp = true
	h.s.Deadlines.TSA = 50 * time.Millisecond
	start := time.Now()
	if _, err := h.s.Handle(context.Background(), req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the TSA's deadline didn't hold")
	}
}

func der(r, s *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1BigInt(r); b.AddASN1BigInt(s) })
	return b.BytesOrPanic()
}

func TestRFromDER(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{0x80, 1, 2}) // DER pads it with a zero
	got, err := RFromDER(der(r, big.NewInt(5)))
	if err != nil || !bytes.Equal(got, []byte{0x80, 1, 2}) {
		t.Fatalf("%x %v", got, err)
	}
	small := big.NewInt(9)
	if got, _ := RFromDER(der(small, big.NewInt(5))); !bytes.Equal(got, []byte{9}) {
		t.Fatalf("%x", got)
	}
	for _, bad := range [][]byte{nil, {0x30, 0}, append(der(r, big.NewInt(5)), 0), der(big.NewInt(0), big.NewInt(5))} {
		if _, err := RFromDER(bad); err == nil {
			t.Fatalf("%x taken", bad)
		}
	}
}
