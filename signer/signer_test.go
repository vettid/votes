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
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
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

func (m *memClaims) Lease(_ context.Context, slot string, digest []byte, owner string, until, now time.Time) error {
	return m.set(slot, digest, "lease", func(c *Claim) bool { return c.Sig == nil && !c.LeaseUntil.After(now) },
		func(c *Claim) { c.LeaseUntil, c.LeaseOwner = until, owner })
}

func (m *memClaims) SetEnterAttempted(_ context.Context, slot string, digest, r []byte) error {
	return m.set(slot, digest, "attempt", func(c *Claim) bool { return bytes.Equal(c.R, r) && !c.EnterAttempted },
		func(c *Claim) { c.EnterAttempted = true })
}

func (m *memClaims) ReplaceLateToken(_ context.Context, slot string, digest, r, old []byte, entry json.RawMessage, tok []byte) error {
	return m.set(slot, digest, "late", func(c *Claim) bool {
		return bytes.Equal(c.R, r) && bytes.Equal(c.TSAToken, old) && bytes.Equal(c.RekorEntry, entry)
	}, func(c *Claim) { c.TSAToken = tok })
}

func (m *memClaims) ReplaceToken(_ context.Context, slot string, digest, r, old, tok []byte) error {
	return m.set(slot, digest, "replace", func(c *Claim) bool {
		return bytes.Equal(c.R, r) && bytes.Equal(c.TSAToken, old) && c.RekorEntry == nil && !c.EnterAttempted
	}, func(c *Claim) { c.TSAToken = tok })
}

func (m *memClaims) SetSig(ctx context.Context, slot string, digest, sig, r []byte, id, owner string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return m.set(slot, digest, "sig", func(c *Claim) bool { return c.Sig == nil && c.LeaseOwner == owner },
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
	notes    []NoteEntry
	done     []CompletionEntry
	failSign int // fail this many Sign writes
}

func (j *memJournal) Sign(ctx context.Context, e SignEntry) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failSign > 0 {
		j.failSign--
		return errors.New("the log is down")
	}
	j.signs = append(j.signs, e)
	return nil
}

func (j *memJournal) Note(_ context.Context, e NoteEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.notes = append(j.notes, e)
	return nil
}

func (j *memJournal) kinds() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var k []string
	for _, n := range j.notes {
		k = append(k, n.Kind)
	}
	return k
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
	signGate              chan struct{}    // if set, Sign waits on it
	clock                 func() time.Time // the TSA's
	entryClock            func() time.Time // Rekor's, if set
	failSign              bool
	mismatch              bool // Sign answers a KeyMismatchError
	failBundle            int
	onSign                func() // if set, runs as Sign answers
}

func (a *fakeAnchor) Sign(ctx context.Context, doc []byte) ([]byte, []byte, error) {
	if a.signGate != nil {
		<-a.signGate
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signs++
	if a.mismatch {
		d := sha256.Sum256(doc)
		return d[:], nil, &KeyMismatchError{Sig: []byte{0x30, 6, 2, 1, 1, 2, 1, 1}}
	}
	if a.failSign {
		if p := RequestIDSink(ctx); p != nil {
			*p = "req-lost"
		}
		return nil, nil, errors.New("connection reset")
	}
	d := sha256.Sum256(doc)
	if a.wrongDigest {
		d[0] ^= 1
	}
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, d[:])
	if p := RequestIDSink(ctx); p != nil {
		*p = "req-" + strconv.Itoa(a.signs)
	}
	if a.onSign != nil {
		a.onSign()
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
	return []byte("token:" + strconv.Itoa(n) + ":" + strconv.FormatInt(a.clock().Unix(), 10)), nil
}

func (a *fakeAnchor) TokenTime(tok []byte) (time.Time, error) {
	var n, t int64
	if _, err := fmt.Sscanf(string(tok), "token:%d:%d", &n, &t); err != nil {
		return time.Time{}, err
	}
	return time.Unix(t, 0), nil
}

func (a *fakeAnchor) Enter(_ context.Context, digest, sig []byte) (json.RawMessage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enters++
	if a.failEnter > 0 {
		a.failEnter--
		return nil, errors.New("Rekor down")
	}
	at := time.Now()
	if a.entryClock != nil {
		at = a.entryClock()
	}
	return json.RawMessage(`{"logIndex":"7","integratedTime":"` + strconv.FormatInt(at.Unix(), 10) + `"}`), nil
}

func (a *fakeAnchor) EntryTime(e json.RawMessage) (time.Time, error) {
	var v struct {
		IntegratedTime string `json:"integratedTime"`
	}
	if err := json.Unmarshal(e, &v); err != nil {
		return time.Time{}, err
	}
	n, err := strconv.ParseInt(v.IntegratedTime, 10, 64)
	return time.Unix(n, 0), err
}

func (a *fakeAnchor) Bundle(digest, sig, ts []byte, entry json.RawMessage) (json.RawMessage, error) {
	if a.failBundle > 0 {
		a.failBundle--
		return nil, errors.New("too far apart")
	}
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
	heldOnly  bool     // Prepare reports a held bundle, not a published document
	answers   []answer // answers to uploads, in turn; then 201, indexed
	uploads   []site.Upload
	opts      site.PrepareOptions
}

type answer struct {
	status  int
	code    string
	indexed bool
}

func (f *fakeSite) Prepare(_ context.Context, _, _ string, _, _, _ []byte, opts site.PrepareOptions) (site.Prepared, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = opts
	if f.refuse != nil {
		return site.Prepared{}, f.refuse
	}
	return site.Prepared{Published: f.published, Held: f.heldOnly}, nil
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
	h := &harness{c: &memClaims{}, j: &memJournal{}, a: &fakeAnchor{key: k, clock: time.Now}, st: &fakeSite{}}
	h.s = &Signer{Claims: h.c, Journal: h.j, Anchor: h.a, Site: h.st, Now: time.Now, Deadlines: DefaultDeadlines,
		ServiceIKs: [][]byte{[]byte("ik")}}
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
	h.s.ServiceIKs = [][]byte{[]byte("ik")}
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 201 || r.Bundle == nil || !r.IndexUpdated || !bytes.Equal(r.AnchorKey, h.a.PublicKeyDER()) {
		t.Fatalf("%+v %v", r, err)
	}
	if len(h.st.opts.ServiceIKs) != 1 {
		t.Fatal("Prepare wasn't given the compiled identity keys")
	}
	if d := time.Until(h.st.opts.At) - DefaultDeadlines.Lead(); d > time.Second || d < -time.Second {
		t.Fatalf("Prepare's time %v", h.st.opts.At)
	}
	if !bytes.Equal(h.st.opts.AnchorKey, h.a.PublicKeyDER()) {
		t.Fatal("Prepare wasn't given the signer's key")
	}
	if k := h.j.kinds(); len(k) != 1 || k[0] != NoteIntent || h.j.notes[0].AttemptID == "" ||
		h.j.notes[0].AttemptID != h.j.signs[0].AttemptID {
		t.Fatalf("notes %+v", h.j.notes)
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

// A bundle a partial upload left for these bytes is uploaded, not signed
// again.
func TestHeldBundle(t *testing.T) {
	h := newHarness(t)
	h.st.heldOnly, h.st.held = true, []byte(`{"partial":1}`)
	if r, err := h.s.Handle(context.Background(), req); err != nil || r.Status != 201 {
		t.Fatalf("%+v %v", r, err)
	}
	h.counts(t, 0, 0, 0, 1)
	if string(h.st.uploads[0].Bundle) != `{"partial":1}` {
		t.Fatalf("uploaded %s", h.st.uploads[0].Bundle)
	}
}

// The call's context ending as KMS answers: the signature is still kept
// and journaled.
func TestSignKeptPastTheContext(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.a.onSign = cancel
	_, _ = h.s.Handle(ctx, req)
	c, _ := h.c.Get(context.Background(), slot)
	if c.Sig == nil || !c.Journaled || len(h.j.signs) != 1 {
		t.Fatalf("claim %+v, journal %d", c, len(h.j.signs))
	}
}

// A mark another call made first is fine.
func TestJournaledByAnother(t *testing.T) {
	h := newHarness(t)
	h.c.before = func(which string) {
		if which != "journaled" {
			return
		}
		h.c.before = nil
		h.c.mu.Lock()
		h.c.c[slot].Journaled = true
		h.c.mu.Unlock()
	}
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	h.counts(t, 1, 1, 1, 1)
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
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := h.s.Handle(context.Background(), req)
			results <- err
		}()
	}
	// The lease holder waits in Sign; the other finds the lease and
	// answers first. Then the holder may sign.
	first := <-results
	close(h.a.signGate)
	errs := []error{first, <-results}
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
		h.c.c[slot].TSAToken = []byte("token:99:" + strconv.FormatInt(time.Now().Unix(), 10))
		h.c.mu.Unlock()
	}
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var b map[string][]byte
	_ = json.Unmarshal(h.st.uploads[0].Bundle, &b)
	if !strings.HasPrefix(string(b["ts"]), "token:99:") {
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
	d := DefaultDeadlines
	if w := d.Worst(); w > 115*time.Second {
		t.Fatalf("worst case %v", w)
	}
	// The lead covers everything from the checks to the token.
	// The claim (3), the lease, the intent, the sign, keeping, journaling
	// and marking it, then the TSA.
	if d.Lead() < d.Site+8*d.Claims+d.Key+d.TSA {
		t.Fatal("the lead is shorter than the steps before the TSA")
	}
	// A re-timestamped token still pairs with an entry asked for at once.
	if after := d.RetimestampAfter(); after-d.toMark() < 7*time.Minute || after+d.Rekor+3*d.Claims+d.Margin >= 600*time.Second {
		t.Fatalf("re-timestamp after %v", after)
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

// reasons are the retimestamp notes' reasons.
func (j *memJournal) reasons() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var r []string
	for _, n := range j.notes {
		if n.Kind == NoteRetimestamp {
			r = append(r, n.Reason)
		}
	}
	return r
}

// A kept token too old to pair with an entry is replaced by a fresh one for
// the same signature, before the entry; never a second sign.
func TestRetimestampStale(t *testing.T) {
	h := newHarness(t)
	h.c.failOn = "attempt" // the first call stops before the attempt mark
	h.a.clock = func() time.Time { return time.Now().Add(-20 * time.Minute) }
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	h.a.clock = time.Now
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 201 {
		t.Fatalf("%+v %v", r, err)
	}
	h.counts(t, 1, 2, 1, 1)
	if got := h.j.reasons(); len(got) != 1 || got[0] != "stale_token" {
		t.Fatalf("retimestamps %v", got)
	}
	// Prepare judged the second call at now plus the lead, as the bundle
	// carries a fresh token.
	if time.Until(h.st.opts.At) < DefaultDeadlines.Lead()-time.Second {
		t.Fatalf("judged at %v", h.st.opts.At)
	}
	var b map[string][]byte
	_ = json.Unmarshal(h.st.uploads[0].Bundle, &b)
	if tt, _ := h.a.TokenTime(b["ts"]); time.Since(tt) > time.Minute {
		t.Fatalf("the bundle carries the old token (%v)", tt)
	}
}

// Once an entry may exist, a stale token is never replaced before the
// entry; an entry integrated too late for the kept token gets a fresh
// token right after it, on that entry's claim only.
func TestRetimestampLateEntry(t *testing.T) {
	h := newHarness(t)
	h.a.failEnter = 1
	h.a.clock = func() time.Time { return time.Now().Add(-20 * time.Minute) }
	_, _ = h.s.Handle(context.Background(), req)
	if c, _ := h.c.Get(context.Background(), slot); !c.EnterAttempted {
		t.Fatal("no attempt mark before Rekor")
	}
	h.a.clock = time.Now
	r, err := h.s.Handle(context.Background(), req)
	if err != nil || r.Status != 201 {
		t.Fatalf("%+v %v", r, err)
	}
	h.counts(t, 1, 2, 2, 1)
	if got := h.j.reasons(); len(got) != 1 || got[0] != "late_entry" {
		t.Fatalf("retimestamps %v", got)
	}
}

// An entry integrated long ago, too late for its token, can't be helped
// by a fresh token: the claim is left, and it alarms.
func TestLateEntryTooLate(t *testing.T) {
	h := newHarness(t)
	h.a.clock = func() time.Time { return time.Now().Add(-40 * time.Minute) }
	h.a.entryClock = func() time.Time { return time.Now().Add(-20 * time.Minute) }
	h.a.failBundle = 2
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	if got := h.j.reasons(); len(got) != 0 {
		t.Fatalf("retimestamps %v", got)
	}
}

// A resume is judged at the kept token's time, not at now.
func TestResumeAtTokenTime(t *testing.T) {
	h := newHarness(t)
	h.a.failEnter = 1
	at := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	h.a.clock = func() time.Time { return at }
	_, _ = h.s.Handle(context.Background(), req)
	_, _ = h.s.Handle(context.Background(), req)
	if !h.st.opts.At.Equal(at) {
		t.Fatalf("the resume was judged at %v, not the token's %v", h.st.opts.At, at)
	}
}

// A Sign whose answer is lost is journaled as of unknown outcome, with the
// request id.
func TestSignOutcomeUnknown(t *testing.T) {
	h := newHarness(t)
	h.a.failSign = true
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	k := h.j.kinds()
	if len(k) != 2 || k[0] != NoteIntent || k[1] != NoteOutcomeUnknown || h.j.notes[1].KMSRequestID != "req-lost" ||
		h.j.notes[1].AttemptID != h.j.notes[0].AttemptID {
		t.Fatalf("notes %+v", h.j.notes)
	}
}

// A kept but unjournaled signature is journaled even when the site
// already holds the document; a held document with no bundle read is an
// error, never a sign.
func TestHeldPaths(t *testing.T) {
	h := newHarness(t)
	h.j.failSign = 1
	_, _ = h.s.Handle(context.Background(), req)
	h.st.published, h.st.held = true, []byte(`{"held":1}`)
	if _, err := h.s.Handle(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(h.j.signs) != 1 {
		t.Fatalf("journal %+v", h.j.signs)
	}
	h2 := newHarness(t)
	h2.st.published = true
	if _, err := h2.s.Handle(context.Background(), req); err == nil {
		t.Fatal("a held document with no bundle passed")
	}
	h2.counts(t, 0, 0, 0, 0)
}

// A bundle that fails is tried once more from the claim before it alarms.
func TestBundleRetried(t *testing.T) {
	h := newHarness(t)
	h.a.failBundle = 1
	if r, err := h.s.Handle(context.Background(), req); err != nil || r.Status != 201 {
		t.Fatalf("%+v %v", r, err)
	}
	h3 := newHarness(t)
	h3.a.failBundle = 2
	if _, err := h3.s.Handle(context.Background(), req); err == nil {
		t.Fatal("a bundle failing twice passed")
	}
}

// A kept entry late for its kept token: Prepare is judged at about when
// the fresh token will be taken, not at the old token.
func TestPrepareBeforeLateToken(t *testing.T) {
	h := newHarness(t)
	h.a.clock = func() time.Time { return time.Now().Add(-40 * time.Minute) }
	h.a.entryClock = func() time.Time { return time.Now().Add(-20 * time.Minute) }
	h.st.answers = []answer{{503, "unavailable", false}}
	_, _ = h.s.Handle(context.Background(), req) // kept: the token and the late entry
	h.a.clock = time.Now
	_, _ = h.s.Handle(context.Background(), req)
	if time.Until(h.st.opts.At) < 0 {
		t.Fatalf("judged at %v, the old token's time", h.st.opts.At)
	}
}

// A kept token that doesn't parse alarms and is retried, never signed
// over.
func TestUnparseableToken(t *testing.T) {
	h := newHarness(t)
	h.a.failEnter = 1
	_, _ = h.s.Handle(context.Background(), req)
	h.c.mu.Lock()
	h.c.c[slot].TSAToken = []byte("junk")
	h.c.mu.Unlock()
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	h.counts(t, 1, 1, 1, 0)
}

// A signature under another key: journaled raw, and nothing more is signed.
func TestKeyMismatch(t *testing.T) {
	h := newHarness(t)
	h.a.mismatch = true
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	k := h.j.kinds()
	if len(k) != 2 || k[1] != NoteUnkept || h.j.notes[1].Signature == nil {
		t.Fatalf("notes %+v", h.j.notes)
	}
	h.a.mismatch = false
	if _, err := h.s.Handle(context.Background(), req); err == nil || h.a.signs != 1 {
		t.Fatalf("signed again after a mismatch: %v, %d signs", err, h.a.signs)
	}
}

// With no identity keys compiled in, nothing is signed.
func TestNoServiceIKs(t *testing.T) {
	h := newHarness(t)
	h.s.ServiceIKs = nil
	if _, err := h.s.Handle(context.Background(), req); err == nil {
		t.Fatal("no error")
	}
	h.counts(t, 0, 0, 0, 0)
}
