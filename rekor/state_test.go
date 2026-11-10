package rekor

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeProver answers consistency proofs from a table, or with err.
type fakeProver struct {
	proofs map[[2]int64][]string
	tree   string // if set, only proofs of this tree are answered
	err    error
	asked  int
}

func (f *fakeProver) ConsistencyProof(_ context.Context, first, last int64, treeID string) ([]string, error) {
	f.asked++
	if f.err != nil {
		return nil, f.err
	}
	if f.tree != "" && treeID != f.tree {
		return nil, ErrBadAnswer
	}
	return f.proofs[[2]int64{first, last}], nil
}

// The fixtures' checkpoints: before and after, and the proof between.
func fixturePin(t *testing.T) (a, b *Checkpoint, p *fakeProver) {
	t.Helper()
	logs := stagingLogs(t)
	var before, after LogInfo
	fixture(t, "log-before.json", &before)
	fixture(t, "log-after.json", &after)
	var pr struct {
		Hashes []string `json:"hashes"`
	}
	fixture(t, "proof.json", &pr)
	a, err := VerifyCheckpoint(before.SignedTreeHead, host, logs, at)
	if err != nil {
		t.Fatal(err)
	}
	b, err = VerifyCheckpoint(after.SignedTreeHead, host, logs, at)
	if err != nil {
		t.Fatal(err)
	}
	return a, b, &fakeProver{proofs: map[[2]int64][]string{{int64(a.Size), int64(b.Size)}: pr.Hashes}}
}

func stateAt(cp *Checkpoint) LoadedState {
	s := State{}
	s.record(cp)
	return ParseState(s.Encode())
}

func TestParseState(t *testing.T) {
	a, _, _ := fixturePin(t)
	ok := State{}
	ok.record(a)
	ok.Failures = 2
	ok.ScanAt(a.TreeID, 7)
	if ls := ParseState(ok.Encode()); ls.Kind != StateOK || ls.State.Failures != 2 || *ls.State.ScannedTo != 7 {
		t.Fatalf("round trip: %+v", ls)
	}
	// The scan at 0 (a new shard) survives its write-back; no scan at all
	// too (production).
	zero := ok
	zero.ScanAt(a.TreeID, 0)
	if ls := ParseState(zero.Encode()); ls.Kind != StateOK || ls.State.ScannedTo == nil || *ls.State.ScannedTo != 0 {
		t.Fatalf("scan at 0: %+v %s", ls, zero.Encode())
	}
	noScan := ok
	noScan.ScanTreeID, noScan.ScannedTo = "", nil
	if ls := ParseState(noScan.Encode()); ls.Kind != StateOK || ls.State.ScannedTo != nil {
		t.Fatalf("no scan: %+v", ls)
	}
	if ParseState([]byte(`{"v":1.0,"bootstrap":true}`)).Kind == StateEmpty {
		t.Error("v 1.0 read as the sentinel")
	}
	for _, raw := range []string{"", "  ", Sentinel, ` {"bootstrap": true, "v": 1} `} {
		if ls := ParseState([]byte(raw)); ls.Kind != StateEmpty {
			t.Errorf("%q: %v", raw, ls.Kind)
		}
	}
	good := string(ok.Encode())
	for name, raw := range map[string]string{
		"not json":     "{",
		"unknown":      good[:len(good)-1] + `,"x":1}`,
		"v 2":          `{"v":2` + good[6:],
		"trailing":     good + " {}",
		"short root":   string(func() []byte { s := ok; s.RootHash = s.RootHash[:62]; return s.Encode() }()),
		"origin":       string(func() []byte { s := ok; s.Origin = "x - 1"; return s.Encode() }()),
		"zero size":    string(func() []byte { s := ok; s.TreeSize = 0; return s.Encode() }()),
		"sentinel and": `{"v":1,"bootstrap":true,"x":1}`,
		"duplicate":    good[:len(good)-1] + `,"v":1}`,
		"case":         strings.Replace(good, `"tree_size"`, `"TREE_SIZE"`, 1),
		"missing":      strings.Replace(good, `"stale_runs":0,`, ``, 1),
		"scan half":    good[:len(good)-1] + `,"scanned_to":3}`,
	} {
		ls := ParseState([]byte(raw))
		if ls.Kind != StateUnparsed || len(ls.SHA256) != 64 {
			t.Errorf("%s: %v", name, ls.Kind)
		}
	}
}

func names(r *PinResult) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Name)
	}
	return out
}

func TestCheckPin(t *testing.T) {
	ctx := context.Background()
	a, b, p := fixturePin(t)
	fork := *a
	fork.Root = append([]byte(nil), a.Root...)
	fork.Root[0] ^= 1
	other := *b
	other.TreeID = "1234"
	other.Origin = host + " - 1234"

	// No state given: nothing recorded, no findings.
	r, err := CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: b, Prover: p})
	if err != nil || len(r.Findings) != 0 || r.Next != nil {
		t.Fatalf("no state given: %+v %v", r, err)
	}
	// Empty: "no state", written back as it was; bootstrap records.
	empty := ParseState([]byte(Sentinel))
	r, _ = CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p})
	if !slices.Equal(names(r), []string{FindingNoState}) || r.Next != nil {
		t.Fatalf("empty: %+v", r)
	}
	r, err = CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p, Admin: Admin{Bootstrap: true}})
	if err != nil || r.Next == nil || r.Next.TreeSize != b.Size || *r.Next.ScannedTo != b.Size || r.Next.ScanTreeID != b.TreeID {
		t.Fatalf("bootstrap: %+v %v", r, err)
	}
	// Unparseable: bootstrap only with its hash; an empty state names none.
	bad := ParseState([]byte("{"))
	if _, err := CheckPin(ctx, PinInput{Loaded: bad, Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap over unparsed, no hash: %v", err)
	}
	if r, err := CheckPin(ctx, PinInput{Loaded: bad, Current: b, Prover: p, Admin: Admin{Bootstrap: true, BootstrapReplaces: bad.SHA256}}); err != nil || r.Next == nil {
		t.Errorf("bootstrap over unparsed with its hash: %v", err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p, Admin: Admin{Bootstrap: true, BootstrapReplaces: bad.SHA256}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap over empty naming a hash: %v", err)
	}
	// Only a bootstrap applies to no state; one request at a time.
	for name, adm := range map[string]Admin{
		"accept over empty":   {AcceptShard: b.TreeID},
		"reset over empty":    {ResetPin: "1:00"},
		"bootstrap and reset": {Bootstrap: true, ResetPin: "1:00"},
		"hash alone":          {BootstrapReplaces: bad.SHA256},
	} {
		if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p, Admin: adm}); !errors.Is(err, ErrAdminRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: b}, Prover: p, Admin: Admin{AcceptShard: other.TreeID, ResetPin: "1:00"}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept and reset: %v", err)
	}
	// A state: bootstrap refused.
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap over a state: %v", err)
	}
	// Grown and consistent: recorded; the stale count reset.
	staleA := stateAt(a).State
	staleA.StaleRuns, staleA.Failures = 1, 2
	staleA.ScanAt(a.TreeID, 5)
	r, err = CheckPin(ctx, PinInput{Loaded: ParseState(staleA.Encode()), Current: b, Prover: p})
	if err != nil || len(r.Findings) != 0 || r.Next.TreeSize != b.Size || r.Next.StaleRuns != 0 || r.Next.Failures != 2 || *r.Next.ScannedTo != 5 {
		t.Fatalf("grown: %+v %v", r, err)
	}
	// Not grown: stale on the second run.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(b), Current: b, Prover: p})
	if len(r.Findings) != 0 || r.Next.StaleRuns != 1 {
		t.Fatalf("one stale run: %+v", r)
	}
	r, _ = CheckPin(ctx, PinInput{Loaded: ParseState(r.Next.Encode()), Current: b, Prover: p})
	if !slices.Equal(names(r), []string{FindingStale}) || r.Next.StaleRuns != 2 {
		t.Fatalf("two stale runs: %+v", r)
	}
	// Another root at the same size: inconsistent, the pin kept, the
	// state still returned for its counts.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: a, Prover: p})
	if !slices.Equal(names(r), []string{FindingInconsistent}) || r.Next == nil || r.Next.RootHash != hex.EncodeToString(fork.Root) {
		t.Fatalf("fork: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(b), Current: a, Prover: p}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("shrunk: %+v", r)
	}
	// A reset names the pin it replaces, and applies only to an
	// inconsistent one; it resets the stale count.
	wrong := "1:" + hex.EncodeToString(a.Root)
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: a, Prover: p, Admin: Admin{ResetPin: wrong}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset naming another pin: %v", err)
	}
	forkStale := stateAt(&fork).State
	forkStale.StaleRuns = 1
	r, err = CheckPin(ctx, PinInput{Loaded: ParseState(forkStale.Encode()), Current: a, Prover: p, Admin: Admin{ResetPin: formatPin(forkStale)}})
	if err != nil || r.Next == nil || r.Next.RootHash != hex.EncodeToString(a.Root) || r.Next.StaleRuns != 0 {
		t.Fatalf("reset: %+v %v", r, err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p, Admin: Admin{ResetPin: formatPin(stateAt(a).State)}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset of a consistent pin: %v", err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrUnavailable}, Admin: Admin{ResetPin: formatPin(stateAt(a).State)}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset of an unproven pin: %v", err)
	}
	// A changed shard: a finding until accepted, the scan withheld, the
	// stale count reset; acceptance needs the old tree inactive and
	// consistent, and resets the count too.
	r, _ = CheckPin(ctx, PinInput{Loaded: ParseState(staleA.Encode()), Current: &other, Prover: p})
	if !slices.Equal(names(r), []string{FindingShardChanged}) || !r.ShardChanged || r.Next == nil || r.Next.TreeID != a.TreeID || r.Next.StaleRuns != 0 {
		t.Fatalf("shard changed: %+v", r)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Prover: p, Admin: Admin{AcceptShard: other.TreeID}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept with the old tree not inactive: %v", err)
	}
	inactive := map[string]*Checkpoint{a.TreeID: b}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: inactive, Prover: p, Admin: Admin{AcceptShard: "999"}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept of another tree: %v", err)
	}
	r, err = CheckPin(ctx, PinInput{Loaded: ParseState(staleA.Encode()), Current: &other, Inactive: inactive, Prover: p, Admin: Admin{AcceptShard: other.TreeID}})
	if err != nil || r.Next == nil || r.Next.TreeID != other.TreeID || r.Next.StaleRuns != 0 {
		t.Fatalf("accept: %+v %v", r, err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: a}, Prover: p, Admin: Admin{AcceptShard: other.TreeID}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept from an inconsistent pin: %v", err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p, Admin: Admin{AcceptShard: b.TreeID}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept of the same tree: %v", err)
	}
	// The newest bundle binds every run; an admin step refuses while it is
	// contradicted or unproven.
	r, _ = CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: a, Bundle: &fork, Prover: p})
	if !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Fatalf("bundle forked: %+v", r)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: a, Bundle: &fork, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap under a forked bundle: %v", err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: b, Bundle: a, Prover: &fakeProver{err: ErrUnavailable}, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap under an unproven bundle: %v", err)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: a, Prover: p}); len(r.Findings) != 0 {
		t.Errorf("bundle consistent: %+v", r)
	}
	// A bundle larger than the run's checkpoint is proved forward, not
	// taken as a shrink.
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: a, Bundle: b, Prover: p}); len(r.Findings) != 0 || r.Unavailable != nil {
		t.Errorf("bundle ahead of the run: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: &other, Prover: p}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("bundle in an unknown shard: %+v", r)
	}
	// A proof request with no answer: Unavailable, with any finding already
	// proven kept; nothing moved.
	forkB := *b
	forkB.Root = append([]byte(nil), b.Root...)
	forkB.Root[0] ^= 1
	r, err = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: &forkB, Prover: &fakeProver{err: ErrUnavailable}})
	if err != nil || !errors.Is(r.Unavailable, ErrUnavailable) || !slices.Equal(names(r), []string{FindingInconsistent}) || r.Next.TreeSize != a.Size {
		t.Fatalf("no answer after a proven fork: %+v %v", r, err)
	}
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrUnavailable}})
	if !errors.Is(r.Unavailable, ErrUnavailable) || len(r.Findings) != 0 || r.Next.TreeSize != a.Size {
		t.Fatalf("no answer: %+v", r)
	}
	// A bad answer is inconsistent; a gone endpoint is search unavailable.
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrBadAnswer}}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("bad answer: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrGone}}); !slices.Equal(names(r), []string{FindingUnavailable}) || r.Unavailable != nil {
		t.Errorf("gone: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{proofs: map[[2]int64][]string{{int64(a.Size), int64(b.Size)}: {hex.EncodeToString(make([]byte, 32))}}}}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("wrong proof: %+v", r)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("admin without a state: %v", err)
	}
	// The run's context ending during a proof: stopped (incomplete), not
	// unavailable.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: context.DeadlineExceeded}})
	if !errors.Is(r.Stopped, context.DeadlineExceeded) || r.Unavailable != nil || r.Next.TreeSize != a.Size {
		t.Errorf("stopped: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: context.Canceled}}); !errors.Is(r.Stopped, context.Canceled) || r.Unavailable != nil {
		t.Errorf("cancelled: %+v", r)
	}
	// A stopped proof refuses an admin step.
	if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: b, Bundle: a, Prover: &fakeProver{err: context.Canceled}, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap after a stopped proof: %v", err)
	}
	// A reset of a pin the run failed to prove, in upper-case hex too.
	grown := stateAt(a).State
	if r, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrBadAnswer}, Admin: Admin{ResetPin: formatPin(grown)}}); err != nil || r.Next.TreeSize != b.Size {
		t.Errorf("reset after a bad answer (unproven, named by the owner): %+v %v", r, err)
	}
	if r, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{proofs: map[[2]int64][]string{{int64(a.Size), int64(b.Size)}: {hex.EncodeToString(make([]byte, 32))}}}, Admin: Admin{ResetPin: formatPin(grown)}}); err != nil || r.Next.TreeSize != b.Size {
		t.Errorf("reset after a failed proof: %+v %v", r, err)
	}
}

func formatPin(s State) string { return itoa(s.TreeSize) + ":" + s.RootHash }

func itoa(n uint64) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			return string(b)
		}
	}
}

func TestFailures(t *testing.T) {
	n, alarm := 0, false
	for range 2 {
		n, alarm = Failures(n, true, false)
	}
	if n != 2 || alarm {
		t.Fatalf("%d %v", n, alarm)
	}
	if n2, _ := Failures(n, false, true); n2 != 2 {
		t.Errorf("an incomplete run changed the count: %d", n2)
	}
	if n, alarm = Failures(n, true, false); n != 3 || !alarm {
		t.Errorf("third: %d %v", n, alarm)
	}
	if n, _ = Failures(n, false, false); n != 0 {
		t.Errorf("a complete run kept %d", n)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	es, _ := os.ReadDir(dir)
	if string(b) != "two" || len(es) != 1 {
		t.Fatalf("%q, %d files", b, len(es))
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "x"), nil); err == nil {
		t.Error("wrote into a missing directory")
	}
}

func TestCheckPinRound2(t *testing.T) {
	ctx := context.Background()
	a, b, p := fixturePin(t)
	other := *b
	other.TreeID, other.Origin = "1234", host+" - 1234"

	// Another origin for the recorded tree, or the bundle's: inconsistent.
	evil := stateAt(a).State
	evil.Origin = "evil.example - " + a.TreeID
	r, _ := CheckPin(ctx, PinInput{Loaded: ParseState(evil.Encode()), Current: b, Prover: p})
	if !slices.Equal(names(r), []string{FindingInconsistent}) || r.Next.Origin != evil.Origin {
		t.Errorf("state's origin: %+v", r)
	}
	evilB := *a
	evilB.Origin = "evil.example - " + a.TreeID
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: &evilB, Prover: p}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("bundle's origin: %+v", r)
	}
	// A bundle in an inactive shard past its final size: inconsistent, no
	// proof asked; within it, consistent, so a changed shard is the only
	// finding.
	np := &fakeProver{err: ErrUnavailable}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: a}, Bundle: b, Prover: np}); !slices.Contains(names(r), FindingInconsistent) || np.asked != 0 {
		t.Errorf("bundle past a frozen shard's final: %+v, %d asked", r, np.asked)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: b}, Bundle: a, Prover: p}); !slices.Equal(names(r), []string{FindingShardChanged}) {
		t.Errorf("bundle in a known inactive shard: %+v", r)
	}
	// A forked bundle ahead of the run: the forward proof fails.
	forkB := *b
	forkB.Root = append([]byte(nil), b.Root...)
	forkB.Root[0] ^= 1
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: a, Bundle: &forkB, Prover: p}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("forked bundle ahead: %+v", r)
	}
	// An empty active shard: admin steps refused.
	emptyCur := &Checkpoint{Origin: other.Origin, TreeID: other.TreeID, Size: 0, Root: make([]byte, 32)}
	for name, in := range map[string]PinInput{
		"bootstrap": {Loaded: ParseState([]byte(Sentinel)), Current: emptyCur, Prover: p, Admin: Admin{Bootstrap: true}},
		"accept":    {Loaded: stateAt(a), Current: emptyCur, Inactive: map[string]*Checkpoint{a.TreeID: b}, Prover: p, Admin: Admin{AcceptShard: other.TreeID}},
	} {
		if _, err := CheckPin(ctx, in); !errors.Is(err, ErrAdminRefused) {
			t.Errorf("%s at size 0: %v", name, err)
		}
	}
	// Error classes: the cap is stopped; anything unclassified a mismatch.
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrCap}}); !errors.Is(r.Stopped, ErrCap) || r.Unavailable != nil {
		t.Errorf("cap: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: errors.New("odd")}}); !slices.Equal(names(r), []string{FindingInconsistent}) || r.Unavailable != nil {
		t.Errorf("unclassified: %+v", r)
	}
	// A proof with a non-hex hash: inconsistent (a bad answer).
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{proofs: map[[2]int64][]string{{int64(a.Size), int64(b.Size)}: {"zz"}}}}); !slices.Equal(names(r), []string{FindingInconsistent}) {
		t.Errorf("non-hex proof: %+v", r)
	}
	// A reset during a shard change is refused.
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Prover: p, Admin: Admin{ResetPin: formatPin(stateAt(a).State)}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset during a shard change: %v", err)
	}
	// No checkpoint: an error, not a panic.
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Prover: p}); err == nil {
		t.Error("no checkpoint")
	}
	// Acceptance asks the old tree for its proof, and says it accepted.
	treeP := &fakeProver{proofs: p.proofs, tree: a.TreeID}
	r, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: b}, Prover: treeP, Admin: Admin{AcceptShard: other.TreeID}})
	if err != nil || !r.Accepted || treeP.asked != 1 {
		t.Errorf("accept: %+v %v, %d asked", r, err, treeP.asked)
	}
	// Counts are unchanged on an inconsistent run.
	counted := stateAt(b).State
	counted.Failures = 2
	counted.ScanAt(b.TreeID, 9)
	if r, _ := CheckPin(ctx, PinInput{Loaded: ParseState(counted.Encode()), Current: a, Prover: p}); r.Next.Failures != 2 || *r.Next.ScannedTo != 9 {
		t.Errorf("counts on an inconsistent run: %+v", r.Next)
	}
	// A reset to a smaller tree clamps the scan to it.
	counted.ScanAt(b.TreeID, b.Size)
	r, err = CheckPin(ctx, PinInput{Loaded: ParseState(counted.Encode()), Current: a, Prover: p, Admin: Admin{ResetPin: strings.ToUpper(formatPin(counted))}})
	if err != nil || *r.Next.ScannedTo != a.Size || r.Next.TreeSize != a.Size {
		t.Errorf("reset clamps the scan: %+v %v", r, err)
	}
	// Strictness: negative counts, the scan pair half empty.
	ok := stateAt(a).State
	for name, raw := range map[string]string{
		"negative failures": strings.Replace(string(ok.Encode()), `"failures":0`, `"failures":-1`, 1),
		"negative stale":    strings.Replace(string(ok.Encode()), `"stale_runs":0`, `"stale_runs":-1`, 1),
		"empty scan tree":   string(ok.Encode())[:len(ok.Encode())-1] + `,"scan_tree_id":"","scanned_to":5}`,
	} {
		if ParseState([]byte(raw)).Kind != StateUnparsed {
			t.Errorf("%s accepted", name)
		}
	}
	// A bootstrap's hash compares in any case.
	bad := ParseState([]byte("{"))
	if _, err := CheckPin(ctx, PinInput{Loaded: bad, Current: b, Prover: p, Admin: Admin{Bootstrap: true, BootstrapReplaces: strings.ToUpper(bad.SHA256)}}); err != nil {
		t.Errorf("upper-case hash: %v", err)
	}
	// Failures: a run both unavailable and incomplete adds one (an answer
	// was missing).
	if n, _ := Failures(1, true, true); n != 2 {
		t.Errorf("unavailable and incomplete: %d", n)
	}
}
