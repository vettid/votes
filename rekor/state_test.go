package rekor

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// fakeProver answers consistency proofs from a table, or with err.
type fakeProver struct {
	proofs map[[2]int64][]string
	err    error
	asked  int
}

func (f *fakeProver) ConsistencyProof(_ context.Context, first, last int64, _ string) ([]string, error) {
	f.asked++
	if f.err != nil {
		return nil, f.err
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
	ok.Failures, ok.ScanTreeID, ok.ScannedTo = 2, a.TreeID, 7
	if ls := ParseState(ok.Encode()); ls.Kind != StateOK || ls.State != ok {
		t.Fatalf("round trip: %+v", ls)
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
	} {
		ls := ParseState([]byte(raw))
		if ls.Kind != StateUnparsed || len(ls.SHA256) != 64 {
			t.Errorf("%s: %v", name, ls.Kind)
		}
	}
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

	// No state given: nothing recorded, trusted.
	r, err := CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: b, Prover: p})
	if err != nil || len(r.Findings) != 0 || r.Next != nil || !r.Trusted {
		t.Fatalf("no state given: %+v %v", r, err)
	}
	// Empty: "no state", written back as it was; bootstrap records.
	empty := ParseState([]byte(Sentinel))
	r, _ = CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p})
	if !slices.Equal(r.Findings, []string{FindingNoState}) || r.Next != nil || r.Trusted {
		t.Fatalf("empty: %+v", r)
	}
	r, err = CheckPin(ctx, PinInput{Loaded: empty, Current: b, Prover: p, Admin: Admin{Bootstrap: true}})
	if err != nil || r.Next == nil || r.Next.TreeSize != b.Size || r.Next.ScannedTo != b.Size || r.Next.ScanTreeID != b.TreeID {
		t.Fatalf("bootstrap: %+v %v", r, err)
	}
	// Unparseable: bootstrap only with its hash.
	bad := ParseState([]byte("{"))
	if _, err := CheckPin(ctx, PinInput{Loaded: bad, Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap over unparsed, no hash: %v", err)
	}
	if r, err := CheckPin(ctx, PinInput{Loaded: bad, Current: b, Prover: p, Admin: Admin{Bootstrap: true, BootstrapReplaces: bad.SHA256}}); err != nil || r.Next == nil {
		t.Errorf("bootstrap over unparsed with its hash: %v", err)
	}
	// A state: bootstrap refused.
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap over a state: %v", err)
	}
	// Grown and consistent: recorded, trusted.
	r, err = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p})
	if err != nil || len(r.Findings) != 0 || !r.Trusted || r.Next.TreeSize != b.Size || r.Next.StaleRuns != 0 {
		t.Fatalf("grown: %+v %v", r, err)
	}
	// Not grown: stale on the second run.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(b), Current: b, Prover: p})
	if len(r.Findings) != 0 || r.Next.StaleRuns != 1 {
		t.Fatalf("one stale run: %+v", r)
	}
	r, _ = CheckPin(ctx, PinInput{Loaded: ParseState(r.Next.Encode()), Current: b, Prover: p})
	if !slices.Equal(r.Findings, []string{FindingStale}) || r.Next.StaleRuns != 2 || r.Trusted {
		t.Fatalf("two stale runs: %+v", r)
	}
	// Another root at the same size: inconsistent, the pin kept.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: a, Prover: p})
	if !slices.Equal(r.Findings, []string{FindingInconsistent}) || r.Next != nil || r.Trusted {
		t.Fatalf("fork: %+v", r)
	}
	// A shrunk tree: inconsistent.
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(b), Current: a, Prover: p}); !slices.Equal(r.Findings, []string{FindingInconsistent}) {
		t.Errorf("shrunk: %+v", r)
	}
	// A reset names the pin it replaces.
	wrong := "1:" + hex.EncodeToString(a.Root)
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: a, Prover: p, Admin: Admin{ResetPin: wrong}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset naming another pin: %v", err)
	}
	right := stateAt(&fork).State
	r, err = CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: a, Prover: p, Admin: Admin{ResetPin: formatPin(right)}})
	if err != nil || r.Next == nil || r.Next.RootHash != hex.EncodeToString(a.Root) {
		t.Fatalf("reset: %+v %v", r, err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: p, Admin: Admin{ResetPin: formatPin(stateAt(a).State)}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("reset of a consistent pin: %v", err)
	}
	// A changed shard: a finding until accepted; the scan withheld.
	r, _ = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Prover: p})
	if !slices.Equal(r.Findings, []string{FindingShardChanged}) || !r.ShardChanged || r.Next != nil {
		t.Fatalf("shard changed: %+v", r)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Prover: p, Admin: Admin{AcceptShard: other.TreeID}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept with the old tree not inactive: %v", err)
	}
	inactive := map[string]*Checkpoint{a.TreeID: b}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: inactive, Prover: p, Admin: Admin{AcceptShard: "999"}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept of another tree: %v", err)
	}
	r, err = CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: &other, Inactive: inactive, Prover: p, Admin: Admin{AcceptShard: other.TreeID}})
	if err != nil || r.Next == nil || r.Next.TreeID != other.TreeID || r.Next.StaleRuns != 0 {
		t.Fatalf("accept: %+v %v", r, err)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(&fork), Current: &other, Inactive: map[string]*Checkpoint{a.TreeID: a}, Prover: p, Admin: Admin{AcceptShard: other.TreeID}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("accept from an inconsistent pin: %v", err)
	}
	// The newest bundle binds every run, and an admin step refuses while
	// it is contradicted.
	r, _ = CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: a, Bundle: &fork, Prover: p})
	if !slices.Equal(r.Findings, []string{FindingBundleInconst}) || r.Trusted {
		t.Fatalf("bundle forked: %+v", r)
	}
	if _, err := CheckPin(ctx, PinInput{Loaded: empty, Current: a, Bundle: &fork, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap under a forked bundle: %v", err)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: a, Prover: p}); len(r.Findings) != 0 {
		t.Errorf("bundle consistent: %+v", r)
	}
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Bundle: &other, Prover: p}); !slices.Equal(r.Findings, []string{FindingBundleInconst}) {
		t.Errorf("bundle in an unknown shard: %+v", r)
	}
	// A proof that can't be had: the error, for the caller to classify;
	// a bad answer is a finding.
	if _, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrUnavailable}}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("no answer: %v", err)
	}
	if r, err := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{err: ErrBadAnswer}}); err != nil || !slices.Equal(r.Findings, []string{FindingInconsistent}) {
		t.Errorf("bad answer: %+v %v", r, err)
	}
	// A wrong proof: inconsistent.
	if r, _ := CheckPin(ctx, PinInput{Loaded: stateAt(a), Current: b, Prover: &fakeProver{proofs: map[[2]int64][]string{{int64(a.Size), int64(b.Size)}: {hex.EncodeToString(make([]byte, 32))}}}}); !slices.Equal(r.Findings, []string{FindingInconsistent}) {
		t.Errorf("wrong proof: %+v", r)
	}
	// No admin request with no state given.
	if _, err := CheckPin(ctx, PinInput{Loaded: LoadedState{Kind: StateNone}, Current: b, Prover: p, Admin: Admin{Bootstrap: true}}); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("admin without a state: %v", err)
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
