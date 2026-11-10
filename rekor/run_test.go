package rekor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
)

// scenario: a log with a published proposal's entry (known, 2 days old),
// another key's entry, an entry of an unknown digest, a body that isn't
// JSON, and one integrated a minute before the run (pending).
type scenario struct {
	f        *fakeLog
	anchor   []byte
	known    string
	unknown  string
	pending  string
	now      time.Time
	bundle   Bundle
	unknownI int
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	s := &scenario{f: newFakeLog(t), now: at}
	k := testKey("votes anchor key")
	s.anchor, _ = x509.MarshalPKIXPublicKey(&k.PublicKey)
	b0, d0 := anchorBody(t, k, "a proposal")
	s.known = d0
	s.f.add(b0, s.now.Add(-48*time.Hour))
	other, _ := anchorBody(t, testKey("another key"), "theirs")
	s.f.add(other, s.now.Add(-24*time.Hour))
	b2, d2 := anchorBody(t, k, "not ours to know")
	s.unknown = d2
	s.unknownI = s.f.add(b2, s.now.Add(-24*time.Hour))
	s.f.add([]byte("not json"), s.now.Add(-24*time.Hour))
	b4, d4 := anchorBody(t, k, "just now")
	s.pending = d4
	s.f.add(b4, s.now.Add(-time.Minute))
	dg, _ := hex.DecodeString(d0)
	s.bundle = Bundle{Name: "p1/proposal", Digest: dg, Leaf: rfc6962.DefaultHasher.HashLeaf(b0), LogIndex: 0, Integrated: s.now.Add(-48 * time.Hour),
		Checkpoint: s.f.checkpoint(1)}
	return s
}

func (s *scenario) input(state LoadedState, scan bool) RunInput {
	return RunInput{Instance: "staging", Host: host, Logs: s.f.l.logs, Anchors: [][]byte{s.anchor},
		Known: map[string]time.Time{s.known: s.bundle.Integrated}, Unexpected: map[string]string{},
		Bundles: []Bundle{s.bundle}, Scan: scan, State: state, Now: func() time.Time { return s.now }}
}

func findings(r *RunReport) []string {
	var out []string
	for _, m := range r.Mismatches {
		out = append(out, m.Finding)
	}
	slices.Sort(out)
	return out
}

// A bootstrap records the checkpoint and starts the scan at it; the run
// reports the unknown digest, holds the fresh entry as pending, and the
// known one as nothing.
func TestRunBootstrapAndFindings(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t)
	in := s.input(ParseState([]byte(Sentinel)), true)
	in.Admin = Admin{Bootstrap: true}
	r, err := Run(ctx, s.f, in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(findings(r), []string{FindingUnknown}) || r.Mismatches[0].SHA256 != s.unknown {
		t.Fatalf("findings %+v", r.Mismatches)
	}
	if len(r.Pending) != 1 || r.Pending[0].SHA256 != s.pending {
		t.Errorf("pending %+v", r.Pending)
	}
	st := ParseState(r.NextState)
	if st.Kind != StateOK || st.State.TreeSize != 5 || *st.State.ScannedTo != 5 || st.State.ScanTreeID != fakeTree {
		t.Fatalf("state %s", r.NextState)
	}
	// Without the state: no state, and nothing written back.
	r, _ = Run(ctx, s.f, s.input(ParseState([]byte(Sentinel)), true))
	if !slices.Contains(findings(r), FindingNoState) || r.NextState != nil {
		t.Errorf("no state: %+v", r)
	}
}

// The next run: the entries come from the store, verified again without
// a fetch; the scan reads only what was added, and finds an entry the
// search left out (index gap) and counts a body that doesn't parse.
func TestRunStoreAndScan(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t)
	in := s.input(ParseState([]byte(Sentinel)), true)
	in.Admin = Admin{Bootstrap: true}
	r1, err := Run(ctx, s.f, in)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ParseStore(r1.NextStore)
	if err != nil || len(store.Entries) != 3 {
		t.Fatalf("store: %d %v", len(store.Entries), err)
	}
	// Two more entries: one the search hides, one not JSON.
	k := testKey("votes anchor key")
	b5, _ := anchorBody(t, k, "hidden from the search")
	i5 := s.f.add(b5, s.now.Add(-12*time.Hour))
	s.f.hidden[i5] = true
	s.f.add([]byte("{not"), s.now.Add(-12*time.Hour))
	s.f.calls = map[string]int{}
	in2 := s.input(ParseState(r1.NextState), true)
	in2.Store = store
	r2, err := Run(ctx, s.f, in2)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(findings(r2), FindingIndexGap) || !slices.Contains(findings(r2), FindingUnknown) {
		t.Fatalf("findings %+v", r2.Mismatches)
	}
	if s.f.calls["entries"] != 0 {
		t.Errorf("%d entry fetches for stored entries", s.f.calls["entries"])
	}
	if r2.Scanned != 2 || r2.Unparsed != 1 {
		t.Errorf("scanned %d, unparsed %d", r2.Scanned, r2.Unparsed)
	}
	if st := ParseState(r2.NextState); *st.State.ScannedTo != 7 || st.State.TreeSize != 7 {
		t.Errorf("state %s", r2.NextState)
	}
}

// An acknowledged unknown digest is reported in acknowledged, not a
// mismatch; an acknowledgement of an entry that isn't there is one.
func TestRunAcknowledged(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t)
	id := s.f.id(s.unknownI)
	in := s.input(LoadedState{Kind: StateNone}, false)
	in.Acks = []Ack{{Instance: "staging", UUID: id, LogIndex: int64(s.unknownI), SHA256: s.unknown, Finding: FindingUnknown, Reason: "a test anchor", AcknowledgedAt: "2026-11-10"}}
	r, err := Run(ctx, s.f, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Mismatches) != 0 || len(r.Acknowledged) != 1 {
		t.Fatalf("mismatches %+v, acknowledged %+v", r.Mismatches, r.Acknowledged)
	}
	in.Acks[0].LogIndex = 99
	if r, _ := Run(ctx, s.f, in); !slices.Contains(findings(r), FindingAckStale) || !slices.Contains(findings(r), FindingUnknown) {
		t.Errorf("a wrong log index: %+v", r.Mismatches)
	}
	gone := "000000000000002a" + hex.EncodeToString(make([]byte, 32))
	in.Acks[0] = Ack{Instance: "staging", UUID: gone, LogIndex: 1, Finding: FindingUnknown, Reason: "x", AcknowledgedAt: "2026-11-10"}
	if r, _ := Run(ctx, s.f, in); !slices.Contains(findings(r), FindingUnverified) {
		t.Errorf("an entry that isn't there: %+v", r.Mismatches)
	}
}

// The canary: a published bundle whose entry the search doesn't return
// is an index gap, after ListingGrace; an entry for a known digest
// integrated more than a day after its bundle is anchored again; a digest
// that is a service list's is unexpected; a document anchored without a
// signed entry is reported.
func TestRunCanaryAndDigests(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t)
	s.f.hidden[0] = true
	in := s.input(LoadedState{Kind: StateNone}, false)
	r, _ := Run(ctx, s.f, in)
	if !slices.Contains(findings(r), FindingIndexGap) {
		t.Errorf("canary: %+v", r.Mismatches)
	}
	s.f.hidden = map[int]bool{}
	k := testKey("votes anchor key")
	again, _ := anchorBody(t, k, "a proposal")
	s.f.add(again, s.now.Add(-time.Hour))
	in.Unexpected = map[string]string{s.unknown: "service list version 3"}
	in.NoEntry = []string{"p1/results"}
	r, _ = Run(ctx, s.f, in)
	want := []string{FindingAnchoredAgain, FindingUnexpected, FindingNoEntry}
	for _, w := range want {
		if !slices.Contains(findings(r), w) {
			t.Errorf("no %s: %+v", w, r.Mismatches)
		}
	}
	if slices.Contains(findings(r), FindingUnknown) {
		t.Errorf("an unexpected digest also unknown: %+v", r.Mismatches)
	}
}

// Failures: a search with no answer counts, and only the third in a row
// is a mismatch; a gone endpoint is search unavailable at once; a forged
// answer is unverified.
func TestRunFailures(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t)
	s.f.searchErr = ErrUnavailable
	in := s.input(ParseState([]byte(Sentinel)), false)
	in.Admin = Admin{Bootstrap: true}
	r, _ := Run(ctx, s.f, in)
	st := r.NextState
	in.Admin = Admin{}
	for run := 2; run <= 3; run++ {
		in.State = ParseState(st)
		r, _ = Run(ctx, s.f, in)
		st = r.NextState
		if alarm := slices.Contains(findings(r), FindingUnavailable); alarm != (run == 3) || r.Failures != run {
			t.Fatalf("run %d: failures %d, %+v", run, r.Failures, r.Mismatches)
		}
	}
	// Production: the scan members are never written.
	if ps := ParseState(st); ps.State.ScanTreeID != "" || ps.State.ScannedTo != nil {
		t.Errorf("production state with a scan: %s", st)
	}
	s.f.searchErr = ErrGone
	if r, _ := Run(ctx, s.f, s.input(LoadedState{Kind: StateNone}, false)); !slices.Contains(findings(r), FindingUnavailable) {
		t.Errorf("gone: %+v", r.Mismatches)
	}
	s.f.searchErr = nil
	// A forged entry: its body changed under its ID.
	forged := &forgingLog{fakeLog: s.f, index: s.unknownI}
	if r, _ := Run(ctx, forged, s.input(LoadedState{Kind: StateNone}, false)); !slices.Contains(findings(r), FindingUnverified) || slices.Contains(findings(r), FindingUnknown) {
		t.Errorf("forged: %+v", r.Mismatches)
	}
	// An owner-run step when the log's checkpoint can't be had: refused.
	s.f.logErr = ErrUnavailable
	bin := s.input(ParseState([]byte(Sentinel)), true)
	bin.Admin = Admin{Bootstrap: true}
	if _, err := Run(ctx, s.f, bin); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("bootstrap without a checkpoint: %v", err)
	}
	s.f.logErr = nil
	// An admin request that doesn't apply.
	in = s.input(LoadedState{Kind: StateNone}, false)
	in.Admin = Admin{Bootstrap: true}
	if _, err := Run(ctx, s.f, in); !errors.Is(err, ErrAdminRefused) {
		t.Errorf("admin refused: %v", err)
	}
}

// forgingLog answers one entry with another body.
type forgingLog struct {
	*fakeLog
	index int
}

func (f *forgingLog) Entries(ctx context.Context, ids []string) (map[string]*Entry, error) {
	out, err := f.fakeLog.Entries(ctx, ids)
	if e := out[f.fakeLog.id(f.index)]; e != nil {
		d := sha256.Sum256([]byte("forged"))
		e.Body = e.Body[:len(e.Body)-4] + hex.EncodeToString(d[:2])
	}
	return out, err
}

func TestParseAcks(t *testing.T) {
	good := `[{"instance":"staging","uuid":"` + "000000000000002a" + hex.EncodeToString(make([]byte, 32)) + `","log_index":1,"sha256":"","finding":"wrong kind","reason":"a test","acknowledged_at":"2026-11-10"}]`
	if as, err := ParseAcks([]byte(good)); err != nil || len(as) != 1 {
		t.Fatalf("%v %v", as, err)
	}
	for name, bad := range map[string]string{
		"unverified": `"finding":"unverified"`,
		"extra":      `"finding":"wrong kind","x":1`,
		"date":       `"acknowledged_at":"10 Nov"`,
	} {
		b := good
		switch name {
		case "unverified":
			b = replace(good, `"finding":"wrong kind"`, bad)
		case "extra":
			b = replace(good, `"finding":"wrong kind"`, bad)
		case "date":
			b = replace(good, `"acknowledged_at":"2026-11-10"`, bad)
		}
		if _, err := ParseAcks([]byte(b)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseAcks([]byte(good[:len(good)-1] + "," + good[1:])); err == nil {
		t.Error("(uuid, finding) twice accepted")
	}
}

func replace(s, a, b string) string {
	for i := 0; i+len(a) <= len(s); i++ {
		if s[i:i+len(a)] == a {
			return s[:i] + b + s[i+len(a):]
		}
	}
	return s
}
