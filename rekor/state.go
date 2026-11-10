package rekor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// State is the Rekor check's state between runs (VOTES-SITE §7, "The
// state"): the recorded checkpoint, the counts, and staging's scan
// position. Between runs it is an SSM parameter; the check reads and
// writes a file.
type State struct {
	V         int    `json:"v"`
	Origin    string `json:"origin"`
	TreeID    string `json:"tree_id"`
	TreeSize  uint64 `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	StaleRuns int    `json:"stale_runs"`
	Failures  int    `json:"failures"`
	// Staging's scan: the tree it reads and the index within that tree it
	// has read to (0 included); both or neither.
	ScanTreeID string  `json:"scan_tree_id,omitempty"`
	ScannedTo  *uint64 `json:"scanned_to,omitempty"`
}

// ScanAt sets staging's scan position.
func (s *State) ScanAt(treeID string, to uint64) { s.ScanTreeID, s.ScannedTo = treeID, &to }

// Sentinel is what the stack creates the parameter holding (SSM holds no
// empty value): no state yet.
const Sentinel = `{"v":1,"bootstrap":true}`

// StateKind is what a stored state is.
type StateKind int

const (
	// StateNone: no state given (another branch, or the role unset): the
	// run checks no consistency from it and counts no failures.
	StateNone StateKind = iota
	// StateEmpty: empty, or the sentinel: "rekor: no state" until a
	// bootstrap.
	StateEmpty
	// StateUnparsed: doesn't parse: "rekor: no state", named by its
	// SHA-256, which a bootstrap must name to replace it.
	StateUnparsed
	// StateOK: a recorded checkpoint.
	StateOK
)

// LoadedState is a state as read.
type LoadedState struct {
	Kind  StateKind
	State State
	// Raw and SHA256 are the bytes read and their hash (hex): a run that
	// leaves a state it couldn't parse writes Raw back; the report names
	// SHA256.
	Raw    []byte
	SHA256 string
}

var (
	stateRequired = []string{"v", "origin", "tree_id", "tree_size", "root_hash", "stale_runs", "failures"}
	stateScan     = []string{"scan_tree_id", "scanned_to"}
)

// ParseState reads a stored state strictly: one JSON object with exactly
// the members of State (the scan's two together or neither), each once,
// named exactly; v 1; a checkpoint that could have been verified.
func ParseState(raw []byte) LoadedState {
	sum := sha256.Sum256(raw)
	ls := LoadedState{Raw: append([]byte(nil), raw...), SHA256: hex.EncodeToString(sum[:])}
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || isSentinel(t) {
		ls.Kind = StateEmpty
		return ls
	}
	ls.Kind = StateUnparsed
	keys, ok := objectKeys(t)
	if !ok {
		return ls
	}
	want := slices.Clone(stateRequired)
	if slices.Contains(keys, "scan_tree_id") || slices.Contains(keys, "scanned_to") {
		want = append(want, stateScan...)
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		return ls
	}
	var s State
	if json.Unmarshal(t, &s) != nil || !s.valid() {
		return ls
	}
	ls.Kind, ls.State = StateOK, s
	return ls
}

// objectKeys returns the keys of a single JSON object, refusing anything
// else, a repeated key, or data after it.
func objectKeys(b []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		k, isKey := tok.(string)
		if err != nil || !isKey || slices.Contains(keys, k) {
			return nil, false
		}
		keys = append(keys, k)
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, false
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return keys, true
}

func isSentinel(b []byte) bool {
	keys, ok := objectKeys(b)
	if !ok || len(keys) != 2 {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	return string(m["v"]) == "1" && string(m["bootstrap"]) == "true"
}

func (s State) valid() bool {
	if s.V != 1 || s.TreeSize == 0 || s.StaleRuns < 0 || s.Failures < 0 {
		return false
	}
	if _, err := strconv.ParseUint(s.TreeID, 10, 64); err != nil || !strings.HasSuffix(s.Origin, " - "+s.TreeID) {
		return false
	}
	if b, err := hex.DecodeString(s.RootHash); err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != s.RootHash {
		return false
	}
	if (s.ScanTreeID == "") != (s.ScannedTo == nil) {
		return false
	}
	if s.ScanTreeID != "" {
		if _, err := strconv.ParseUint(s.ScanTreeID, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// Checkpoint is the recorded checkpoint.
func (s State) Checkpoint() *Checkpoint {
	root, _ := hex.DecodeString(s.RootHash)
	return &Checkpoint{Origin: s.Origin, TreeID: s.TreeID, Size: s.TreeSize, Root: root}
}

func (s *State) record(cp *Checkpoint) {
	s.V, s.Origin, s.TreeID, s.TreeSize, s.RootHash = 1, cp.Origin, cp.TreeID, cp.Size, hex.EncodeToString(cp.Root)
}

// Encode is the state as stored.
func (s State) Encode() []byte {
	b, _ := json.Marshal(s)
	return b
}

// WriteFileAtomic writes data to path whole: to a temporary file in the
// same directory, synced, renamed over path, and the directory synced,
// so a write cut short leaves the old file (VOTES-SITE §7, "Reading and
// writing back"). The file is 0600, as these are the check's own files;
// a symlink at path is replaced, not followed; a temporary file left by a
// process killed mid-write is named ".<name>.*" beside it.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // not supported on every platform; the rename stands
		d.Close()
	}
	return nil
}

// Findings of the checkpoint pin, by the spec's names (VOTES-SITE §7).
const (
	FindingNoState      = "no state"
	FindingInconsistent = "inconsistent"
	FindingShardChanged = "shard changed"
	FindingStale        = "stale"
	FindingUnavailable  = "search unavailable"
)

// Finding is a mismatch: its name and what was found.
type Finding struct {
	Name, Detail string
}

// Admin is what an owner-run dispatch asks of the pin (VOTES-SITE §7,
// "Clearing"); the zero value asks nothing. At most one is asked.
type Admin struct {
	// Bootstrap records the checkpoint found, on an empty or sentinel
	// state, or an unparseable one whose SHA-256 is BootstrapReplaces.
	Bootstrap         bool
	BootstrapReplaces string
	// AcceptShard is the new tree ID to accept.
	AcceptShard string
	// ResetPin names the recorded checkpoint ("<size>:<root hex>") an
	// inconsistent pin replaces.
	ResetPin string
}

func (a Admin) count() int {
	n := 0
	if a.Bootstrap {
		n++
	}
	if a.AcceptShard != "" {
		n++
	}
	if a.ResetPin != "" {
		n++
	}
	return n
}

// ErrAdminRefused is an admin request the state doesn't allow (exit 2):
// nothing is recorded.
var ErrAdminRefused = errors.New("rekor: the admin request doesn't apply to this state")

// Prover gets consistency proofs (Client.ConsistencyProof).
type Prover interface {
	ConsistencyProof(ctx context.Context, first, last int64, treeID string) ([]string, error)
}

// PinInput is what CheckPin works from: the state as loaded, the run's
// verified active checkpoint, the log's inactive shards (their verified
// final checkpoints, by tree ID, from LogInfo), and the newest published
// bundle's checkpoint (nil if none), all verified by the caller.
type PinInput struct {
	Loaded   LoadedState
	Current  *Checkpoint
	Inactive map[string]*Checkpoint
	Bundle   *Checkpoint
	Admin    Admin
	Prover   Prover
}

// PinResult is the pin's outcome.
type PinResult struct {
	// Findings are mismatches, each proven: kept whatever else fails.
	Findings []Finding
	// Next is the state to write back, for a state that parsed (its counts
	// for the caller to update: Failures, staging's scan) or one an admin
	// step recorded; nil for no state, an empty or unparseable one (write
	// back Raw unchanged).
	Next *State
	// ShardChanged: a tree ID other than the recorded one, not accepted:
	// the run withholds the scan, and still searches and verifies entries.
	ShardChanged bool
	// Unavailable is a proof request that got no answer (ErrUnavailable,
	// or another error from the request): for "Rekor unavailable". What
	// it would have proven is unknown; nothing it would have moved moved.
	Unavailable error
	// Stopped is the run's context ending during a proof request: the run
	// is incomplete, neither adding to failures nor resetting them.
	Stopped error

	contradicted bool // a proof that failed, not a bad answer
}

func (r *PinResult) add(name, format string, a ...any) {
	r.Findings = append(r.Findings, Finding{Name: name, Detail: fmt.Sprintf(format, a...)})
}

// prove checks b's tree extends a's, fetching a proof when b is larger.
// It returns true if it does; otherwise it records the finding (a proof
// that fails or a bad answer: inconsistent; a gone endpoint: search
// unavailable) or the request that got no answer, and returns false.
func (r *PinResult) prove(ctx context.Context, p Prover, a, b *Checkpoint, what string) bool {
	var hashes []string
	if a.TreeID == b.TreeID && b.Size > a.Size {
		var err error
		hashes, err = p.ConsistencyProof(ctx, int64(a.Size), int64(b.Size), b.TreeID)
		switch {
		case errors.Is(err, ErrGone):
			r.add(FindingUnavailable, "%s: %v", what, err)
			return false
		case errors.Is(err, ErrBadAnswer):
			r.add(FindingInconsistent, "%s: %v", what, err)
			return false
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			if r.Stopped == nil {
				r.Stopped = err
			}
			return false
		case err != nil:
			if r.Unavailable == nil {
				r.Unavailable = err
			}
			return false
		}
	}
	if err := VerifyConsistency(a, b, hashes); err != nil {
		r.add(FindingInconsistent, "%s: %v", what, err)
		r.contradicted = true
		return false
	}
	return true
}

// CheckPin checks the run's checkpoint against the recorded one and the
// newest bundle's (VOTES-SITE §7, "The checkpoint", "Freshness",
// "Shards", "Clearing"). It never moves the pin to a checkpoint not
// proven consistent with it, except by an admin step the spec allows. An
// admin request that doesn't apply is ErrAdminRefused, with nothing
// recorded.
func CheckPin(ctx context.Context, in PinInput) (*PinResult, error) {
	res := &PinResult{}
	cur, a, ls := in.Current, in.Admin, in.Loaded
	if a.count() > 1 || a.BootstrapReplaces != "" && !a.Bootstrap {
		return nil, fmt.Errorf("%w: one admin request at a time", ErrAdminRefused)
	}
	// The newest bundle's checkpoint binds every run, with or without a
	// state, so a state rolled back or reset can't take the check below
	// it. A bundle larger than the run's (published during the run, or a
	// lagging view) is proved from the run's up to it.
	if b := in.Bundle; b != nil {
		target := cur
		if b.TreeID != cur.TreeID {
			target = in.Inactive[b.TreeID]
		}
		switch {
		case target == nil:
			res.add(FindingInconsistent, "the newest bundle's tree %s is neither the active nor an inactive shard", b.TreeID)
		case b.Size > target.Size:
			res.prove(ctx, in.Prover, target, b, "the newest bundle's checkpoint, from the log's")
		default:
			res.prove(ctx, in.Prover, b, target, "the log's checkpoint, from the newest bundle's")
		}
	}
	// An admin step never records a pin the newest bundle contradicts, or
	// that it couldn't be checked against: a transient outage refuses it
	// too (exit 2), and the owner dispatches it again.
	if a.count() > 0 && (len(res.Findings) > 0 || res.Unavailable != nil || res.Stopped != nil) {
		return nil, fmt.Errorf("%w: the newest bundle's checkpoint isn't proven consistent with the log's", ErrAdminRefused)
	}
	switch ls.Kind {
	case StateNone:
		if a.count() > 0 {
			return nil, fmt.Errorf("%w: no state given", ErrAdminRefused)
		}
		return res, nil
	case StateEmpty, StateUnparsed:
		if !a.Bootstrap {
			if a.count() > 0 {
				return nil, fmt.Errorf("%w: only a bootstrap applies to no state", ErrAdminRefused)
			}
			res.add(FindingNoState, "the state is empty, the sentinel, or doesn't parse (sha256 %s)", ls.SHA256)
			return res, nil
		}
		if ls.Kind == StateUnparsed && a.BootstrapReplaces != ls.SHA256 {
			return nil, fmt.Errorf("%w: the state doesn't parse; a bootstrap must name its SHA-256 %s", ErrAdminRefused, ls.SHA256)
		}
		if ls.Kind == StateEmpty && a.BootstrapReplaces != "" {
			return nil, fmt.Errorf("%w: the state is empty; a bootstrap names no hash", ErrAdminRefused)
		}
		next := &State{}
		next.record(cur)
		next.ScanAt(cur.TreeID, cur.Size)
		res.Next = next
		return res, nil
	}
	if a.Bootstrap {
		return nil, fmt.Errorf("%w: a bootstrap applies only to an empty, sentinel or unparseable state", ErrAdminRefused)
	}
	st := ls.State
	next := st
	res.Next = &next
	rec := st.Checkpoint()

	if cur.TreeID != st.TreeID {
		if a.AcceptShard == "" {
			res.add(FindingShardChanged, "the active tree is %s; the recorded one is %s", cur.TreeID, st.TreeID)
			res.ShardChanged = true
			next.StaleRuns = 0
			return res, nil
		}
		if a.AcceptShard != cur.TreeID {
			return nil, fmt.Errorf("%w: the active tree is %s, not %s", ErrAdminRefused, cur.TreeID, a.AcceptShard)
		}
		old := in.Inactive[st.TreeID]
		if old == nil {
			return nil, fmt.Errorf("%w: the recorded tree %s isn't among the inactive shards", ErrAdminRefused, st.TreeID)
		}
		var check PinResult
		if !check.prove(ctx, in.Prover, rec, old, "the recorded checkpoint, to the old shard's final one") {
			return nil, fmt.Errorf("%w: the recorded checkpoint isn't proven consistent with tree %s's final one (%v %v)", ErrAdminRefused, st.TreeID, check.Findings, check.Unavailable)
		}
		next.record(cur)
		next.StaleRuns = 0
		return res, nil
	}
	if a.AcceptShard != "" {
		return nil, fmt.Errorf("%w: the tree hasn't changed", ErrAdminRefused)
	}
	var pin PinResult
	ok := pin.prove(ctx, in.Prover, rec, cur, "the log's checkpoint, from the recorded one")
	if a.ResetPin != "" {
		// Only a log shown contradicting the pin (a proof that failed, a
		// shrunk tree, another root), not a malformed answer.
		if ok || !pin.contradicted {
			return nil, fmt.Errorf("%w: a reset applies only to a pin the log was shown to contradict", ErrAdminRefused)
		}
		if a.ResetPin != fmt.Sprintf("%d:%s", st.TreeSize, st.RootHash) {
			return nil, fmt.Errorf("%w: the reset names %q, not the recorded %d:%s", ErrAdminRefused, a.ResetPin, st.TreeSize, st.RootHash)
		}
		next.record(cur)
		next.StaleRuns = 0
		return res, nil
	}
	res.Findings = append(res.Findings, pin.Findings...)
	if res.Unavailable == nil {
		res.Unavailable = pin.Unavailable
	}
	if res.Stopped == nil {
		res.Stopped = pin.Stopped
	}
	if !ok {
		// The recorded checkpoint is kept, so every later run reports it
		// (or proves it, once Rekor answers).
		return res, nil
	}
	if cur.Size == st.TreeSize {
		next.StaleRuns = st.StaleRuns + 1
		if next.StaleRuns >= 2 {
			res.add(FindingStale, "the tree has stayed at size %d for %d runs", cur.Size, next.StaleRuns)
		}
	} else {
		next.StaleRuns = 0
	}
	next.record(cur)
	return res, nil
}

// Failures updates the count of runs whose Rekor requests got no answer
// (VOTES-SITE §7, "Rekor unavailable"): unavailable adds one; a run that
// got every answer resets it; an incomplete one neither adds nor resets.
// It returns the new count and whether it is the "search unavailable"
// mismatch (3 in a row).
func Failures(prev int, unavailable, incomplete bool) (int, bool) {
	switch {
	case unavailable:
		prev++
	case !incomplete:
		prev = 0
	}
	return prev, prev >= 3
}
