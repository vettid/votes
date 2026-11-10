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
	"strconv"
	"strings"
)

// State is the Rekor check's state between runs (VOTES-SITE §7, "The
// state"): the recorded checkpoint, the counts, and staging's scan
// position. Between runs it is an SSM parameter; the check reads and
// writes a file.
type State struct {
	V          int    `json:"v"`
	Origin     string `json:"origin"`
	TreeID     string `json:"tree_id"`
	TreeSize   uint64 `json:"tree_size"`
	RootHash   string `json:"root_hash"`
	StaleRuns  int    `json:"stale_runs"`
	Failures   int    `json:"failures"`
	ScanTreeID string `json:"scan_tree_id,omitempty"`
	ScannedTo  uint64 `json:"scanned_to,omitempty"`
}

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
	// Raw and SHA256 are the bytes read and their hash (hex), for a run
	// that writes back a state it didn't change, and for the report.
	Raw    []byte
	SHA256 string
}

// ParseState reads a stored state strictly: one JSON object of the
// members above, v 1, a checkpoint that could have been verified.
func ParseState(raw []byte) LoadedState {
	sum := sha256.Sum256(raw)
	ls := LoadedState{Raw: append([]byte(nil), raw...), SHA256: hex.EncodeToString(sum[:])}
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || isSentinel(t) {
		ls.Kind = StateEmpty
		return ls
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.DisallowUnknownFields()
	var s State
	if dec.Decode(&s) != nil || dec.More() || !s.valid() {
		ls.Kind = StateUnparsed
		return ls
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		ls.Kind = StateUnparsed
		return ls
	}
	ls.Kind, ls.State = StateOK, s
	return ls
}

func isSentinel(b []byte) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || len(m) != 2 {
		return false
	}
	return m["v"] == float64(1) && m["bootstrap"] == true
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
// same directory, synced, then renamed over it, so a write cut short
// leaves the old file (VOTES-SITE §7, "Reading and writing back").
func WriteFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
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
	return os.Rename(tmp, path)
}

// Findings of the checkpoint pin (VOTES-SITE §7).
const (
	FindingNoState       = "no state"
	FindingInconsistent  = "inconsistent"
	FindingShardChanged  = "shard changed"
	FindingStale         = "stale"
	FindingBundleInconst = "inconsistent (newest bundle)"
)

// Admin is what an owner-run dispatch asks of the pin (VOTES-SITE §7,
// "Clearing"); the zero value asks nothing.
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

// ErrAdminRefused is an admin request the state doesn't allow (exit 2).
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

// PinResult is the pin's outcome: the findings (each a mismatch), the
// state to write back (nil: write back what was read, unchanged), and
// whether consistency held from the recorded checkpoint, so that the run
// may check entries against the current one.
type PinResult struct {
	Findings []string
	Next     *State
	// Trusted: the current checkpoint may anchor the run's other checks
	// (consistent with the state's, or recorded by an admin step).
	Trusted bool
	// ShardChanged: a tree ID other than the recorded one, not accepted:
	// the run withholds the scan.
	ShardChanged bool
}

// CheckPin checks the run's checkpoint against the recorded one and the
// newest bundle's (VOTES-SITE §7, "The checkpoint", "Freshness",
// "Shards", "Clearing"). A failed proof request is returned as an error
// (the caller classifies it: ErrUnavailable counts toward "Rekor
// unavailable"); a proof that fails is a finding. An admin request that
// doesn't apply is ErrAdminRefused, with nothing recorded.
func CheckPin(ctx context.Context, in PinInput) (*PinResult, error) {
	res := &PinResult{}
	cur := in.Current
	// The newest bundle's checkpoint binds every run, with or without a
	// state, so a state rolled back or reset can't take the check below it.
	if b := in.Bundle; b != nil {
		target := cur
		if b.TreeID != cur.TreeID {
			target = in.Inactive[b.TreeID]
		}
		if target == nil {
			res.Findings = append(res.Findings, FindingBundleInconst)
		} else if err := consistent(ctx, in.Prover, b, target); err != nil {
			if !errors.Is(err, ErrInconsistent) {
				return nil, err
			}
			res.Findings = append(res.Findings, FindingBundleInconst)
		}
	}
	ls := in.Loaded
	a := in.Admin
	// An admin step never records a pin the newest bundle contradicts.
	if a != (Admin{}) && len(res.Findings) > 0 {
		return nil, fmt.Errorf("%w: the newest bundle's checkpoint isn't consistent with the log's", ErrAdminRefused)
	}
	switch ls.Kind {
	case StateNone:
		if a != (Admin{}) {
			return nil, fmt.Errorf("%w: no state given", ErrAdminRefused)
		}
		res.Trusted = len(res.Findings) == 0
		return res, nil
	case StateEmpty, StateUnparsed:
		if !a.Bootstrap {
			if a != (Admin{}) {
				return nil, fmt.Errorf("%w: only a bootstrap applies to no state", ErrAdminRefused)
			}
			res.Findings = append(res.Findings, FindingNoState)
			return res, nil
		}
		if ls.Kind == StateUnparsed && a.BootstrapReplaces != ls.SHA256 {
			return nil, fmt.Errorf("%w: the state doesn't parse; a bootstrap must name its SHA-256 %s", ErrAdminRefused, ls.SHA256)
		}
		next := &State{}
		next.record(cur)
		next.ScanTreeID, next.ScannedTo = cur.TreeID, cur.Size
		res.Next, res.Trusted = next, len(res.Findings) == 0
		return res, nil
	}
	if a.Bootstrap {
		return nil, fmt.Errorf("%w: a bootstrap applies only to an empty, sentinel or unparseable state", ErrAdminRefused)
	}
	st := ls.State
	rec := st.Checkpoint()
	next := st
	if cur.TreeID != st.TreeID {
		old := in.Inactive[st.TreeID]
		if a.AcceptShard == "" || a.AcceptShard != cur.TreeID {
			if a.AcceptShard != "" {
				return nil, fmt.Errorf("%w: the active tree is %s, not %s", ErrAdminRefused, cur.TreeID, a.AcceptShard)
			}
			res.Findings = append(res.Findings, FindingShardChanged)
			res.ShardChanged = true
			return res, nil
		}
		if old == nil {
			return nil, fmt.Errorf("%w: the recorded tree %s isn't among the inactive shards", ErrAdminRefused, st.TreeID)
		}
		if err := consistent(ctx, in.Prover, rec, old); err != nil {
			if !errors.Is(err, ErrInconsistent) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: the recorded checkpoint isn't consistent with tree %s's final one: %v", ErrAdminRefused, st.TreeID, err)
		}
		next.record(cur)
		next.StaleRuns = 0
		res.Next, res.Trusted = &next, len(res.Findings) == 0
		return res, nil
	}
	if a.AcceptShard != "" {
		return nil, fmt.Errorf("%w: the tree hasn't changed", ErrAdminRefused)
	}
	if err := consistent(ctx, in.Prover, rec, cur); err != nil {
		if !errors.Is(err, ErrInconsistent) {
			return nil, err
		}
		if a.ResetPin != "" {
			if a.ResetPin != fmt.Sprintf("%d:%s", st.TreeSize, st.RootHash) {
				return nil, fmt.Errorf("%w: the reset names %q, not the recorded %d:%s", ErrAdminRefused, a.ResetPin, st.TreeSize, st.RootHash)
			}
			next.record(cur)
			next.StaleRuns = 0
			res.Next, res.Trusted = &next, len(res.Findings) == 0
			return res, nil
		}
		// The recorded checkpoint is kept, so every later run reports it.
		res.Findings = append(res.Findings, FindingInconsistent)
		return res, nil
	}
	if a.ResetPin != "" {
		return nil, fmt.Errorf("%w: the pin is consistent", ErrAdminRefused)
	}
	if cur.Size == st.TreeSize {
		next.StaleRuns = st.StaleRuns + 1
		if next.StaleRuns >= 2 {
			res.Findings = append(res.Findings, FindingStale)
		}
	} else {
		next.StaleRuns = 0
	}
	next.record(cur)
	res.Next, res.Trusted = &next, len(res.Findings) == 0
	return res, nil
}

// consistent checks b's tree extends a's, fetching the proof when b is
// larger: ErrInconsistent if not, another error if the proof couldn't be
// had.
func consistent(ctx context.Context, p Prover, a, b *Checkpoint) error {
	if a.TreeID != b.TreeID || b.Size <= a.Size {
		return VerifyConsistency(a, b, nil)
	}
	hashes, err := p.ConsistencyProof(ctx, int64(a.Size), int64(b.Size), b.TreeID)
	if err != nil {
		if errors.Is(err, ErrBadAnswer) || errors.Is(err, ErrGone) {
			return fmt.Errorf("%w: %v", ErrInconsistent, err)
		}
		return err
	}
	return VerifyConsistency(a, b, hashes)
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
