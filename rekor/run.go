package rekor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/util"
)

// Run's timing (VOTES-SITE §7).
const (
	// ListingGrace: an entry younger than this when verified is pending.
	ListingGrace = 10 * time.Minute
	// AnchoredAgainAfter: a known digest anchored again later than this
	// after its reference time is "anchored again".
	AnchoredAgainAfter = 24 * time.Hour
	// Budget is the most time a run spends on one instance.
	Budget = 10 * time.Minute
)

// More findings of the run (VOTES-SITE §7), with the pin's.
const (
	FindingUnverified    = "unverified"
	FindingWrongKind     = "wrong kind"
	FindingUnknown       = "unknown digest"
	FindingUnexpected    = "unexpected digest"
	FindingAnchoredAgain = "anchored again"
	FindingIndexGap      = "index gap"
	FindingIncomplete    = "incomplete"
	FindingNoEntry       = "no signed entry"
	FindingAckStale      = "acknowledgement"
)

// Acknowledgeable findings (never "unverified").
var acknowledgeable = []string{FindingUnknown, FindingUnexpected, FindingAnchoredAgain, FindingIndexGap, FindingWrongKind}

// Log is what a run uses of a Client.
type Log interface {
	LogInfo(ctx context.Context) (*LogInfo, error)
	ConsistencyProof(ctx context.Context, first, last int64, treeID string) ([]string, error)
	SearchKey(ctx context.Context, pem []byte) ([]string, error)
	Entries(ctx context.Context, ids []string) (map[string]*Entry, error)
	EntriesAt(ctx context.Context, indexes []int64) (map[string]*Entry, error)
}

// Bundle is a published document's own Rekor entry (site.RekorEntry),
// for the canary and the reference times.
type Bundle struct {
	Name       string // "<proposal_id>/<document>"
	Digest     []byte // the document's SHA-256
	Leaf       []byte
	LogIndex   int64
	ShardIndex int64
	Integrated time.Time
	Checkpoint string
}

// Ack is one acknowledged entry (VOTES-SITE §7, "Acknowledged entries").
type Ack struct {
	Instance       string `json:"instance"`
	UUID           string `json:"uuid"`
	LogIndex       int64  `json:"log_index"`
	SHA256         string `json:"sha256"`
	Finding        string `json:"finding"`
	Reason         string `json:"reason"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

var ackMembers = []string{"instance", "uuid", "log_index", "sha256", "finding", "reason", "acknowledged_at"}

// ParseAcks reads an acknowledged-entries file strictly: a JSON array of
// objects with exactly Ack's members, each finding acknowledgeable, no
// (uuid, finding) twice.
func ParseAcks(b []byte) ([]Ack, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return nil, fmt.Errorf("rekor: acknowledged entries: %w", err)
	}
	out := make([]Ack, 0, len(raws))
	seen := map[string]bool{}
	for i, r := range raws {
		keys, ok := objectKeys(r)
		slices.Sort(keys)
		want := slices.Clone(ackMembers)
		slices.Sort(want)
		if !ok || !slices.Equal(keys, want) {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: members other than %v", i, ackMembers)
		}
		var a Ack
		if err := json.Unmarshal(r, &a); err != nil {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: %w", i, err)
		}
		if len(a.UUID) != 80 || strings.Trim(a.UUID, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: uuid isn't 80 lowercase hex digits", i)
		}
		if a.SHA256 != "" && (len(a.SHA256) != 64 || strings.Trim(a.SHA256, "0123456789abcdef") != "") {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: sha256 isn't 64 lowercase hex digits", i)
		}
		if !slices.Contains(acknowledgeable, a.Finding) {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: %q can't be acknowledged", i, a.Finding)
		}
		if a.Reason == "" || a.Instance == "" || a.LogIndex < 0 {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: incomplete", i)
		}
		if _, err := time.Parse("2006-01-02", a.AcknowledgedAt); err != nil {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: acknowledged_at isn't a date", i)
		}
		k := a.UUID[16:] + "|" + a.Finding
		if seen[k] {
			return nil, fmt.Errorf("rekor: acknowledged entry %d: (uuid, finding) twice", i)
		}
		seen[k] = true
		out = append(out, a)
	}
	return out, nil
}

// Store is the verified store (VOTES-SITE §7, "The verified store"): each
// verified entry whole, by its 80-hex entry ID.
type Store struct {
	V       int               `json:"v"`
	Entries map[string]*Entry `json:"entries"`
}

// ParseStore reads the verified store: nil or empty is an empty store;
// anything else must parse (an error is a failed check, exit 1).
func ParseStore(b []byte) (*Store, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return &Store{V: 1, Entries: map[string]*Entry{}}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Store
	if err := dec.Decode(&s); err != nil || s.V != 1 || s.Entries == nil {
		return nil, errors.New("rekor: the verified store doesn't parse")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("rekor: the verified store doesn't parse")
	}
	for id := range s.Entries {
		if len(id) != 80 || strings.Trim(id, "0123456789abcdef") != "" {
			return nil, errors.New("rekor: the verified store has an ID that isn't 80 hex digits")
		}
	}
	return &s, nil
}

// RunInput is what a run works from. The caller has checked the site;
// the digests are hex SHA-256.
type RunInput struct {
	Instance string // "production" or "staging"
	Host     string
	Logs     Logs
	// Anchors are every listed anchor key's SPKI (DER).
	Anchors [][]byte
	// Known digests, each with its reference time: the published bundle's
	// integrated time, or zero (an acknowledged partial upload's: the
	// earliest verified entry's).
	Known map[string]time.Time
	// Unexpected digests, with what they are: service-list versions,
	// results' rows.
	Unexpected map[string]string
	// Bundles are the published documents' own entries; NoEntry names
	// documents anchored without a signed entry.
	Bundles []Bundle
	NoEntry []string
	// ListsIncomplete: the run's index or an archive month wasn't read.
	ListsIncomplete bool
	// Scan: staging's full scan.
	Scan  bool
	State LoadedState
	Store *Store
	Acks  []Ack
	Admin Admin
	Now   func() time.Time
}

// Item is one entry reported.
type Item struct {
	Finding  string `json:"finding,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	LogIndex int64  `json:"log_index,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// RunReport is the report's rekor member, and what to write back.
type RunReport struct {
	Instance     string   `json:"instance"`
	Checkpoint   string   `json:"checkpoint,omitempty"` // origin, size, root
	State        string   `json:"state"`
	Searched     int      `json:"searched"`
	Verified     int      `json:"verified"`
	Scanned      uint64   `json:"scanned"`
	Unparsed     int      `json:"unparsed"`
	Requests     int      `json:"requests"`
	Failures     int      `json:"failures"`
	Error        string   `json:"error,omitempty"`
	Mismatches   []Item   `json:"mismatches"`
	Pending      []Item   `json:"pending,omitempty"`
	Acknowledged []Item   `json:"acknowledged,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`

	// NextState is the state to write back (nil: write back what was
	// read, unchanged); NextStore the verified store.
	NextState []byte `json:"-"`
	NextStore []byte `json:"-"`
}

// OK reports whether the run found no mismatch.
func (r *RunReport) OK() bool { return len(r.Mismatches) == 0 }

type run struct {
	in      RunInput
	log     Log
	rep     *RunReport
	ctx     context.Context
	now     time.Time
	cur     *Checkpoint
	shards  map[string]*Checkpoint // inactive, by tree ID
	offsets map[string]int64       // by tree ID, the active one too
	proofs  map[string]bool        // entry checkpoints proved (or refuted) this run
	// unavailable / stopped: a request with no answer, or the cap or the
	// time limit reached.
	unavailable, stopped bool
	searched             map[string]string // leaf -> 80-hex ID returned by a search
	verified             map[string]*Verified
	wrongKind            map[string]*Verified
	earliest             map[string]time.Time // digest -> earliest verified entry
	seenItem             map[string]bool
	searchStart          time.Time
}

// pemOf is a key's SPKI as a PEM public key.
func pemOf(spki []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
}

func (r *run) mismatch(it Item) {
	k := it.Finding + "|" + it.UUID + "|" + it.Detail
	if r.seenItem[k] {
		return
	}
	r.seenItem[k] = true
	r.rep.Mismatches = append(r.rep.Mismatches, it)
}

// failed classifies a request's error: it returns true if the run must
// stop asking (the cap, the time limit, the context), and records "no
// answer" for an unavailable one, a mismatch for anything that came back.
func (r *run) failed(err error, what string) {
	switch {
	case errors.Is(err, ErrUnavailable):
		r.unavailable = true
		if r.rep.Error == "" {
			r.rep.Error = fmt.Sprintf("%s: %v", what, err)
		}
	case errors.Is(err, ErrCap) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		r.stopped = true
	case errors.Is(err, ErrGone):
		r.mismatch(Item{Finding: FindingUnavailable, Detail: fmt.Sprintf("%s: %v", what, err)})
	default:
		r.mismatch(Item{Finding: FindingUnverified, Detail: fmt.Sprintf("%s: %v", what, err)})
	}
}

// Run is one Rekor check (VOTES-SITE §7, "The Rekor check"). An admin
// request that doesn't apply is ErrAdminRefused; anything else is in the
// report.
func Run(ctx context.Context, log Log, in RunInput) (*RunReport, error) {
	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	r := &run{in: in, log: log, ctx: ctx, now: now(), rep: &RunReport{Instance: in.Instance, Mismatches: []Item{}},
		shards: map[string]*Checkpoint{}, offsets: map[string]int64{}, proofs: map[string]bool{},
		searched: map[string]string{}, verified: map[string]*Verified{}, wrongKind: map[string]*Verified{},
		earliest: map[string]time.Time{}, seenItem: map[string]bool{}}
	if in.Store == nil {
		in.Store = &Store{V: 1, Entries: map[string]*Entry{}}
		r.in.Store = in.Store
	}
	switch in.State.Kind {
	case StateNone:
		r.rep.State = "none"
	case StateEmpty, StateUnparsed:
		r.rep.State = "no state"
	default:
		r.rep.State = "ok"
	}
	pin, err := r.checkpoints()
	if err != nil {
		return nil, err
	}
	if pin == nil && in.Admin.count() > 0 {
		// An owner-run step needs the log's checkpoint: never silently skipped.
		return nil, fmt.Errorf("%w: the log's checkpoint couldn't be had or verified (%v)", ErrAdminRefused, r.rep.Mismatches)
	}
	if r.cur != nil {
		r.search()
		r.fetchAndVerify(r.searchedIDs(), true)
		r.acks()
		r.canary()
		if in.Scan && pin != nil && !pin.ShardChanged {
			r.scan(pin)
		}
	}
	for _, name := range in.NoEntry {
		r.mismatch(Item{Finding: FindingNoEntry, Detail: name + ": anchored, with no signed Rekor entry"})
	}
	r.finish(pin)
	return r.rep, nil
}

// checkpoints verifies the active checkpoint, the inactive shards' and
// the newest bundle's, and runs the pin.
func (r *run) checkpoints() (*PinResult, error) {
	li, err := r.log.LogInfo(r.ctx)
	if err != nil {
		r.failed(err, "the log's checkpoint")
		return nil, nil
	}
	cur, err := VerifyCheckpoint(li.SignedTreeHead, r.in.Host, r.in.Logs, r.now)
	if err != nil {
		r.mismatch(Item{Finding: FindingUnverified, Detail: "the active checkpoint: " + err.Error()})
		return nil, nil
	}
	if cur.TreeID != li.TreeID || int64(cur.Size) != li.TreeSize || hex.EncodeToString(cur.Root) != li.RootHash {
		r.mismatch(Item{Finding: FindingUnverified, Detail: "the log's answer differs from its signed checkpoint"})
		return nil, nil
	}
	var off int64
	for _, sh := range li.InactiveShards {
		cp, err := VerifyCheckpoint(sh.SignedTreeHead, r.in.Host, r.in.Logs, r.now)
		if err != nil || cp.TreeID != sh.TreeID {
			r.mismatch(Item{Finding: FindingUnverified, Detail: "inactive shard " + sh.TreeID + "'s checkpoint: " + fmt.Sprint(err)})
			return nil, nil
		}
		r.shards[cp.TreeID], r.offsets[cp.TreeID] = cp, off
		off += int64(cp.Size)
	}
	r.offsets[cur.TreeID] = off
	r.cur = cur
	r.rep.Checkpoint = fmt.Sprintf("%s %d %s", cur.Origin, cur.Size, hex.EncodeToString(cur.Root))

	var bundle *Checkpoint
	var newest *Bundle
	for i := range r.in.Bundles {
		if b := &r.in.Bundles[i]; newest == nil || b.Integrated.After(newest.Integrated) {
			newest = b
		}
	}
	if newest != nil {
		if bundle, err = VerifyCheckpoint(newest.Checkpoint, r.in.Host, r.in.Logs, newest.Integrated); err != nil {
			r.mismatch(Item{Finding: FindingUnverified, Detail: newest.Name + ": its bundle's checkpoint: " + err.Error()})
			bundle = nil
		}
	}
	pin, err := CheckPin(r.ctx, PinInput{Loaded: r.in.State, Current: cur, Inactive: r.shards, Bundle: bundle, Admin: r.in.Admin, Prover: r.log})
	if err != nil {
		return nil, err
	}
	for _, f := range pin.Findings {
		r.mismatch(Item{Finding: f.Name, Detail: f.Detail})
	}
	if pin.Unavailable != nil {
		r.failed(pin.Unavailable, "a consistency proof")
	}
	if pin.Stopped != nil {
		r.stopped = true
	}
	return pin, nil
}

// search asks the index for each anchor key's entries.
func (r *run) search() {
	r.searchStart = time.Now()
	if r.in.Now != nil {
		r.searchStart = r.in.Now()
	}
	for _, a := range r.in.Anchors {
		if r.stopped {
			return
		}
		ids, err := r.log.SearchKey(r.ctx, pemOf(a))
		if err != nil {
			r.failed(err, "the search")
			continue
		}
		for _, id := range ids {
			id = strings.ToLower(id)
			if len(id) != 80 || strings.Trim(id, "0123456789abcdef") != "" {
				r.mismatch(Item{Finding: FindingUnverified, UUID: id, Detail: "the search answered an ID that isn't 80 hex digits"})
				continue
			}
			r.searched[id[16:]] = id
		}
	}
	r.rep.Searched = len(r.searched)
}

func (r *run) searchedIDs() []string {
	ids := make([]string, 0, len(r.searched))
	for _, id := range r.searched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// place says where an entry's proof is, from its checkpoint's origin (the
// signature is verified by VerifyEntry).
func (r *run) place(e *Entry) (Place, bool) {
	if e.Verification.InclusionProof == nil {
		return Place{}, false
	}
	var sc util.SignedCheckpoint
	if sc.UnmarshalText([]byte(e.Verification.InclusionProof.Checkpoint)) != nil {
		return Place{}, false
	}
	tree, ok := strings.CutPrefix(sc.Origin, r.in.Host+" - ")
	if !ok {
		return Place{}, false
	}
	off, known := r.offsets[tree]
	if !known {
		return Place{}, false
	}
	if tree == r.cur.TreeID {
		return Place{TreeID: tree, Offset: off, CheckpointAt: r.now}, true
	}
	return Place{TreeID: tree, Offset: off, Inactive: true}, true
}

// consistentProof checks an entry's proof checkpoint is the run's or
// consistent with it: in the active tree, at most the run's size (proven
// from the stored state's chain) or proved up to it; in an inactive tree,
// at most its final size, proved up to it.
func (r *run) consistentProof(cp *Checkpoint, fetched bool) bool {
	target := r.cur
	if cp.TreeID != r.cur.TreeID {
		target = r.shards[cp.TreeID]
	}
	if target == nil {
		return false
	}
	var res PinResult
	key := cp.TreeID + "/" + strconv.FormatUint(cp.Size, 10) + "/" + hex.EncodeToString(cp.Root)
	if ok, done := r.proofs[key]; done {
		return ok
	}
	var ok bool
	switch {
	case cp.Size > target.Size && cp.TreeID != r.cur.TreeID:
		// A frozen shard holds nothing past its final size.
		r.mismatch(Item{Finding: FindingInconsistent, Detail: "an entry's checkpoint is past inactive tree " + cp.TreeID + "'s final size"})
		ok = false
	case cp.Size > target.Size:
		ok = res.prove(r.ctx, r.log, target, cp, "an entry's checkpoint, from the run's")
	case !fetched:
		// Stored: proved at fetch, carried by the state's chain.
		return true
	default:
		ok = res.prove(r.ctx, r.log, cp, target, "an entry's checkpoint, to the run's")
	}
	if !ok {
		r.pinResult(&res)
	}
	if res.Unavailable == nil && res.Stopped == nil {
		r.proofs[key] = ok
	}
	return ok
}

func (r *run) pinResult(res *PinResult) {
	for _, f := range res.Findings {
		r.mismatch(Item{Finding: f.Name, Detail: f.Detail})
	}
	if res.Unavailable != nil {
		r.failed(res.Unavailable, "a consistency proof")
	}
	if res.Stopped != nil {
		r.stopped = true
	}
}

// fetchAndVerify verifies the entries with these IDs: from the store,
// again locally, or fetched (10 a request), proved consistent and stored.
// asked: the IDs are ones the check asked for (an entry that isn't an
// anchor key's, or doesn't parse, is then a mismatch, not a skip).
func (r *run) fetchAndVerify(ids []string, asked bool) {
	var fetch []string
	for _, id := range ids {
		if _, done := r.verified[id[16:]]; done {
			continue
		}
		if e, ok := r.in.Store.Entries[id]; ok {
			r.verifyOne(id, e, false, asked)
			continue
		}
		fetch = append(fetch, id)
	}
	for len(fetch) > 0 && !r.stopped {
		n := min(MaxBatch, len(fetch))
		batch := fetch[:n]
		fetch = fetch[n:]
		got, err := r.log.Entries(r.ctx, batch)
		if err != nil {
			r.failed(err, "entries")
			continue
		}
		byLeaf := map[string]string{}
		for gid := range got {
			if len(gid) == 80 {
				byLeaf[gid[16:]] = gid
			}
		}
		for _, id := range batch {
			gid, ok := byLeaf[id[16:]]
			if !ok {
				r.mismatch(Item{Finding: FindingUnverified, UUID: id, Detail: "named, but not returned by the log"})
				continue
			}
			r.verifyOne(gid, got[gid], true, asked)
		}
	}
}

func (r *run) verifyOne(id string, e *Entry, fetched, asked bool) {
	pl, ok := r.place(e)
	if !ok {
		r.mismatch(Item{Finding: FindingUnverified, UUID: id, LogIndex: e.LogIndex, Detail: "its proof's checkpoint isn't of a tree the log lists"})
		return
	}
	at := time.Now()
	if r.in.Now != nil {
		at = r.in.Now()
	}
	v, err := VerifyEntry(r.ctx, id, e, r.in.Host, r.in.Logs, r.in.Anchors, pl, at)
	switch {
	case errors.Is(err, ErrNotAnchor) || errors.Is(err, ErrUnparsed):
		if asked {
			r.mismatch(Item{Finding: FindingUnverified, UUID: id, LogIndex: e.LogIndex, Detail: "asked for, and not an anchor key's: " + err.Error()})
		}
		return
	case err != nil && !errors.Is(err, ErrWrongKind):
		r.mismatch(Item{Finding: FindingUnverified, UUID: id, LogIndex: e.LogIndex, Detail: err.Error()})
		return
	}
	if !r.consistentProof(v.Proof, fetched) {
		return
	}
	if fetched {
		r.in.Store.Entries[v.ID] = e
	}
	if errors.Is(err, ErrWrongKind) {
		r.wrongKind[v.Leaf] = v
		r.mismatch(Item{Finding: FindingWrongKind, UUID: v.ID, LogIndex: v.LogIndex, Detail: err.Error()})
		return
	}
	r.verified[v.Leaf] = v
	r.rep.Verified++
	d := hex.EncodeToString(v.Digest)
	if t, ok := r.earliest[d]; !ok || v.Integrated.Before(t) {
		r.earliest[d] = v.Integrated
	}
}

// classify reports each verified entry by its digest.
func (r *run) classify() {
	leaves := make([]string, 0, len(r.verified))
	for l := range r.verified {
		leaves = append(leaves, l)
	}
	sort.Strings(leaves)
	for _, l := range leaves {
		v := r.verified[l]
		d := hex.EncodeToString(v.Digest)
		it := Item{UUID: v.ID, LogIndex: v.LogIndex, SHA256: d}
		age := r.now.Sub(v.Integrated)
		switch ref, known := r.in.Known[d]; {
		case age >= -Skew && age < ListingGrace:
			it.Detail = "integrated " + age.Round(time.Second).String() + " before the run"
			r.rep.Pending = append(r.rep.Pending, it)
		case r.in.Unexpected[d] != "":
			it.Finding, it.Detail = FindingUnexpected, r.in.Unexpected[d]
			r.mismatch(it)
		case known:
			if ref.IsZero() {
				ref = r.earliest[d]
			}
			if v.Integrated.Sub(ref) > AnchoredAgainAfter {
				it.Finding, it.Detail = FindingAnchoredAgain, "anchored "+v.Integrated.Sub(ref).Round(time.Hour).String()+" after its first"
				r.mismatch(it)
			}
		default:
			it.Finding = FindingUnknown
			if r.in.ListsIncomplete {
				it.Detail = "lists_incomplete"
			}
			r.mismatch(it)
		}
	}
}

// canary: every published bundle's own entry is among its key's search
// results (VOTES-SITE §7, "The canary").
func (r *run) canary() {
	for _, b := range r.in.Bundles {
		leaf := hex.EncodeToString(b.Leaf)
		if _, ok := r.searched[leaf]; ok {
			continue
		}
		if r.searchStart.Sub(b.Integrated) <= ListingGrace {
			continue
		}
		r.mismatch(Item{Finding: FindingIndexGap, UUID: leaf, LogIndex: b.LogIndex, SHA256: hex.EncodeToString(b.Digest),
			Detail: b.Name + ": its bundle's entry isn't among its key's search results"})
	}
}

// scan reads the active shard (and, after an accepted shard change, the
// old one's tail) from the state's position, 10 entries a request, for
// every entry of an anchor key (VOTES-SITE §7, "Staging's scan").
func (r *run) scan(pin *PinResult) {
	if pin.Next == nil {
		return
	}
	st := pin.Next
	type span struct {
		tree     string
		from, to uint64
	}
	var spans []span
	switch {
	case st.ScannedTo == nil:
		spans = []span{{r.cur.TreeID, r.cur.Size, r.cur.Size}}
	case pin.Accepted:
		if old := r.shards[st.ScanTreeID]; old != nil {
			spans = append(spans, span{st.ScanTreeID, *st.ScannedTo, old.Size})
		}
		spans = append(spans, span{r.cur.TreeID, 0, r.cur.Size})
	case st.ScanTreeID == r.cur.TreeID:
		spans = []span{{r.cur.TreeID, *st.ScannedTo, r.cur.Size}}
	default:
		// The scan's tree isn't the active one, without an acceptance.
		r.mismatch(Item{Finding: FindingShardChanged, Detail: "the scan's tree " + st.ScanTreeID + " isn't the active one"})
		return
	}
	for _, sp := range spans {
		pos := sp.from
		for pos < sp.to && !r.stopped {
			n := min(uint64(MaxBatch), sp.to-pos)
			idx := make([]int64, 0, n)
			for i := uint64(0); i < n; i++ {
				idx = append(idx, r.offsets[sp.tree]+int64(pos+i))
			}
			got, err := r.log.EntriesAt(r.ctx, idx)
			if err != nil {
				r.failed(err, "the scan")
				break
			}
			byIndex := map[int64]string{}
			for id, e := range got {
				byIndex[e.LogIndex] = id
			}
			for _, gi := range idx {
				id, ok := byIndex[gi]
				if !ok {
					r.mismatch(Item{Finding: FindingUnverified, LogIndex: gi, Detail: "the scan's request wasn't answered for this index"})
					continue
				}
				r.scanOne(id, got[id])
			}
			pos += n
			r.rep.Scanned += n
			st.ScanAt(sp.tree, pos)
		}
		if pos < sp.to {
			return
		}
	}
	st.ScanAt(r.cur.TreeID, max(r.cur.Size, scannedIn(st, r.cur.TreeID)))
}

func scannedIn(st *State, tree string) uint64 {
	if st.ScannedTo != nil && st.ScanTreeID == tree {
		return *st.ScannedTo
	}
	return 0
}

func (r *run) scanOne(id string, e *Entry) {
	pl, ok := r.place(e)
	if !ok {
		r.mismatch(Item{Finding: FindingUnverified, UUID: id, LogIndex: e.LogIndex, Detail: "a scanned entry's proof isn't of a tree the log lists"})
		return
	}
	at := time.Now()
	if r.in.Now != nil {
		at = r.in.Now()
	}
	v, err := VerifyEntry(r.ctx, strings.ToLower(id), e, r.in.Host, r.in.Logs, r.in.Anchors, pl, at)
	switch {
	case errors.Is(err, ErrNotAnchor):
		return
	case errors.Is(err, ErrUnparsed):
		r.rep.Unparsed++
		return
	case err != nil && !errors.Is(err, ErrWrongKind):
		r.mismatch(Item{Finding: FindingUnverified, UUID: id, LogIndex: e.LogIndex, Detail: "scanned: " + err.Error()})
		return
	}
	if !r.consistentProof(v.Proof, true) {
		return
	}
	if _, inSearch := r.searched[v.Leaf]; !inSearch && r.searchStart.Sub(v.Integrated) > ListingGrace {
		r.mismatch(Item{Finding: FindingIndexGap, UUID: v.ID, LogIndex: v.LogIndex, Detail: "scanned, but not returned by the search"})
	}
	if _, done := r.verified[v.Leaf]; done || r.wrongKind[v.Leaf] != nil {
		return
	}
	r.in.Store.Entries[v.ID] = e
	if errors.Is(err, ErrWrongKind) {
		r.wrongKind[v.Leaf] = v
		r.mismatch(Item{Finding: FindingWrongKind, UUID: v.ID, LogIndex: v.LogIndex, Detail: err.Error()})
		return
	}
	r.verified[v.Leaf] = v
	r.rep.Verified++
	d := hex.EncodeToString(v.Digest)
	if t, ok := r.earliest[d]; !ok || v.Integrated.Before(t) {
		r.earliest[d] = v.Integrated
	}
}

// acks checks each acknowledged entry is still true, by fetching or
// re-verifying it (VOTES-SITE §7, "Acknowledged entries").
func (r *run) acks() {
	var ids []string
	for _, a := range r.in.Acks {
		if a.Instance == r.in.Instance {
			ids = append(ids, a.UUID)
		}
	}
	r.fetchAndVerify(ids, true)
}

// applyAcks moves acknowledged findings out of the mismatches, and makes a
// listed entry that isn't true a mismatch.
func (r *run) applyAcks() {
	type key struct{ leaf, finding string }
	acked := map[key]Ack{}
	for _, a := range r.in.Acks {
		if a.Instance != r.in.Instance {
			continue
		}
		leaf := a.UUID[16:]
		v := r.verified[leaf]
		if v == nil {
			v = r.wrongKind[leaf]
		}
		switch {
		case v == nil:
			r.mismatch(Item{Finding: FindingAckStale, UUID: a.UUID, Detail: "an acknowledged entry that isn't there, or isn't an anchor key's"})
			continue
		case v.LogIndex != a.LogIndex:
			r.mismatch(Item{Finding: FindingAckStale, UUID: a.UUID, Detail: "an acknowledged entry whose log index is " + strconv.FormatInt(v.LogIndex, 10)})
			continue
		case hex.EncodeToString(v.Digest) != a.SHA256 && !(v.Digest == nil && a.SHA256 == ""):
			r.mismatch(Item{Finding: FindingAckStale, UUID: a.UUID, Detail: "an acknowledged entry whose digest differs"})
			continue
		}
		acked[key{leaf, a.Finding}] = a
	}
	kept := r.rep.Mismatches[:0]
	for _, m := range r.rep.Mismatches {
		if len(m.UUID) >= 64 {
			if _, ok := acked[key{m.UUID[len(m.UUID)-64:], m.Finding}]; ok {
				r.rep.Acknowledged = append(r.rep.Acknowledged, m)
				continue
			}
		}
		kept = append(kept, m)
	}
	r.rep.Mismatches = kept
}

func (r *run) finish(pin *PinResult) {
	r.classify()
	r.applyAcks()
	if r.stopped {
		r.mismatch(Item{Finding: FindingIncomplete, Detail: "the run stopped at its request cap or time limit"})
	}
	prev := 0
	if r.in.State.Kind == StateOK {
		prev = r.in.State.State.Failures
	}
	n, alarm := Failures(prev, r.unavailable, r.stopped)
	if r.in.State.Kind == StateNone {
		n, alarm = 0, false
	}
	r.rep.Failures = n
	if alarm {
		r.mismatch(Item{Finding: FindingUnavailable, Detail: fmt.Sprintf("no answer for %d runs in a row", n)})
	}
	if pin != nil && pin.Next != nil {
		next := *pin.Next
		next.Failures = n
		if !r.in.Scan {
			next.ScanTreeID, next.ScannedTo = "", nil
		}
		r.rep.NextState = next.Encode()
	}
	if b, err := json.Marshal(r.in.Store); err == nil {
		r.rep.NextStore = b
	}
	if c, ok := r.log.(interface{ Requests() int }); ok {
		r.rep.Requests = c.Requests()
	}
	sort.SliceStable(r.rep.Mismatches, func(i, j int) bool { return r.rep.Mismatches[i].Finding < r.rep.Mismatches[j].Finding })
}
