package rekor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/transparency-dev/merkle/rfc6962"
)

// RFC 6962 §2.1: the tree head, an audit path, a consistency proof.
func mth(leaves [][]byte) []byte {
	h := rfc6962.DefaultHasher
	switch len(leaves) {
	case 0:
		return h.EmptyRoot()
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return h.HashChildren(mth(leaves[:k]), mth(leaves[k:]))
}

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func auditPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(auditPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(auditPath(m-k, leaves[k:]), mth(leaves[:k]))
}

func consistency(m int, leaves [][]byte) [][]byte { return subproof(m, leaves, true) }

func subproof(m int, leaves [][]byte, whole bool) [][]byte {
	n := len(leaves)
	if m == n {
		if whole {
			return nil
		}
		return [][]byte{mth(leaves)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, leaves[:k], whole), mth(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), mth(leaves[:k]))
}

// fakeLog is a one-shard Rekor v1 log at host under the test log's key:
// real leaves, signed checkpoints, proofs and signed entry timestamps.
type fakeLog struct {
	t          *testing.T
	l          *testLog
	bodies     [][]byte
	integrated []time.Time
	// hidden entries are left out of the search; searchErr, entriesErr
	// and logErr fail those requests.
	hidden                        map[int]bool
	searchErr, entriesErr, logErr error
	calls                         map[string]int
	frozen                        int // if > 0, the log's size (later entries not yet visible)
}

const fakeTree = "42"

func newFakeLog(t *testing.T) *fakeLog {
	return &fakeLog{t: t, l: newTestLog(t), hidden: map[int]bool{}, calls: map[string]int{}}
}

func (f *fakeLog) add(body []byte, at time.Time) int {
	f.bodies = append(f.bodies, body)
	f.integrated = append(f.integrated, at)
	return len(f.bodies) - 1
}

func (f *fakeLog) size() int {
	if f.frozen > 0 {
		return f.frozen
	}
	return len(f.bodies)
}

func (f *fakeLog) leaves() [][]byte {
	out := make([][]byte, f.size())
	for i := range out {
		out[i] = rfc6962.DefaultHasher.HashLeaf(f.bodies[i])
	}
	return out
}

func (f *fakeLog) checkpoint(n int) string {
	signer, _ := signature.LoadECDSASignerVerifier(f.l.key, crypto.SHA256)
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{Origin: host + " - " + fakeTree, Size: uint64(n), Hash: mth(f.leaves()[:n])})
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := sc.Sign(host, signer, options.WithContext(context.Background())); err != nil {
		f.t.Fatal(err)
	}
	b, _ := sc.MarshalText()
	return string(b)
}

func (f *fakeLog) id(i int) string {
	return "000000000000002a" + hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(f.bodies[i]))
}

func (f *fakeLog) entry(i int) *Entry {
	n := f.size()
	e := &Entry{Body: base64.StdEncoding.EncodeToString(f.bodies[i]), IntegratedTime: f.integrated[i].Unix(), LogID: f.l.id, LogIndex: int64(i)}
	payload, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{e.Body, e.IntegratedTime, e.LogID, e.LogIndex})
	h := sha256.Sum256(payload)
	set, _ := ecdsa.SignASN1(rand.Reader, f.l.key, h[:])
	e.Verification.SignedEntryTimestamp = set
	var hashes []string
	for _, p := range auditPath(i, f.leaves()) {
		hashes = append(hashes, hex.EncodeToString(p))
	}
	if hashes == nil {
		hashes = []string{}
	}
	e.Verification.InclusionProof = &struct {
		Checkpoint string   `json:"checkpoint"`
		Hashes     []string `json:"hashes"`
		LogIndex   int64    `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   int64    `json:"treeSize"`
	}{f.checkpoint(n), hashes, int64(i), hex.EncodeToString(mth(f.leaves())), int64(n)}
	return e
}

func (f *fakeLog) LogInfo(context.Context) (*LogInfo, error) {
	f.calls["log"]++
	if f.logErr != nil {
		return nil, f.logErr
	}
	n := f.size()
	return &LogInfo{Shard: Shard{RootHash: hex.EncodeToString(mth(f.leaves())), SignedTreeHead: f.checkpoint(n), TreeID: fakeTree, TreeSize: int64(n)}}, nil
}

func (f *fakeLog) ConsistencyProof(_ context.Context, first, last int64, treeID string) ([]string, error) {
	f.calls["proof"]++
	if treeID != fakeTree || last > int64(f.size()) || first < 1 {
		return nil, ErrBadAnswer
	}
	var out []string
	for _, p := range consistency(int(first), f.leaves()[:last]) {
		out = append(out, hex.EncodeToString(p))
	}
	return out, nil
}

func (f *fakeLog) SearchKey(_ context.Context, keyPEM []byte) ([]string, error) {
	f.calls["search"]++
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	blk, _ := pem.Decode(keyPEM)
	ids := []string{}
	for i := 0; i < f.size(); i++ {
		if f.hidden[i] {
			continue
		}
		var hr hashedRekord
		if json.Unmarshal(f.bodies[i], &hr) != nil {
			continue
		}
		if kb, _ := pem.Decode(hr.Spec.Signature.PublicKey.Content); kb != nil && blk != nil && string(kb.Bytes) == string(blk.Bytes) {
			ids = append(ids, f.id(i))
		}
	}
	return ids, nil
}

func (f *fakeLog) Entries(_ context.Context, ids []string) (map[string]*Entry, error) {
	f.calls["entries"]++
	if f.entriesErr != nil {
		return nil, f.entriesErr
	}
	out := map[string]*Entry{}
	for _, id := range ids {
		for i := 0; i < f.size(); i++ {
			if f.id(i)[16:] == id[16:] {
				out[f.id(i)] = f.entry(i)
			}
		}
	}
	return out, nil
}

func (f *fakeLog) EntriesAt(_ context.Context, idx []int64) (map[string]*Entry, error) {
	f.calls["at"]++
	out := map[string]*Entry{}
	for _, i := range idx {
		if i < 0 || i >= int64(f.size()) {
			return nil, errors.New("index out of range")
		}
		out[f.id(int(i))] = f.entry(int(i))
	}
	return out, nil
}

// anchorBody is a hashedrekord body over sha256(doc) signed by k.
func anchorBody(t *testing.T, k *ecdsa.PrivateKey, doc string) ([]byte, string) {
	t.Helper()
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	d := sha256.Sum256([]byte(doc))
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(d[:]), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), sig), hex.EncodeToString(d[:])
}
