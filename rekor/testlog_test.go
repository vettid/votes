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

// testLog is a one-entry log at host under a test key: it logs a body as
// the only leaf of tree 42 and returns the entry as Rekor's API gives it,
// with a signed entry timestamp, an inclusion proof and its checkpoint,
// all of which verify.
type testLog struct {
	key  *ecdsa.PrivateKey
	id   string // hex sha256 of the SPKI: Rekor's log ID
	logs Logs
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	k := testKey("votes rekor test log")
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sum := sha256.Sum256(spki)
	id := hex.EncodeToString(sum[:])
	return &testLog{key: k, id: id, logs: Logs{id: {BaseURL: "https://" + host, PublicKey: &k.PublicKey, HashFunc: crypto.SHA256,
		ValidityPeriodStart: time.Unix(0, 0), ID: sum[:]}}}
}

func (l *testLog) log(t *testing.T, body []byte, integrated time.Time) (string, *Entry) {
	t.Helper()
	return l.logIn(t, body, integrated, 1, 1)
}

// logIn logs body as leaf 0 of a tree of size leaves (1 or 4), the proof
// claiming claimed as its tree size.
func (l *testLog) logIn(t *testing.T, body []byte, integrated time.Time, size, claimed int64) (string, *Entry) {
	t.Helper()
	hs := rfc6962.DefaultHasher
	leaf := hs.HashLeaf(body)
	root, path := leaf, []string{}
	if size == 4 {
		l1, l2, l3 := hs.HashLeaf([]byte("x1")), hs.HashLeaf([]byte("x2")), hs.HashLeaf([]byte("x3"))
		right := hs.HashChildren(l2, l3)
		root = hs.HashChildren(hs.HashChildren(leaf, l1), right)
		path = []string{hex.EncodeToString(l1), hex.EncodeToString(right)}
	}
	e := &Entry{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: integrated.Unix(), LogID: l.id, LogIndex: 0}
	// The signed entry timestamp: over the canonical JSON of body,
	// integratedTime, logID and logIndex (keys in order, no spaces).
	payload, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{e.Body, e.IntegratedTime, e.LogID, e.LogIndex})
	h := sha256.Sum256(payload)
	set, err := ecdsa.SignASN1(rand.Reader, l.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	e.Verification.SignedEntryTimestamp = set
	signer, err := signature.LoadECDSASignerVerifier(l.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{Origin: host + " - 42", Size: uint64(size), Hash: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Sign(host, signer, options.WithContext(context.Background())); err != nil {
		t.Fatal(err)
	}
	cp, _ := sc.MarshalText()
	e.Verification.InclusionProof = &struct {
		Checkpoint string   `json:"checkpoint"`
		Hashes     []string `json:"hashes"`
		LogIndex   int64    `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   int64    `json:"treeSize"`
	}{Checkpoint: string(cp), Hashes: path, LogIndex: 0, RootHash: hex.EncodeToString(root), TreeSize: claimed}
	return "0000000000000042" + hex.EncodeToString(leaf), e
}

// Entries that pass the log's checks: a hashedrekord 0.0.1 signed by the
// anchor key verifies; an anchor key's entry of another kind, with
// another digest, or whose signature fails is ErrWrongKind (logged truth,
// acknowledgeable), not ErrUnverified.
func TestWrongKind(t *testing.T) {
	ctx := context.Background()
	l := newTestLog(t)
	anchor := testKey("votes anchor key")
	aspki, _ := x509.MarshalPKIXPublicKey(&anchor.PublicKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: aspki})
	digest := sha256.Sum256([]byte("a proposal"))
	sig, _ := ecdsa.SignASN1(rand.Reader, anchor, digest[:])
	dh := hex.EncodeToString(digest[:])
	when := at.Add(-time.Hour)

	id, e := l.log(t, body(t, "hashedrekord", "0.0.1", "sha256", dh, keyPEM, sig), when)
	v, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", CheckpointAt: at}, at)
	if err != nil || hex.EncodeToString(v.Digest) != dh || v.Proof.TreeID != "42" {
		t.Fatalf("a good entry: %+v %v", v, err)
	}

	dsse, _ := json.Marshal(map[string]any{"kind": "dsse", "apiVersion": "0.0.1", "spec": map[string]any{
		"signatures": []any{map[string]any{"signature": "c2ln", "verifier": base64.StdEncoding.EncodeToString(keyPEM)}}}})
	for name, b := range map[string][]byte{
		"dsse":      dsse,
		"sha512":    body(t, "hashedrekord", "0.0.1", "sha512", dh, keyPEM, sig),
		"bad sig":   body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(make([]byte, 32)), keyPEM, sig),
		"version":   body(t, "hashedrekord", "0.0.2", "sha256", dh, keyPEM, sig),
		"other key": append([]byte(`{"x":`+string(mustJSON(t, string(keyPEM)))+`,"y":`), append(body(t, "hashedrekord", "0.0.1", "sha256", dh, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustSPKI(t, "another")}), sig), '}')...),
	} {
		id, e := l.log(t, b, when)
		v, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", CheckpointAt: at}, at)
		if !errors.Is(err, ErrWrongKind) || errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
		// The log's part is returned, for the caller's consistency check.
		if v == nil || v.Proof == nil || v.Proof.TreeID != "42" || v.Digest != nil || v.Leaf != id[16:] {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// The same good entry with its signed entry timestamp broken: the
	// log's checks fail, so unverified, whatever its body.
	id, e = l.log(t, dsse, when)
	e.Verification.SignedEntryTimestamp[10] ^= 1
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", CheckpointAt: at}, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("broken SET: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSPKI(t *testing.T, seed string) []byte {
	t.Helper()
	k := testKey(seed)
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The log's checks come before the body: a body that doesn't parse, or
// names no anchor key, is reported only once the log holds it.
func TestLogChecksFirst(t *testing.T) {
	ctx := context.Background()
	l := newTestLog(t)
	anchor := mustSPKI(t, "votes anchor key")
	when := at.Add(-time.Hour)
	pl := Place{TreeID: "42", CheckpointAt: at}
	id, e := l.log(t, []byte("not json"), when)
	if v, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{anchor}, pl, at); !errors.Is(err, ErrUnparsed) || v == nil {
		t.Errorf("unparsed: %v", err)
	}
	other, _ := json.Marshal(map[string]any{"kind": "hashedrekord", "spec": map[string]any{}})
	id, e = l.log(t, other, when)
	if v, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{anchor}, pl, at); !errors.Is(err, ErrNotAnchor) || v == nil {
		t.Errorf("not an anchor's: %v", err)
	}
	// IDs: only 80 hex digits, on an entry that is otherwise good.
	for _, bad := range []string{id[16:], "00000000" + id[16:], id + "00"} {
		if _, err := VerifyEntry(ctx, bad, e, host, l.logs, [][]byte{anchor}, pl, at); !errors.Is(err, ErrUnverified) {
			t.Errorf("id of %d: %v", len(bad), err)
		}
	}
	// A body substituted under an ID: unverified, not "not ours".
	e.Body = base64.StdEncoding.EncodeToString([]byte(`{"kind":"x"}`))
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{anchor}, pl, at); !errors.Is(err, ErrUnverified) || errors.Is(err, ErrNotAnchor) {
		t.Errorf("substituted body: %v", err)
	}
}

// A proof claiming another tree size than its checkpoint's is refused,
// even where the inclusion alone would verify (index 0 has the same path
// at sizes 3 and 4).
func TestProofSize(t *testing.T) {
	ctx := context.Background()
	l := newTestLog(t)
	anchor := testKey("votes anchor key")
	aspki := mustSPKI(t, "votes anchor key")
	digest := sha256.Sum256([]byte("a proposal"))
	sig, _ := ecdsa.SignASN1(rand.Reader, anchor, digest[:])
	b := body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(digest[:]), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: aspki}), sig)
	pl := Place{TreeID: "42", CheckpointAt: at}
	id, e := l.logIn(t, b, at.Add(-time.Hour), 4, 4)
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, pl, at); err != nil {
		t.Fatalf("size 4: %v", err)
	}
	id, e = l.logIn(t, b, at.Add(-time.Hour), 4, 3)
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, pl, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("size 3 claimed of 4: %v", err)
	}
	// The index mapping: the global index is the shard's plus the offset.
	id, e = l.log(t, b, at.Add(-time.Hour))
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", Offset: 1, CheckpointAt: at}, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("another offset: %v", err)
	}
}

// The checkpoint's key: checked at CheckpointAt (the run's, for the
// active shard), or at the integrated time when it is zero (an inactive
// shard's).
func TestCheckpointKeyTime(t *testing.T) {
	ctx := context.Background()
	l := newTestLog(t)
	when := at.Add(-time.Hour)
	for _, tl := range l.logs {
		tl.ValidityPeriodEnd = when.Add(time.Minute)
	}
	anchor := testKey("votes anchor key")
	aspki := mustSPKI(t, "votes anchor key")
	digest := sha256.Sum256([]byte("a proposal"))
	sig, _ := ecdsa.SignASN1(rand.Reader, anchor, digest[:])
	id, e := l.log(t, body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(digest[:]), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: aspki}), sig), when)
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", CheckpointAt: at}, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("active shard, key ended before the run: %v", err)
	}
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", Inactive: true}, at); err != nil {
		t.Errorf("inactive shard, key valid at the entry: %v", err)
	}
	// A Place that says too little verifies nothing; another tree is refused.
	for name, pl := range map[string]Place{
		"zero":            {},
		"no tree ID":      {CheckpointAt: at},
		"active, no time": {TreeID: "42"},
		"another tree":    {TreeID: "43", Inactive: true},
	} {
		if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, pl, at); !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The entry's signing key must be the anchor key found: a body naming
// another key first, then the anchor's, is wrong kind.
func TestSigningKeyIsAnchor(t *testing.T) {
	ctx := context.Background()
	l := newTestLog(t)
	other := testKey("another signer")
	ospki := mustSPKI(t, "another signer")
	aspki := mustSPKI(t, "votes anchor key")
	digest := sha256.Sum256([]byte("a proposal"))
	sig, _ := ecdsa.SignASN1(rand.Reader, other, digest[:])
	two := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ospki}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: aspki})...)
	id, e := l.log(t, body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(digest[:]), two, sig), at.Add(-time.Hour))
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, Place{TreeID: "42", CheckpointAt: at}, at); !errors.Is(err, ErrWrongKind) {
		t.Errorf("signed by another key: %v", err)
	}
}
