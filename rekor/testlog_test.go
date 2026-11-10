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
	leaf := rfc6962.DefaultHasher.HashLeaf(body)
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
	sc, err := util.CreateSignedCheckpoint(util.Checkpoint{Origin: host + " - 42", Size: 1, Hash: leaf})
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
	}{Checkpoint: string(cp), Hashes: []string{}, LogIndex: 0, RootHash: hex.EncodeToString(leaf), TreeSize: 1}
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
	v, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, at)
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
		if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, at); !errors.Is(err, ErrWrongKind) || errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same good entry with its signed entry timestamp broken: the
	// log's checks fail, so unverified, whatever its body.
	id, e = l.log(t, dsse, when)
	e.Verification.SignedEntryTimestamp[10] ^= 1
	if _, err := VerifyEntry(ctx, id, e, host, l.logs, [][]byte{aspki}, at); !errors.Is(err, ErrUnverified) {
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
