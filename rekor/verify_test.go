package rekor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/vettid/votes/site"
)

// The fixtures are reads of rekor.sigstage.dev (2026-11-10) for the
// staging service's anchor key: the log before and after, a consistency
// proof between them, the search's answer and its four entries.
const (
	host        = "rekor.sigstage.dev"
	stagingSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5bG4J1Tt1+OurhyU+nKVp9NaFwRqbO0fgo1MqFRcf6sojaBGr4ToGANz5jv6nETgDxscLRZi4sphfgt3zQrndA=="
)

func fixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func stagingLogs(t *testing.T) Logs {
	t.Helper()
	b, _, err := site.EmbeddedRoot(site.Staging)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return tr.RekorLogs()
}

func anchors(t *testing.T) [][]byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(stagingSPKI)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{b}
}

func entries(t *testing.T) map[string]*Entry {
	t.Helper()
	var raw []map[string]*Entry
	fixture(t, "entries.json", &raw)
	out := map[string]*Entry{}
	for _, m := range raw {
		for k, v := range m {
			out[k] = v
		}
	}
	if len(out) != 4 {
		t.Fatalf("%d entries in the fixture", len(out))
	}
	return out
}

var at = time.Date(2026, 11, 10, 16, 0, 0, 0, time.UTC)

// The recorded entries verify: each an anchor key's, its digest, its
// global and shard indexes, against a checkpoint of the log's.
func TestVerifyRecordedEntries(t *testing.T) {
	ctx := context.Background()
	logs := stagingLogs(t)
	var li LogInfo
	fixture(t, "log-before.json", &li)
	for id, e := range entries(t) {
		v, err := VerifyEntry(ctx, id, e, host, logs, anchors(t))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if v.Leaf != id[16:] || len(v.Digest) != 32 || v.LogIndex <= v.ShardIndex || v.Proof.TreeID != li.TreeID || v.Integrated.IsZero() {
			t.Errorf("%s: %+v", id, v)
		}
		if v.Integrated.After(at) {
			t.Errorf("%s integrated after the fixture was recorded", id)
		}
	}
}

// Any change to an entry is refused as unverified; an entry naming no
// anchor key is ErrNotAnchor.
func TestVerifyEntryRefuses(t *testing.T) {
	ctx := context.Background()
	logs := stagingLogs(t)
	var id string
	var orig *Entry
	for k, v := range entries(t) {
		id, orig = k, v
		break
	}
	clone := func() *Entry {
		b, _ := json.Marshal(orig)
		var e Entry
		_ = json.Unmarshal(b, &e)
		return &e
	}
	flip := func(s string) string { // one hex digit changed
		b := []byte(s)
		if b[10] == '0' {
			b[10] = '1'
		} else {
			b[10] = '0'
		}
		return string(b)
	}
	cases := map[string]func(e *Entry) (string, *Entry){
		"another leaf":      func(e *Entry) (string, *Entry) { return id[:40] + flip(id[40:]), e },
		"id not hex length": func(e *Entry) (string, *Entry) { return id[:70], e },
		"integrated time":   func(e *Entry) (string, *Entry) { e.IntegratedTime++; return id, e },
		"global index":      func(e *Entry) (string, *Entry) { e.LogIndex++; return id, e },
		"shard index":       func(e *Entry) (string, *Entry) { e.Verification.InclusionProof.LogIndex++; return id, e },
		"set":               func(e *Entry) (string, *Entry) { e.Verification.SignedEntryTimestamp[8] ^= 1; return id, e },
		"no set":            func(e *Entry) (string, *Entry) { e.Verification.SignedEntryTimestamp = nil; return id, e },
		"proof hash": func(e *Entry) (string, *Entry) {
			h := e.Verification.InclusionProof.Hashes
			h[0] = flip(h[0])
			return id, e
		},
		"proof root": func(e *Entry) (string, *Entry) {
			p := e.Verification.InclusionProof
			p.RootHash = flip(p.RootHash)
			return id, e
		},
		"no proof": func(e *Entry) (string, *Entry) { e.Verification.InclusionProof = nil; return id, e },
		"checkpoint": func(e *Entry) (string, *Entry) {
			p := e.Verification.InclusionProof
			p.Checkpoint = strings.Replace(p.Checkpoint, "\n", "\n1", 1)
			return id, e
		},
		"another log id":  func(e *Entry) (string, *Entry) { e.LogID = flip(e.LogID); return id, e },
		"body not base64": func(e *Entry) (string, *Entry) { e.Body = "%%"; return id, e },
	}
	for name, change := range cases {
		gotID, e := change(clone())
		if _, err := VerifyEntry(ctx, gotID, e, host, logs, anchors(t)); !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyEntry(ctx, id, clone(), host, logs, nil); !errors.Is(err, ErrNotAnchor) {
		t.Errorf("no anchor key: %v", err)
	}
	if _, err := VerifyEntry(ctx, id, clone(), "rekor.sigstore.dev", logs, anchors(t)); !errors.Is(err, ErrUnverified) {
		t.Errorf("another host: %v", err)
	}
	if _, err := VerifyEntry(ctx, id, clone(), host, Logs{}, anchors(t)); !errors.Is(err, ErrUnverified) {
		t.Errorf("no trusted log: %v", err)
	}
	if _, err := VerifyEntry(ctx, strings.ToUpper(id), clone(), host, logs, anchors(t)); err != nil {
		t.Errorf("upper-case id: %v", err)
	}
	// Named by its leaf hash, whatever tree ID prefix Rekor gives it.
	if v, err := VerifyEntry(ctx, flip(id), clone(), host, logs, anchors(t)); err != nil || v.Leaf != id[16:] {
		t.Errorf("another tree prefix: %v", err)
	}
}

// testKey is a P-256 key from a fixed, public test seed.
func testKey(seed string) *ecdsa.PrivateKey {
	h := sha256.Sum256([]byte(seed))
	c := elliptic.P256()
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, new(big.Int).Sub(c.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k := &ecdsa.PrivateKey{D: d}
	k.PublicKey.Curve = c
	k.PublicKey.X, k.PublicKey.Y = c.ScalarBaseMult(d.Bytes())
	return k
}

func body(t *testing.T, kind, version, alg, digestHex string, keyPEM, sig []byte) []byte {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"kind": kind, "apiVersion": version, "spec": map[string]any{
		"data":      map[string]any{"hash": map[string]string{"algorithm": alg, "value": digestHex}},
		"signature": map[string]any{"content": sig, "publicKey": map[string]any{"content": keyPEM}},
	}})
	return b
}

// The body's own checks: a hashedrekord 0.0.1 over a sha256 digest with a
// signature that verifies; any key form (a certificate, CRLF line ends,
// no final newline) names the key by SPKI.
func TestCheckBody(t *testing.T) {
	k := testKey("votes rekor test key")
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	digest := sha256.Sum256([]byte("a document"))
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	dh := hex.EncodeToString(digest[:])
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, kp := range map[string][]byte{
		"key":         keyPEM,
		"crlf":        []byte(strings.ReplaceAll(string(keyPEM), "\n", "\r\n")),
		"no newline":  []byte(strings.TrimSuffix(string(keyPEM), "\n")),
		"certificate": certPEM,
	} {
		b := body(t, "hashedrekord", "0.0.1", "sha256", dh, kp, sig)
		if got, err := checkBody(b); err != nil || hex.EncodeToString(got) != dh {
			t.Errorf("%s: %v", name, err)
		}
		e := &Entry{Body: base64.StdEncoding.EncodeToString(b)}
		if a := AnchorOf(e, [][]byte{spki}); a == nil {
			t.Errorf("%s: anchor key not found", name)
		}
	}
	bad := map[string][]byte{
		"kind":      body(t, "intoto", "0.0.1", "sha256", dh, keyPEM, sig),
		"version":   body(t, "hashedrekord", "0.0.2", "sha256", dh, keyPEM, sig),
		"sha512":    body(t, "hashedrekord", "0.0.1", "sha512", dh, keyPEM, sig),
		"short":     body(t, "hashedrekord", "0.0.1", "sha256", dh[:62], keyPEM, sig),
		"uppercase": body(t, "hashedrekord", "0.0.1", "sha256", strings.ToUpper(dh), keyPEM, sig),
		"signature": body(t, "hashedrekord", "0.0.1", "sha256", hex.EncodeToString(make([]byte, 32)), keyPEM, sig),
		"no key":    body(t, "hashedrekord", "0.0.1", "sha256", dh, []byte("x"), sig),
		"not json":  []byte("{"),
	}
	for name, b := range bad {
		if _, err := checkBody(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other := testKey("another key")
	ospki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if AnchorOf(&Entry{Body: base64.StdEncoding.EncodeToString(body(t, "hashedrekord", "0.0.1", "sha256", dh, keyPEM, sig))}, [][]byte{ospki}) != nil {
		t.Error("another key matched")
	}
}

// Checkpoints verify under the trusted root and name the host and tree;
// the later one is consistent with the earlier by the recorded proof; a
// shrunk tree, another root at a size, another tree or a changed proof
// are not.
func TestCheckpointsAndConsistency(t *testing.T) {
	logs := stagingLogs(t)
	var before, after LogInfo
	fixture(t, "log-before.json", &before)
	fixture(t, "log-after.json", &after)
	var p struct {
		Hashes []string `json:"hashes"`
	}
	fixture(t, "proof.json", &p)
	a, err := VerifyCheckpoint(before.SignedTreeHead, host, logs, at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyCheckpoint(after.SignedTreeHead, host, logs, at)
	if err != nil {
		t.Fatal(err)
	}
	if a.TreeID != before.TreeID || int64(a.Size) != before.TreeSize || hex.EncodeToString(a.Root) != before.RootHash {
		t.Fatalf("checkpoint %+v, log %+v", a, before.Shard)
	}
	if err := VerifyConsistency(a, b, p.Hashes); err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(a, a, nil); err != nil {
		t.Errorf("same checkpoint: %v", err)
	}
	if err := VerifyConsistency(b, a, p.Hashes); err == nil {
		t.Error("a shrunk tree is consistent")
	}
	forked := *a
	forked.Root = append([]byte(nil), a.Root...)
	forked.Root[0] ^= 1
	if err := VerifyConsistency(a, &forked, nil); err == nil {
		t.Error("another root at the same size is consistent")
	}
	if err := VerifyConsistency(&forked, b, p.Hashes); err == nil {
		t.Error("a proof from another root holds")
	}
	other := *b
	other.TreeID = "1"
	if err := VerifyConsistency(a, &other, p.Hashes); err == nil {
		t.Error("another tree is consistent")
	}
	changed := append([]string(nil), p.Hashes...)
	changed[0] = strings.Repeat("0", 64)
	if err := VerifyConsistency(a, b, changed); err == nil {
		t.Error("a changed proof holds")
	}
	if _, err := VerifyCheckpoint(before.SignedTreeHead, "rekor.sigstore.dev", logs, at); err == nil {
		t.Error("another host's origin accepted")
	}
	if _, err := VerifyCheckpoint(before.SignedTreeHead, host, Logs{}, at); err == nil {
		t.Error("verified without a trusted log")
	}
	if _, err := VerifyCheckpoint(strings.Replace(before.SignedTreeHead, "\n"+strconv.FormatInt(before.TreeSize, 10)+"\n", "\n"+strconv.FormatInt(before.TreeSize+1, 10)+"\n", 1), host, logs, at); err == nil {
		t.Error("a changed checkpoint verified")
	}
	if _, err := VerifyCheckpoint(before.SignedTreeHead, host, logs, time.Unix(0, 0)); err == nil {
		t.Error("verified before the log key's validity")
	}
}
