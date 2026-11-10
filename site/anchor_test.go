package site

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The service vault's anchor-bundle vector (BALLOT-PROTOCOL §11 item 3),
// read from the pinned module, verifies with Sigstore's verifier under its
// trusted root, at its timestamp; the stdlib checks are the service
// vault's own test.
func TestAnchorVector(t *testing.T) {
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/service-vault")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	dir := strings.TrimSpace(string(out))
	if err != nil || dir == "" {
		t.Fatalf("go list: %v: %s", err, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "vote", "testdata", "anchor-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		AnchorKey   []byte          `json:"anchor_key"`
		Proposal    string          `json:"proposal"`
		Timestamp   int64           `json:"timestamp"`
		Bundle      json.RawMessage `json:"bundle"`
		TrustedRoot json.RawMessage `json:"trusted_root"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromJSON(v.TrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAnchorsWith(tr)
	doc := []byte(v.Proposal)
	ts, err := a.Verify(v.Bundle, doc, v.AnchorKey)
	if err != nil || ts.Unix() != v.Timestamp {
		t.Fatalf("verify: %v at %v, want %d", err, ts, v.Timestamp)
	}
	// The bundle's own Rekor entry: its leaf hash is its body's (sha256 of
	// 0x00 and the body), its indexes and checkpoint the proof's.
	at, err := a.VerifyTimes(v.Bundle, doc, v.AnchorKey)
	if err != nil || at.Entry == nil {
		t.Fatalf("entry: %+v %v", at, err)
	}
	var bj struct {
		VerificationMaterial struct {
			TlogEntries []struct {
				LogIndex          string `json:"logIndex"`
				CanonicalizedBody []byte `json:"canonicalizedBody"`
				InclusionProof    struct {
					LogIndex   string `json:"logIndex"`
					TreeSize   string `json:"treeSize"`
					Checkpoint struct {
						Envelope string `json:"envelope"`
					} `json:"checkpoint"`
				} `json:"inclusionProof"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(v.Bundle, &bj); err != nil || len(bj.VerificationMaterial.TlogEntries) != 1 {
		t.Fatal("bundle: no single tlog entry")
	}
	te := bj.VerificationMaterial.TlogEntries[0]
	leaf := sha256.Sum256(append([]byte{0}, te.CanonicalizedBody...))
	e := at.Entry
	if !bytes.Equal(e.Leaf, leaf[:]) || strconv.FormatInt(e.LogIndex, 10) != te.LogIndex || strconv.FormatInt(e.ShardIndex, 10) != te.InclusionProof.LogIndex ||
		strconv.FormatInt(e.TreeSize, 10) != te.InclusionProof.TreeSize || e.Checkpoint != te.InclusionProof.Checkpoint.Envelope || e.Integrated.IsZero() {
		t.Errorf("entry %+v, bundle %+v", e, te)
	}
	// Other bytes, another key, and a bundle whose entry is altered.
	if _, err := a.Verify(v.Bundle, append(doc, ' '), v.AnchorKey); err == nil {
		t.Error("other bytes verified")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := a.Verify(v.Bundle, doc, other); err == nil {
		t.Error("another key verified")
	}
	// Another key the bundle names: Sigstore's verifier refuses it, not
	// only the hint check.
	h := sha256.Sum256(v.AnchorKey)
	renamed := bytes.Replace(v.Bundle, []byte(base64.StdEncoding.EncodeToString(h[:])), []byte(Hint(other)), 1)
	if bytes.Equal(renamed, v.Bundle) {
		t.Fatal("no hint to rewrite")
	}
	if _, err := a.Verify(renamed, doc, other); err == nil {
		t.Error("another key, named by the bundle, verified")
	}
	// The anchor key inside a certificate, not as a bare key: refused.
	// The Rekor check's production search can't find such an entry
	// (VOTES-SITE §7, "Not guaranteed"), so it must anchor nothing here.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	anchorPub, err := x509.ParsePKIXPublicKey(v.AnchorKey)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, anchorPub, k)
	if err != nil {
		t.Fatal(err)
	}
	var bundle, material map[string]json.RawMessage
	if json.Unmarshal(v.Bundle, &bundle) != nil || json.Unmarshal(bundle["verificationMaterial"], &material) != nil || material["publicKey"] == nil {
		t.Fatal("bundle: no publicKey")
	}
	delete(material, "publicKey")
	material["certificate"], _ = json.Marshal(map[string][]byte{"rawBytes": certDER})
	bundle["verificationMaterial"], _ = json.Marshal(material)
	wrapped, _ := json.Marshal(bundle)
	if _, err := a.Verify(wrapped, doc, v.AnchorKey); err == nil {
		t.Error("a bundle with its key in a certificate verified")
	}
	// The RFC 3161 timestamp is required.
	var bm, vm map[string]json.RawMessage
	if json.Unmarshal(v.Bundle, &bm) != nil || json.Unmarshal(bm["verificationMaterial"], &vm) != nil || vm["timestampVerificationData"] == nil {
		t.Fatal("bundle: no timestampVerificationData")
	}
	delete(vm, "timestampVerificationData")
	bm["verificationMaterial"], _ = json.Marshal(vm)
	noTS, _ := json.Marshal(bm)
	if _, err := a.Verify(noTS, doc, v.AnchorKey); err == nil {
		t.Error("a bundle without a timestamp verified")
	}
	bad := bytes.Replace(v.Bundle, []byte(`"integratedTime": "`), []byte(`"integratedTime": "1`), 1)
	if bytes.Equal(bad, v.Bundle) {
		t.Fatal("no integratedTime to alter")
	}
	if _, err := a.Verify(bad, doc, v.AnchorKey); err == nil {
		t.Error("an altered entry verified")
	}
}

// VerifyTimes reads the Rekor time from the verified inclusion promise:
// an entry without one has none.
func TestVerifyTimesRekor(t *testing.T) {
	f := loadFixture(t)
	s, _ := newSite(t, f, f.during())
	at, err := s.Anchors.VerifyTimes(f.Proposal.Bundle, f.Proposal.Doc, f.AnchorKey)
	if err != nil || at.Rekor.Unix() != 1793354334 || at.TSA.IsZero() {
		t.Fatalf("times %+v %v", at, err)
	}
	var bm map[string]any
	_ = json.Unmarshal(f.Proposal.Bundle, &bm)
	e := bm["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	delete(e, "inclusionPromise")
	noPromise, _ := json.Marshal(bm)
	if at, err := s.Anchors.VerifyTimes(noPromise, f.Proposal.Doc, f.AnchorKey); err == nil && !at.Rekor.IsZero() {
		t.Fatalf("a Rekor time without a promise: %+v", at)
	}
	// A promise for another time doesn't verify.
	e2 := map[string]any{}
	_ = json.Unmarshal(f.Proposal.Bundle, &e2)
	ent := e2["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	ent["integratedTime"] = "1793354999"
	moved, _ := json.Marshal(e2)
	if _, err := s.Anchors.VerifyTimes(moved, f.Proposal.Doc, f.AnchorKey); err == nil {
		t.Fatal("a moved integrated time verified")
	}
}
