package site

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The service vault's anchor-bundle vector (BALLOT-PROTOCOL §11 item 3),
// read from the pinned module, verifies with Sigstore's verifier under its
// trusted root, at its timestamp; the stdlib checks are the service
// vault's own test.
func TestAnchorVector(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/service-vault").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "vote", "testdata", "anchor-vector.json"))
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
	// Other bytes, another key, and a bundle whose entry is altered.
	if _, err := a.Verify(v.Bundle, append(doc, ' '), v.AnchorKey); err == nil {
		t.Error("other bytes verified")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := a.Verify(v.Bundle, doc, other); err == nil {
		t.Error("another key verified")
	}
	bad := bytes.Replace(v.Bundle, []byte(`"integratedTime": "`), []byte(`"integratedTime": "1`), 1)
	if bytes.Equal(bad, v.Bundle) {
		t.Fatal("no integratedTime to alter")
	}
	if _, err := a.Verify(bad, doc, v.AnchorKey); err == nil {
		t.Error("an altered entry verified")
	}
}
