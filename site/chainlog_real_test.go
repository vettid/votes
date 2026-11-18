package site

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The walk with the real verifier: service-vault's anchor vector (a real
// staging bundle, over a proposal) kept as a version's bundle fails under
// staging's root (it anchors another document) and under production's
// (another instance). No real bundle over a signed list is kept here, so
// a passing case is the fake verifier's.
func TestServiceChainLogRealVerifier(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/service-vault")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "vote", "testdata", "anchor-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		AnchorKey   []byte          `json:"anchor_key"`
		Bundle      json.RawMessage `json:"bundle"`
		TrustedRoot json.RawMessage `json:"trusted_root"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	staging, err := root.NewTrustedRootFromJSON(v.TrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	emb, _, err := EmbeddedRoot(Production)
	if err != nil {
		t.Fatal(err)
	}
	production, err := root.NewTrustedRootFromJSON(emb)
	if err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t)
	objs, _ := chainSite(t, f)
	objs["v1/services/3.bundle"] = v.Bundle
	for name, tr := range map[string]root.TrustedMaterial{"staging": staging, "production": production} {
		lg := &ListLog{Anchors: NewAnchorsWith(tr), SPKI: v.AnchorKey, First: 3}
		_, err := CheckServiceChainLogged(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), time.Now(), nil, lg)
		if err == nil || !strings.Contains(err.Error(), "services/3.bundle") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
