package site

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The embedded roots parse, are dated, and the staging one verifies the
// test vote's bundles.
func TestEmbeddedRoots(t *testing.T) {
	var at time.Time
	for _, instance := range []string{Production, Staging} {
		b, when, err := EmbeddedRoot(instance)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := root.NewTrustedRootFromJSON(b); err != nil {
			t.Fatalf("%s: %v", instance, err)
		}
		at = when
	}
	if at.IsZero() || at.After(time.Now()) {
		t.Fatalf("embedded at %v", at)
	}
	if _, _, err := EmbeddedRoot("other"); err == nil {
		t.Fatal("an unknown instance")
	}
	b, _, _ := EmbeddedRoot(Staging)
	tr, _ := root.NewTrustedRootFromJSON(b)
	f := loadFixture(t)
	if _, err := NewAnchorsWith(tr).Verify(f.Proposal.Bundle, f.Proposal.Doc, f.AnchorKey); err != nil {
		t.Fatalf("the embedded staging root doesn't verify the test vote: %v", err)
	}
}

// A start uses the fetched root; if the fetch fails, the embedded one
// unless it is over MaxEmbeddedAge old. The root is fetched again at
// most once per RootRefresh, and a failed fetch keeps the one in use.
func TestRootRefresh(t *testing.T) {
	emb, embAt, err := EmbeddedRoot(Staging)
	if err != nil {
		t.Fatal(err)
	}
	fetched, _ := root.NewTrustedRootFromJSON(emb)
	clock := embAt.Add(time.Hour)
	now := func() time.Time { return clock }
	calls, fail := 0, false
	fetch := func() (root.TrustedMaterial, error) {
		calls++
		if fail {
			return nil, errors.New("unreachable")
		}
		return fetched, nil
	}

	a, err := newAnchorsFrom(emb, embAt, fetch, now)
	if err != nil || a.RootSource() != RootFromTUF || calls != 1 {
		t.Fatalf("a start with TUF: %v %s %d", err, a.RootSource(), calls)
	}
	clock = clock.Add(RootRefresh - time.Minute)
	a.trusted()
	if calls != 1 {
		t.Fatal("fetched again within a day")
	}
	clock = clock.Add(time.Minute)
	fail = true
	if a.trusted() == nil || calls != 2 || a.RootSource() != RootFromTUF {
		t.Fatalf("a failed refresh: %d calls, %s", calls, a.RootSource())
	}
	a.trusted()
	if calls != 2 {
		t.Fatal("a failed fetch was retried within a day")
	}

	// A cold start with TUF down: the embedded root, if fresh enough.
	clock = embAt.Add(MaxEmbeddedAge)
	a, err = newAnchorsFrom(emb, embAt, fetch, now)
	if err != nil || a.RootSource() != RootFromEmbedded || a.trusted() == nil {
		t.Fatalf("a cold start on the embedded root: %v", err)
	}
	fail = false
	clock = clock.Add(RootRefresh)
	if a.trusted(); a.RootSource() != RootFromTUF {
		t.Fatal("not refreshed from the embedded root")
	}
	fail = true
	clock = embAt.Add(MaxEmbeddedAge + time.Second)
	if _, err := newAnchorsFrom(emb, embAt, fetch, now); err == nil || !strings.Contains(err.Error(), "over 90 days old") {
		t.Fatalf("a cold start on a stale embedded root: %v", err)
	}
	// Given material is never refreshed.
	if NewAnchorsWith(fetched).RootSource() != RootFromFile {
		t.Fatal("given material")
	}
}
