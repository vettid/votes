package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/votes/site"
)

// stubVerifier stands for the run's trusted root.
type stubVerifier struct{ name string }

func (stubVerifier) Verify(_, _, _ []byte) (time.Time, error) { return time.Time{}, nil }

// The chain walk gets exactly the pins and the run's verifier: the pinned
// key (never anything else), the first version, pending; none unpinned.
func TestListLogFor(t *testing.T) {
	v := stubVerifier{name: "run"}
	pin := &listLogPin{spki: []byte("the pinned key"), first: 7}
	lg, desc := listLogFor(v, pin)
	if lg == nil || !bytes.Equal(lg.SPKI, pin.spki) || lg.First != 7 || lg.Pending || desc != "from version 7" {
		t.Fatalf("%+v %q", lg, desc)
	}
	if got, ok := lg.Anchors.(stubVerifier); !ok || got.name != "run" {
		t.Fatalf("verifier %v", lg.Anchors)
	}
	pin.pending = true
	if lg, desc := listLogFor(v, pin); !lg.Pending || desc != "from version 7 (pending: not published yet)" {
		t.Fatalf("%+v %q", lg, desc)
	}
	if lg, desc := listLogFor(v, nil); lg != nil || desc != "not pinned" {
		t.Fatalf("%+v %q", lg, desc)
	}
	var _ site.BundleVerifier = v
}
