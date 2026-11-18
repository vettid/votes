package site

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeBundles verifies "bundle:" and the hex SHA-256 of the document,
// under one key.
type fakeBundles struct{ spki []byte }

func fakeBundle(doc []byte) []byte { return []byte("bundle:" + hex.EncodeToString(sha(doc))) }

func (f fakeBundles) Verify(b, doc, spki []byte) (time.Time, error) {
	if !bytes.Equal(spki, f.spki) || !bytes.Equal(b, fakeBundle(doc)) {
		return time.Time{}, errors.New("not this document's bundle under this key")
	}
	return time.Unix(1, 0), nil
}

var testListKey = []byte("list anchor spki")

func logCheck(objs map[string][]byte, first int64, now time.Time, modified func(context.Context, string) (time.Time, error)) (*ChainReport, error) {
	lg := &ListLog{Anchors: fakeBundles{spki: testListKey}, SPKI: testListKey, First: first}
	return CheckServiceChainLogged(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), now, modified, lg)
}

// Rolled back to the list before logging began: a first logged version
// past the current one is an error, not a clean pass with nothing
// checked.
func TestServiceChainLogRollbackBeforeFirst(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/3.bundle"] = fakeBundle(datas[2])
	objs["v1/services.json"], objs["v1/services.json.sig"] = objs["v1/services/2.json"], objs["v1/services/2.json.sig"]
	if _, err := logCheck(objs, 3, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("%v", err)
	}
}

// A Last-Modified in the future doesn't hold the grace open.
func TestServiceChainLogFutureModified(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/3.bundle"] = fakeBundle(datas[2])
	objs["v1/services/4.bundle"] = []byte("bundle:anything")
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) func(context.Context, string) (time.Time, error) {
		return func(context.Context, string) (time.Time, error) { return now.Add(d), nil }
	}
	if rep, err := logCheck(objs, 3, now, at(time.Minute)); err != nil || len(rep.Mismatches) != 0 {
		t.Fatalf("within the skew: %v %+v", err, rep)
	}
	if rep, err := logCheck(objs, 3, now, at(time.Minute+time.Second)); err != nil || !has(rep.Mismatches, "services/4: a bundle past") {
		t.Fatalf("past the skew: %v %+v", err, rep)
	}
}

func has(ms []string, s string) bool {
	for _, m := range ms {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// From the first logged version on, every version's bundle anchors its
// bytes; versions before it need none.
func TestServiceChainLogged(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/2.bundle"], objs["v1/services/3.bundle"] = fakeBundle(datas[1]), fakeBundle(datas[2])
	rep, err := logCheck(objs, 2, time.Now(), nil)
	if err != nil || len(rep.Mismatches) != 0 || rep.Logged != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
	// From version 1: its bundle is missing, a mismatch.
	if rep, err := logCheck(objs, 1, time.Now(), nil); err != nil || !has(rep.Mismatches, "services/1: no bundle") || rep.Logged != 2 {
		t.Fatalf("%v %+v", err, rep)
	}
	// Without the log, nothing of it is checked.
	if rep, err := chainCheck(objs); err != nil || rep.Logged != 0 || len(rep.Mismatches) != 0 {
		t.Fatalf("%v %+v", err, rep)
	}
}

// The current version's bundle is required at once (it is written before
// the list moves); one for other bytes, or under another key, is an error.
func TestServiceChainLogRefuses(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/2.bundle"] = fakeBundle(datas[1])
	if rep, err := logCheck(objs, 2, time.Now(), nil); err != nil || !has(rep.Mismatches, "services/3: no bundle") {
		t.Fatalf("the current version unlogged: %v %+v", err, rep)
	}
	objs["v1/services/3.bundle"] = fakeBundle(datas[1])
	if _, err := logCheck(objs, 2, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "services/3.bundle") {
		t.Fatalf("another version's bundle: %v", err)
	}
	objs["v1/services/3.bundle"] = fakeBundle(datas[2])
	lg := &ListLog{Anchors: fakeBundles{spki: testListKey}, SPKI: []byte("another key"), First: 2}
	if _, err := CheckServiceChainLogged(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), time.Now(), nil, lg); err == nil {
		t.Fatal("another key")
	}
}

// The current version's copy missing (it is written just after the list):
// the list itself is still checked against its bundle.
func TestServiceChainLogCurrentCopyMissing(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/3.bundle"] = fakeBundle(datas[2])
	delete(objs, "v1/services/3.json")
	delete(objs, "v1/services/3.json.sig")
	rep, err := logCheck(objs, 3, time.Now(), nil)
	if err != nil || rep.Logged != 1 || !has(rep.Mismatches, "services/3: not published") {
		t.Fatalf("%v %+v", err, rep)
	}
	delete(objs, "v1/services/3.bundle")
	if rep, err := logCheck(objs, 3, time.Now(), nil); err != nil || !has(rep.Mismatches, "services/3: no bundle") {
		t.Fatalf("%v %+v", err, rep)
	}
}

// A bundle past the current version is a list logged but not served: a
// mismatch once it is older than ListingGrace (a publish in progress
// writes it first).
func TestServiceChainLogPastCurrent(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/3.bundle"] = fakeBundle(datas[2])
	objs["v1/services/4.bundle"] = []byte("bundle:anything")
	written := time.Unix(1_800_000_000, 0)
	modified := func(_ context.Context, p string) (time.Time, error) {
		if p != "v1/services/4.bundle" {
			return time.Time{}, errors.New("unexpected")
		}
		return written, nil
	}
	if rep, err := logCheck(objs, 3, written.Add(ListingGrace), modified); err != nil || len(rep.Mismatches) != 0 {
		t.Fatalf("in progress: %v %+v", err, rep)
	}
	if rep, err := logCheck(objs, 3, written.Add(ListingGrace+time.Second), modified); err != nil || !has(rep.Mismatches, "services/4: a bundle past the current version") {
		t.Fatalf("stale: %v %+v", err, rep)
	}
	if rep, err := logCheck(objs, 3, written, nil); err != nil || !has(rep.Mismatches, "services/4: a bundle past") {
		t.Fatalf("no modified: %v %+v", err, rep)
	}
}

// The pins: a first logged version from 1 to the next version, a key.
func TestServiceChainLogPins(t *testing.T) {
	f := loadFixture(t)
	objs, _ := chainSite(t, f)
	// The next version (pinned before its publish) is an error too.
	for _, first := range []int64{0, -1, 4, 5} {
		if _, err := logCheck(objs, first, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "pins") {
			t.Errorf("first %d: %v", first, err)
		}
	}
	// The current version, logged: clean.
	objs["v1/services/3.bundle"] = fakeBundle(objs["v1/services/3.json"])
	if rep, err := logCheck(objs, 3, time.Now(), nil); err != nil || len(rep.Mismatches) != 0 || rep.Logged != 1 {
		t.Fatalf("from the current version: %v %+v", err, rep)
	}
	lg := &ListLog{Anchors: fakeBundles{spki: testListKey}, First: 1}
	if _, err := CheckServiceChainLogged(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), time.Now(), nil, lg); err == nil {
		t.Fatal("no key")
	}
	lg = &ListLog{SPKI: testListKey, First: 1}
	if _, err := CheckServiceChainLogged(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), time.Now(), nil, lg); err == nil {
		t.Fatal("no verifier")
	}
}

// A first logged version pinned past the real one: the version before it
// has a bundle, a mismatch (else the versions between go unchecked).
func TestServiceChainLogPinTooHigh(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/2.bundle"], objs["v1/services/3.bundle"] = fakeBundle(datas[1]), fakeBundle(datas[2])
	if rep, err := logCheck(objs, 3, time.Now(), nil); err != nil || !has(rep.Mismatches, "services/2: has a bundle, so the pinned first logged version is past the real one") {
		t.Fatalf("%v %+v", err, rep)
	}
	if rep, err := logCheck(objs, 2, time.Now(), nil); err != nil || len(rep.Mismatches) != 0 {
		t.Fatalf("the real first: %v %+v", err, rep)
	}
}

// An answer that isn't a 404 (an error) on any bundle fails the check: it
// never reads as "not there".
func TestServiceChainLogFetchErrors(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	objs["v1/services/2.bundle"], objs["v1/services/3.bundle"] = fakeBundle(datas[1]), fakeBundle(datas[2])
	for _, p := range []string{"v1/services/3.bundle", "v1/services/4.bundle", "v1/services/1.bundle"} {
		failing := func(ctx context.Context, path string) ([]byte, error) {
			if path == p {
				return nil, errors.New("403")
			}
			return fetcher(objs)(ctx, path)
		}
		lg := &ListLog{Anchors: fakeBundles{spki: testListKey}, SPKI: testListKey, First: 2}
		if _, err := CheckServiceChainLogged(context.Background(), failing, siteKey().Public().(ed25519.PublicKey), time.Now(), nil, lg); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s: %v", p, err)
		}
	}
}
