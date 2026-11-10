package site

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
)

// signedList is a list's canonical bytes and the site's signature.
func signedList(t *testing.T, l *ServiceList, key ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	if b, err = vote.Canonicalize(b); err != nil {
		t.Fatal(err)
	}
	sig, _ := suite.Sign(key, vote.LabelServiceList, sha(b))
	return b, sig
}

// chainSite publishes versions 1 to 3 of a list as publish-services does:
// each kept as services/<v>.json, the last also current.
func chainSite(t *testing.T, f *fixture) (map[string][]byte, [][]byte) {
	t.Helper()
	objs := map[string][]byte{}
	l := f.list()
	var datas [][]byte
	for v := int64(1); v <= 3; v++ {
		if v > 1 {
			l.Version, l.Previous = v, sha(datas[len(datas)-1])
			l.Services[0].Name = "Test service " + string(rune('0'+v))
		}
		data, sig := signedList(t, l, siteKey())
		datas = append(datas, data)
		p := "v1/services/" + string(rune('0'+v)) + ".json"
		objs[p], objs[p+".sig"] = data, sig
		objs["v1/services.json"], objs["v1/services.json.sig"] = data, sig
	}
	return objs, datas
}

func chainCheck(objs map[string][]byte) (*ChainReport, error) {
	return CheckServiceChain(context.Background(), fetcher(objs), siteKey().Public().(ed25519.PublicKey), time.Now(), nil)
}

func TestServiceChain(t *testing.T) {
	f := loadFixture(t)
	objs, datas := chainSite(t, f)
	rep, err := chainCheck(objs)
	if err != nil || rep.Version != 3 || rep.Checked != 3 || len(rep.Mismatches) != 0 {
		t.Fatalf("the chain: %+v %v", rep, err)
	}
	// Each version's digest, once.
	if len(rep.Digests) != 3 {
		t.Fatalf("%d digests", len(rep.Digests))
	}
	for _, d := range datas {
		if !slices.ContainsFunc(rep.Digests, func(x []byte) bool { return bytes.Equal(x, sha(d)) }) {
			t.Error("a version's digest is missing")
		}
	}

	// Missing copies are mismatches: the current one's still chains.
	for name, c := range map[string]struct {
		drop string
		want string
	}{
		"a middle copy":  {"v1/services/2.json", "services/2: not published"},
		"the current's":  {"v1/services/3.json.sig", "services/3: not published"},
		"the first copy": {"v1/services/1.json", "services/1: not published"},
	} {
		o := maps.Clone(objs)
		delete(o, c.drop)
		rep, err := chainCheck(o)
		if err != nil || !slices.Contains(rep.Mismatches, c.want) {
			t.Fatalf("%s: %+v %v", name, rep, err)
		}
	}
	// The current version's copy may lag services.json by ListingGrace.
	o := maps.Clone(objs)
	delete(o, "v1/services/3.json")
	published := time.Unix(1793354334, 0)
	modified := func(_ context.Context, path string) (time.Time, error) {
		if path != "v1/services.json" {
			t.Fatalf("modified: %s", path)
		}
		return published, nil
	}
	key := siteKey().Public().(ed25519.PublicKey)
	if rep, err := CheckServiceChain(context.Background(), fetcher(o), key, published.Add(ListingGrace), modified); err != nil || len(rep.Mismatches) != 0 {
		t.Fatalf("the current copy within the grace: %+v %v", rep, err)
	}
	if rep, err := CheckServiceChain(context.Background(), fetcher(o), key, published.Add(ListingGrace+time.Second), modified); err != nil ||
		!slices.Equal(rep.Mismatches, []string{"services/3: not published"}) {
		t.Fatalf("the current copy past the grace: %+v %v", rep, err)
	}
	o = maps.Clone(objs)
	delete(o, "v1/services/2.json")
	if rep, err := CheckServiceChain(context.Background(), fetcher(o), key, published, modified); err != nil ||
		!slices.Equal(rep.Mismatches, []string{"services/2: not published"}) {
		t.Fatalf("an earlier copy has no grace: %+v %v", rep, err)
	}

	o = maps.Clone(objs)
	o["v1/services/4.json"] = objs["v1/services/3.json"]
	if rep, err := chainCheck(o); err != nil || !slices.Contains(rep.Mismatches, "services/4: published past the current version") {
		t.Fatalf("a stray past the current version: %+v %v", rep, err)
	}

	// What doesn't verify or chain is an error.
	l2 := f.list()
	l2.Version, l2.Previous = 2, sha(objs["v1/services/1.json"])
	l2.Services = []Service{}
	dropped, droppedSig := signedList(t, l2, siteKey())
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	l2.Services = f.list().Services
	foreign, foreignSig := signedList(t, l2, other)
	l3 := f.list()
	l3.Version, l3.Previous = 3, sha(objs["v1/services/2.json"])
	l3.Services[0].Name = "Another name"
	alt, altSig := signedList(t, l3, siteKey())
	// The first version's previous is 32 zero bytes: an empty or a
	// nonzero one doesn't verify as a list, or doesn't start the chain.
	l1 := f.list()
	l1.Previous = []byte{}
	empty, emptySig := signedList(t, l1, siteKey())
	l1.Previous = bytes.Repeat([]byte{1}, 32)
	nonzero, nonzeroSig := signedList(t, l1, siteKey())
	for name, c := range map[string]struct {
		change func(map[string][]byte)
		want   string
	}{
		"another key's signature": {func(o map[string][]byte) { o["v1/services/2.json"], o["v1/services/2.json.sig"] = foreign, foreignSig }, "signature"},
		"an empty previous":       {func(o map[string][]byte) { o["v1/services/1.json"], o["v1/services/1.json.sig"] = empty, emptySig }, "fields"},
		"a nonzero previous":      {func(o map[string][]byte) { o["v1/services/1.json"], o["v1/services/1.json.sig"] = nonzero, nonzeroSig }, "names a previous"},
		"a dropped service":       {func(o map[string][]byte) { o["v1/services/2.json"], o["v1/services/2.json.sig"] = dropped, droppedSig }, "dropped"},
		"a copy of another version": {func(o map[string][]byte) {
			o["v1/services/2.json"], o["v1/services/2.json.sig"] = o["v1/services/1.json"], o["v1/services/1.json.sig"]
		}, "holds version 1"},
		"the current list isn't its copy": {func(o map[string][]byte) {
			o["v1/services/3.json"], o["v1/services/3.json.sig"] = alt, altSig
		}, "isn't the current services.json"},
	} {
		o := maps.Clone(objs)
		c.change(o)
		if _, err := chainCheck(o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
