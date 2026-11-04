package site

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"time"

	"github.com/vettid/service-vault/vote"
)

// ChainReport is what a walk of the service list's kept versions found
// (docs/VOTES-SITE.md §3, services/<version>.json).
type ChainReport struct {
	// Version is the current list's, from services.json.
	Version int64
	// Checked is how many kept versions were fetched and verified.
	Checked int
	// Mismatches name what a monitor fails on: a version whose copy isn't
	// published, or a copy past the current version (a stray, which
	// publish-services would refuse every later list for).
	Mismatches []string
}

// CheckServiceChain walks the kept versions of the service list,
// services/1 to the current one: each copy's signature verifies under the
// site's key, it holds its own version, the first names an all-zero
// previous, and each Extends the one before it with the next version; the
// current version's copy is the current list. A link that can't be
// checked because a copy is missing is reported in Mismatches, with the
// copy; a copy that doesn't verify or doesn't chain is an error. The
// current version's copy is written just after the list (§3), so its
// absence is a mismatch only ListingGrace after services.json was last
// modified, as modified says (nil, or an error: at once).
func CheckServiceChain(ctx context.Context, fetch Fetcher, siteKey ed25519.PublicKey, now time.Time,
	modified func(ctx context.Context, path string) (time.Time, error)) (*ChainReport, error) {
	cur, curSig, err := fetchPair(ctx, fetch, "v1/services.json")
	if err != nil {
		return nil, err
	}
	if cur == nil || curSig == nil {
		return nil, fmt.Errorf("site: services.json or its signature isn't published")
	}
	current, err := ParseServiceList(cur, curSig, siteKey)
	if err != nil {
		return nil, fmt.Errorf("site: services.json: %w", err)
	}
	rep := &ChainReport{Version: current.Version}
	var prev *ServiceList
	var prevData []byte
	link := func(name string, l *ServiceList, data []byte) error {
		switch {
		case l.Version == 1:
			if !bytes.Equal(l.Previous, make([]byte, vote.HashLen)) {
				return fmt.Errorf("site: %s: the first version names a previous list", name)
			}
		case prev != nil:
			if l.Version != prev.Version+1 {
				return fmt.Errorf("site: %s: version %d follows %d", name, l.Version, prev.Version)
			}
			if err := Extends(prev, prevData, l); err != nil {
				return fmt.Errorf("site: %s: %w", name, err)
			}
		}
		prev, prevData = l, data
		return nil
	}
	for v := int64(1); v <= current.Version; v++ {
		path := "v1/services/" + strconv.FormatInt(v, 10) + ".json"
		data, sig, err := fetchPair(ctx, fetch, path)
		if err != nil {
			return nil, err
		}
		if data == nil || sig == nil {
			if v != current.Version || !recent(ctx, modified, now) {
				rep.Mismatches = append(rep.Mismatches, "services/"+strconv.FormatInt(v, 10)+": not published")
			}
			if v == current.Version {
				// The list itself still chains to the copy before it.
				if err := link("services.json", current, cur); err != nil {
					return nil, err
				}
				break
			}
			prev, prevData = nil, nil // the next link can't be checked
			continue
		}
		l, err := ParseServiceList(data, sig, siteKey)
		if err != nil {
			return nil, fmt.Errorf("site: %s: %w", path, err)
		}
		if l.Version != v {
			return nil, fmt.Errorf("site: %s holds version %d", path, l.Version)
		}
		if err := link(path, l, data); err != nil {
			return nil, err
		}
		rep.Checked++
		if v == current.Version && (!bytes.Equal(data, cur) || !bytes.Equal(sig, curSig)) {
			return nil, fmt.Errorf("site: %s isn't the current services.json", path)
		}
	}
	next := "v1/services/" + strconv.FormatInt(current.Version+1, 10) + ".json"
	if data, sig, err := fetchPair(ctx, fetch, next); err != nil {
		return nil, err
	} else if data != nil || sig != nil {
		rep.Mismatches = append(rep.Mismatches, "services/"+strconv.FormatInt(current.Version+1, 10)+": published past the current version")
	}
	return rep, nil
}

// recent reports whether services.json changed within ListingGrace.
func recent(ctx context.Context, modified func(context.Context, string) (time.Time, error), now time.Time) bool {
	if modified == nil {
		return false
	}
	t, err := modified(ctx, "v1/services.json")
	return err == nil && !t.IsZero() && now.Sub(t) <= ListingGrace
}

// fetchPair fetches a list and its signature (path + ".sig").
func fetchPair(ctx context.Context, fetch Fetcher, path string) (data, sig []byte, err error) {
	if data, err = fetch(ctx, path); err != nil {
		return nil, nil, err
	}
	if sig, err = fetch(ctx, path+".sig"); err != nil {
		return nil, nil, err
	}
	return data, sig, nil
}
