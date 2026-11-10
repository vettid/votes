package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/vettid/votes/rekor"
	"github.com/vettid/votes/site"
)

// rekorFlags are votesctl check's Rekor flags (docs/VOTES-SITE.md §7, "The
// Rekor check").
type rekorFlags struct {
	on                bool
	state, verified   string
	acknowledged      string
	bootstrap         bool
	bootstrapReplaces string
	acceptShard       string
	resetPin          string
	resetStore        bool
}

func (f *rekorFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.on, "rekor", false, "with -all: the Rekor check")
	fs.StringVar(&f.state, "rekor-state", "", "the Rekor check's state file (read, and rewritten)")
	fs.StringVar(&f.verified, "rekor-verified", "", "the verified store file (read, and rewritten)")
	fs.StringVar(&f.acknowledged, "rekor-acknowledged", "", "a file of acknowledged Rekor entries")
	fs.BoolVar(&f.bootstrap, "rekor-bootstrap", false, "owner-run: record the checkpoint found, over an empty or sentinel state")
	fs.StringVar(&f.bootstrapReplaces, "rekor-bootstrap-replaces", "", "owner-run, with -rekor-bootstrap: the SHA-256 of an unparseable state it replaces")
	fs.StringVar(&f.acceptShard, "rekor-accept-shard", "", "owner-run: accept a changed shard, by its tree ID")
	fs.StringVar(&f.resetPin, "rekor-reset-pin", "", "owner-run: <size>:<root hex> of the recorded checkpoint an inconsistent pin replaces")
	fs.BoolVar(&f.resetStore, "rekor-reset-store", false, "owner-run: start the verified store empty")
}

// usage reports a flag combination that is a usage error.
func (f *rekorFlags) usage(all bool, sinceSet bool) error {
	admin := f.bootstrap || f.bootstrapReplaces != "" || f.acceptShard != "" || f.resetPin != "" || f.resetStore
	switch {
	case !f.on && (admin || f.state != "" || f.verified != "" || f.acknowledged != ""):
		return errors.New("the -rekor- flags need -rekor")
	case f.on && !all:
		return errors.New("-rekor needs -all")
	case f.on && sinceSet:
		return errors.New("-rekor refuses -since: the older proposals' digests would be left out")
	case (f.bootstrap || f.acceptShard != "" || f.resetPin != "") && f.state == "":
		return errors.New("an owner-run Rekor step needs -rekor-state")
	case f.resetStore && f.verified == "":
		return errors.New("-rekor-reset-store needs -rekor-verified")
	}
	return nil
}

// rekorHosts are the Rekor v1 instances (VOTES-SITE §7).
var rekorHosts = map[string]string{site.Production: "rekor.sigstore.dev", site.Staging: "rekor.sigstage.dev"}

// rekorCollect gathers, from the site's check, what the Rekor check
// compares with: the known and unexpected digests, each bundle's entry,
// and documents anchored without one.
type rekorCollect struct {
	known      map[string]time.Time
	unexpected map[string]string
	bundles    []rekor.Bundle
	noEntry    []string
}

func newRekorCollect() *rekorCollect {
	return &rekorCollect{known: map[string]time.Time{}, unexpected: map[string]string{}}
}

func (c *rekorCollect) proposal(rep *site.Report) {
	for name, h := range rep.Hashes {
		d := hex.EncodeToString(h)
		if name == "rows" {
			c.unexpected[d] = rep.ProposalID + "'s results rows"
			continue
		}
		var ref time.Time
		if e := rep.Entries[name]; e != nil {
			ref = e.Integrated
			c.bundles = append(c.bundles, rekor.Bundle{Name: rep.ProposalID + "/" + name, Digest: h, Leaf: e.Leaf, LogIndex: e.LogIndex,
				ShardIndex: e.ShardIndex, Integrated: e.Integrated, Checkpoint: e.Checkpoint})
		}
		if t, ok := c.known[d]; !ok || !ref.IsZero() && (t.IsZero() || ref.Before(t)) {
			c.known[d] = ref
		}
	}
	for name := range rep.Anchored {
		if rep.Entries[name] == nil {
			c.noEntry = append(c.noEntry, rep.ProposalID+"/"+name)
		}
	}
	// A partial upload's served documents: known (reported as partial
	// already), dated by the earliest entry found.
	for _, objs := range rep.PartialObjects {
		for _, o := range objs {
			if len(o.Key) > 5 && o.Key[len(o.Key)-5:] == ".json" {
				if _, ok := c.known[o.SHA256]; !ok {
					c.known[o.SHA256] = time.Time{}
				}
			}
		}
	}
}

func (c *rekorCollect) services(ch *site.ChainReport) {
	for _, d := range ch.Digests {
		c.unexpected[hex.EncodeToString(d)] = "a service list version (signed by the site key)"
	}
}

// errRekorAdmin wraps an owner-run step that doesn't apply (exit 2).
type errRekorAdmin struct{ err error }

func (e *errRekorAdmin) Error() string { return e.err.Error() }

// runRekor is the Rekor check, after the site's: it reads the anchor keys
// from the current service list, runs the check, writes the store and
// then the state, and returns the report's rekor member.
func runRekor(ctx context.Context, f *rekorFlags, instance string, anchors *site.Anchors, fetch site.Fetcher,
	siteKeyB64 string, col *rekorCollect, listsIncomplete bool, log rekor.Log, now time.Time) (*rekor.RunReport, error) {
	host, ok := rekorHosts[instance]
	if !ok {
		return nil, fmt.Errorf("no Rekor instance for %q", instance)
	}
	key, err := decodeSiteKey(siteKeyB64)
	if err != nil {
		return nil, err
	}
	cur, err := fetch(ctx, "v1/services.json")
	if err != nil || cur == nil {
		return nil, fmt.Errorf("services.json: %v", err)
	}
	sig, err := fetch(ctx, "v1/services.json.sig")
	if err != nil || sig == nil {
		return nil, fmt.Errorf("services.json.sig: %v", err)
	}
	list, err := site.ParseServiceList(cur, sig, key)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	for _, s := range list.Services {
		for _, a := range s.AnchorKeys {
			keys = append(keys, a.Key)
		}
	}
	tm := anchors.Trusted()
	in := rekor.RunInput{Instance: instance, Host: host, Logs: tm.RekorLogs(), Anchors: keys, Known: col.known,
		Unexpected: col.unexpected, Bundles: col.bundles, NoEntry: col.noEntry, ListsIncomplete: listsIncomplete,
		Scan: instance == site.Staging, State: rekor.LoadedState{Kind: rekor.StateNone},
		Admin: rekor.Admin{Bootstrap: f.bootstrap, BootstrapReplaces: f.bootstrapReplaces, AcceptShard: f.acceptShard, ResetPin: f.resetPin},
		Now:   func() time.Time { return now }}
	if f.state != "" {
		b, err := os.ReadFile(f.state)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		in.State = rekor.ParseState(b)
	}
	if f.verified != "" && !f.resetStore {
		b, err := os.ReadFile(f.verified)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if in.Store, err = rekor.ParseStore(b); err != nil {
			return nil, err
		}
	}
	if f.acknowledged != "" {
		b, err := os.ReadFile(f.acknowledged)
		if err != nil {
			return nil, err
		}
		if in.Acks, err = rekor.ParseAcks(b); err != nil {
			return nil, err
		}
	}
	if log == nil {
		log = &rekor.Client{Base: "https://" + host, HTTP: &http.Client{}}
	}
	rep, err := rekor.Run(ctx, log, in)
	if errors.Is(err, rekor.ErrAdminRefused) {
		return nil, &errRekorAdmin{err}
	}
	if err != nil {
		return nil, err
	}
	// The store before the state, each whole.
	if f.verified != "" && rep.NextStore != nil {
		if err := rekor.WriteFileAtomic(f.verified, rep.NextStore); err != nil {
			return nil, err
		}
	}
	if f.state != "" && rep.NextState != nil {
		if err := rekor.WriteFileAtomic(f.state, rep.NextState); err != nil {
			return nil, err
		}
	}
	return rep, nil
}
