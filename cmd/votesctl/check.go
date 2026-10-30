package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/vettid/votes/site"
)

// maxObject bounds one fetched object: the rows of a large vote are the
// biggest.
const maxObject = 16 << 20

// httpFetcher reads published objects from a site's base URL. It follows
// no redirect and takes only a 404 as not published: the site answers
// 404 for a missing object, so a 403 (WAF, access) is an error, not an
// absent document.
func httpFetcher(base string, c *http.Client) site.Fetcher {
	base = strings.TrimRight(base, "/")
	return func(ctx context.Context, path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNotFound:
			return nil, nil
		default:
			return nil, fmt.Errorf("%s: %s", path, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxObject+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxObject {
			return nil, fmt.Errorf("%s: over %d bytes", path, maxObject)
		}
		return b, nil
	}
}

func noRedirects() *http.Client {
	return &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// report is the check's output.
type report struct {
	OK          bool              `json:"ok"`
	ProposalID  string            `json:"proposal_id"`
	ServiceID   string            `json:"service_id"`
	ServiceName string            `json:"service_name"`
	Title       string            `json:"title"`
	Eligible    int64             `json:"eligible"`
	OpensAt     int64             `json:"opens_at"`
	ClosesAt    int64             `json:"closes_at"`
	Extensions  int               `json:"extensions"`
	Anchored    map[string]string `json:"anchored"`
	// Status: open (before the close in force, plus the minute collection
	// takes), closed (after it, with no results published yet: the
	// service hasn't published them, or is withholding them), or counted.
	Status  string            `json:"status"`
	Results *results          `json:"results"` // null until counted
	Hashes  map[string]string `json:"hashes"`  // hex SHA-256, to compare with other readers
	Partial []string          `json:"partial,omitempty"`
}

type results struct {
	Tally    map[string]int64 `json:"tally"`
	Eligible int64            `json:"eligible"`
	Ballots  int64            `json:"ballots"`
	Removed  int64            `json:"removed"`
	// Unhandled: messages from before the close the count went ahead
	// without (BALLOT-PROTOCOL §7); each may have held a ballot.
	Unhandled int64 `json:"unhandled"`
}

// checkVote checks one proposal on a site and writes the report.
func checkVote(ctx context.Context, w io.Writer, fetch site.Fetcher, anchors *site.Anchors, siteKeyB64, id string, now time.Time) error {
	key, err := base64.StdEncoding.DecodeString(siteKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("-site-key: the site's public key, base64 of 32 bytes")
	}
	rep, err := site.Check(ctx, fetch, anchors, key, id)
	if err != nil {
		return err
	}
	out := report{OK: true, ProposalID: rep.ProposalID, ServiceID: rep.ServiceID, ServiceName: rep.ServiceName,
		Title: rep.Title, Eligible: rep.Eligible, OpensAt: rep.OpensAt, ClosesAt: rep.ClosesAt,
		Extensions: rep.Extensions, Anchored: map[string]string{}, Hashes: map[string]string{}, Partial: rep.Partial}
	for name, ts := range rep.Anchored {
		out.Anchored[name] = ts.UTC().Format(time.RFC3339)
	}
	for name, h := range rep.Hashes {
		out.Hashes[name] = hex.EncodeToString(h)
	}
	switch {
	case rep.Results != nil:
		out.Status = "counted"
	case now.Before(time.Unix(rep.ClosesAt, 0).Add(site.CollectMargin)):
		out.Status = "open"
	default:
		out.Status = "closed"
	}
	if r := rep.Results; r != nil {
		out.Results = &results{Tally: r.Tally, Eligible: r.Counts.Eligible, Ballots: r.Counts.Ballots, Removed: r.Counts.Removed,
			Unhandled: r.Counts.Unhandled}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// anchorsFor is the Sigstore trusted material: from a trusted root file,
// or fetched through the instance's TUF repository.
func anchorsFor(instance, rootFile string) (*site.Anchors, error) {
	if rootFile == "" {
		return site.NewAnchors(instance)
	}
	b, err := os.ReadFile(rootFile)
	if err != nil {
		return nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(b)
	if err != nil {
		return nil, err
	}
	return site.NewAnchorsWith(tr), nil
}
