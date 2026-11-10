// Package rekor reads Rekor v1 (rekor.sigstore.dev, rekor.sigstage.dev)
// for votesctl check -rekor (docs/VOTES-SITE.md §7, "The Rekor check"):
// the log's signed checkpoint, consistency proofs, the deprecated search
// by public key, and entries by entry ID or log index, each verified
// before it is used. It only reads: an allowlist of four endpoints, none
// of which adds to the log.
package rekor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pacing (VOTES-SITE §7, "Pacing"): Rekor's rate limits are undocumented.
const (
	// Gap is the least time between two requests.
	Gap = 250 * time.Millisecond
	// MaxRequests is the most requests a run makes of one instance.
	MaxRequests = 1000
	// MaxBatch is the most entries one entries/retrieve request names.
	MaxBatch = 10
	// MaxRetryAfter bounds a Retry-After pause (chosen; not in the spec).
	MaxRetryAfter = 60 * time.Second
	// AttemptTimeout bounds one attempt (chosen; not in the spec): one
	// that takes longer got no answer, and is retried.
	AttemptTimeout = 30 * time.Second
	// maxBody bounds an answer read.
	maxBody = 16 << 20
)

// retries are the pauses before each retry of a request that got no
// answer: a network error, a 429 or a 5xx.
var retries = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}

// allowed is every request the client may send: method and path. Nothing
// else is sent; in particular not POST /api/v1/log/entries, which adds an
// entry to the log.
var allowed = map[string]string{
	"/api/v1/log":                  http.MethodGet,
	"/api/v1/log/proof":            http.MethodGet,
	"/api/v1/index/retrieve":       http.MethodPost,
	"/api/v1/log/entries/retrieve": http.MethodPost,
}

// The kinds of failure (VOTES-SITE §7, "Two kinds of failure").
var (
	// ErrUnavailable: no answer, after the retries (a network error, a 429
	// or a 5xx). Only this counts toward "Rekor unavailable".
	ErrUnavailable = errors.New("rekor: no answer")
	// ErrBadAnswer: an answer that arrived but is malformed, or another
	// 4xx: a mismatch at once.
	ErrBadAnswer = errors.New("rekor: a bad answer")
	// ErrGone: a 404, 410 or 501 from an endpoint the check needs (the
	// search, in Rekor v2): a mismatch at once, not retried.
	ErrGone = errors.New("rekor: the endpoint is gone")
	// ErrCap: a request past MaxRequests; the run stops there.
	ErrCap = errors.New("rekor: the run's request cap is reached")
	// ErrNotAllowed: a request outside the allowlist; never sent.
	ErrNotAllowed = errors.New("rekor: a request the check never makes")
)

// StatusError is an HTTP answer the client didn't take: errors.Is it
// with ErrUnavailable (429, 5xx), ErrGone (404, 410, 501) or ErrBadAnswer
// (another status).
type StatusError struct {
	Path   string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("rekor: %s answered %d", e.Path, e.Status) }

// Unwrap gives the kind of failure.
func (e *StatusError) Unwrap() error {
	switch {
	case e.Status == http.StatusTooManyRequests || e.Status >= 500 && e.Status != http.StatusNotImplemented:
		return ErrUnavailable
	case e.Status == http.StatusNotFound || e.Status == http.StatusGone || e.Status == http.StatusNotImplemented:
		return ErrGone
	}
	return ErrBadAnswer
}

// Client reads one Rekor v1 instance, one request at a time, paced and
// capped. It is safe for concurrent use; requests are still sent one at
// a time.
type Client struct {
	// Base is the instance's URL, e.g. https://rekor.sigstage.dev.
	Base string
	HTTP *http.Client
	// Gap, Max and Attempt override the pacing and the attempt timeout
	// (tests); zero takes the defaults.
	Gap     time.Duration
	Max     int
	Attempt time.Duration
	// Now and Sleep are the clock (tests).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	// mu is held for a whole request, retries included: one at a time.
	mu   sync.Mutex
	last time.Time
	n    int
}

// Requests reports how many requests the client has sent.
func (c *Client) Requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// slot waits for the pacing gap and takes one request of the cap (c.mu
// held).
func (c *Client) slot(ctx context.Context) error {
	gap, limit := c.Gap, c.Max
	if gap == 0 {
		gap = Gap
	}
	if limit == 0 {
		limit = MaxRequests
	}
	if c.n >= limit {
		return ErrCap
	}
	if !c.last.IsZero() {
		if err := c.sleep(ctx, gap-c.now().Sub(c.last)); err != nil {
			return err
		}
	} else if err := ctx.Err(); err != nil {
		return err
	}
	c.n++
	c.last = c.now()
	return nil
}

// do sends one request (body as JSON if non-nil) and decodes a 200's JSON
// into out, retrying an attempt that got no answer. A cancelled ctx ends
// it with ctx's error, which is none of the kinds of failure: the run is
// stopping.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if allowed[path] != method {
		return fmt.Errorf("%w: %s %s", ErrNotAllowed, method, path)
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	hc := http.DefaultClient
	if c.HTTP != nil {
		hc = c.HTTP
	}
	// No redirect is followed: a 3xx is a bad answer (it could send an
	// allowlisted request elsewhere).
	noRedirect := *hc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc = &noRedirect
	target := strings.TrimSuffix(c.Base, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := c.slot(ctx); err != nil {
			return err
		}
		timeout := c.Attempt
		if timeout == 0 {
			timeout = AttemptTimeout
		}
		actx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(actx, method, target, bytes.NewReader(payload))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		pause := time.Duration(0)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A network error, or the attempt's timeout: no answer.
			lastErr = fmt.Errorf("%w: %s: %v", ErrUnavailable, path, err)
		} else {
			data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
			resp.Body.Close()
			cancel()
			if rerr != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if resp.StatusCode == http.StatusOK {
				switch {
				case rerr != nil:
					lastErr = fmt.Errorf("%w: %s: %v", ErrUnavailable, path, rerr)
				case len(data) > maxBody:
					return fmt.Errorf("%w: %s: answer over %d bytes", ErrBadAnswer, path, maxBody)
				default:
					if err := json.Unmarshal(data, out); err != nil {
						return fmt.Errorf("%w: %s: %v", ErrBadAnswer, path, err)
					}
					return nil
				}
			} else {
				se := &StatusError{Path: path, Status: resp.StatusCode}
				if !errors.Is(se, ErrUnavailable) {
					return se
				}
				lastErr = se
				// Retry-After in seconds is taken, up to MaxRetryAfter; an
				// HTTP date is ignored (the fixed pauses apply).
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
					pause = min(time.Duration(s)*time.Second, MaxRetryAfter)
				}
			}
		}
		if attempt >= len(retries) {
			// The run's own deadline is not the log's silence.
			if err := ctx.Err(); err != nil {
				return err
			}
			return lastErr
		}
		if err := c.sleep(ctx, max(retries[attempt], pause)); err != nil {
			return err
		}
	}
}

// Shard is one tree of the log: the active one (LogInfo) or an inactive
// one (LogInfo.InactiveShards).
type Shard struct {
	RootHash       string `json:"rootHash"`
	SignedTreeHead string `json:"signedTreeHead"`
	TreeID         string `json:"treeID"`
	TreeSize       int64  `json:"treeSize"`
}

// LogInfo is GET /api/v1/log: the active shard and the inactive ones, in
// the order Rekor gives them.
type LogInfo struct {
	Shard
	InactiveShards []Shard `json:"inactiveShards"`
}

// LogInfo returns the log's state.
func (c *Client) LogInfo(ctx context.Context) (*LogInfo, error) {
	var li LogInfo
	if err := c.do(ctx, http.MethodGet, "/api/v1/log", nil, nil, &li); err != nil {
		return nil, err
	}
	return &li, nil
}

// ConsistencyProof returns the hashes proving the tree of size first
// consistent with the one of size last, in the shard treeID (the active
// shard if empty).
func (c *Client) ConsistencyProof(ctx context.Context, first, last int64, treeID string) ([]string, error) {
	q := url.Values{"firstSize": {strconv.FormatInt(first, 10)}, "lastSize": {strconv.FormatInt(last, 10)}}
	if treeID != "" {
		if _, err := strconv.ParseUint(treeID, 10, 64); err != nil {
			return nil, fmt.Errorf("rekor: tree ID %q isn't a number", treeID)
		}
		q.Set("treeID", treeID)
	}
	var p struct {
		Hashes *[]string `json:"hashes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/log/proof", q, nil, &p); err != nil {
		return nil, err
	}
	if p.Hashes == nil {
		return nil, fmt.Errorf("%w: a consistency proof without hashes", ErrBadAnswer)
	}
	return *p.Hashes, nil
}

// SearchKey returns the entry IDs Rekor's index holds for a public key
// (POST /api/v1/index/retrieve). The index is deprecated, best-effort and
// unsigned (VOTES-SITE §7, "Not guaranteed").
func (c *Client) SearchKey(ctx context.Context, pem []byte) ([]string, error) {
	type key struct {
		Format  string `json:"format"`
		Content []byte `json:"content"`
	}
	var ids *[]string
	if err := c.do(ctx, http.MethodPost, "/api/v1/index/retrieve", nil, map[string]key{"publicKey": {Format: "x509", Content: pem}}, &ids); err != nil {
		return nil, err
	}
	if ids == nil {
		return nil, fmt.Errorf("%w: a search answered null", ErrBadAnswer)
	}
	return *ids, nil
}

// Entry is a Rekor v1 log entry as the API gives it.
type Entry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

// Entries returns the entries with these IDs (at most MaxBatch), by the
// lower-case IDs Rekor returns them under. Rekor's answer is not trusted
// to hold only what was asked: callers match each entry by its verified
// leaf hash (Verified.Leaf) or log index, which the signed entry
// timestamp binds.
func (c *Client) Entries(ctx context.Context, ids []string) (map[string]*Entry, error) {
	if len(ids) == 0 || len(ids) > MaxBatch {
		return nil, fmt.Errorf("rekor: %d entry IDs in one request", len(ids))
	}
	return c.entries(ctx, map[string]any{"entryUUIDs": ids})
}

// EntriesAt returns the entries at these log indexes (at most MaxBatch),
// as Entries.
func (c *Client) EntriesAt(ctx context.Context, indexes []int64) (map[string]*Entry, error) {
	if len(indexes) == 0 || len(indexes) > MaxBatch {
		return nil, fmt.Errorf("rekor: %d log indexes in one request", len(indexes))
	}
	return c.entries(ctx, map[string]any{"logIndexes": indexes})
}

func (c *Client) entries(ctx context.Context, body map[string]any) (map[string]*Entry, error) {
	var answer []map[string]*Entry
	if err := c.do(ctx, http.MethodPost, "/api/v1/log/entries/retrieve", nil, body, &answer); err != nil {
		return nil, err
	}
	out := map[string]*Entry{}
	for _, m := range answer {
		for id, e := range m {
			if e == nil {
				return nil, fmt.Errorf("%w: entry %s without content", ErrBadAnswer, id)
			}
			out[strings.ToLower(id)] = e
		}
	}
	return out, nil
}
