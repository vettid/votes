// Package rekor reads Rekor v1 (rekor.sigstore.dev, rekor.sigstage.dev)
// for votesctl check -rekor (docs/VOTES-SITE.md §7, "The Rekor check"):
// the log's signed checkpoint, consistency proofs, the deprecated search
// by public key, and entries by entry ID or log index, each verified
// before it is used. It only reads: no request it makes adds to the log.
package rekor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	// maxBody bounds an answer read.
	maxBody = 16 << 20
)

// retries are the pauses before each retry of a request that failed with
// a network error, a 429 or a 5xx.
var retries = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}

// Errors a request can end with.
var (
	// ErrCap is a request past MaxRequests: the run stops there.
	ErrCap = errors.New("rekor: the run's request cap is reached")
	// ErrGone is a 404 or 410 from an endpoint the check needs (the
	// search, in Rekor v2): it is not retried.
	ErrGone = errors.New("rekor: the endpoint is gone")
)

// StatusError is an answer other than 200 that is not retried or still
// failed after the retries.
type StatusError struct {
	Path   string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("rekor: %s answered %d", e.Path, e.Status) }

// Client reads one Rekor v1 instance, one request at a time, paced and
// capped.
type Client struct {
	// Base is the instance's URL, e.g. https://rekor.sigstage.dev.
	Base string
	HTTP *http.Client
	// Gap and Max override the pacing (tests); zero takes the defaults.
	Gap time.Duration
	Max int
	// Now and Sleep are the clock (tests).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

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
		return nil
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

// slot waits for the pacing gap and takes one request of the cap.
func (c *Client) slot(ctx context.Context) error {
	gap, max := c.Gap, c.Max
	if gap == 0 {
		gap = Gap
	}
	if max == 0 {
		max = MaxRequests
	}
	c.mu.Lock()
	if c.n >= max {
		c.mu.Unlock()
		return ErrCap
	}
	wait := gap - c.now().Sub(c.last)
	if c.last.IsZero() {
		wait = 0
	}
	c.n++
	c.mu.Unlock()
	if err := c.sleep(ctx, wait); err != nil {
		return err
	}
	c.mu.Lock()
	c.last = c.now()
	c.mu.Unlock()
	return nil
}

// do sends one request (body JSON if non-nil) and decodes a 200's JSON
// into out, retrying a network error, a 429 or a 5xx.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := c.slot(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.Base, "/")+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hc.Do(req)
		retryAfter := time.Duration(0)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("rekor: %s: %w", path, err)
		default:
			data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
			resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusOK:
				if rerr != nil {
					lastErr = fmt.Errorf("rekor: %s: %w", path, rerr)
					break
				}
				if len(data) > maxBody {
					return fmt.Errorf("rekor: %s: answer over %d bytes", path, maxBody)
				}
				if err := json.Unmarshal(data, out); err != nil {
					return fmt.Errorf("rekor: %s: %w", path, err)
				}
				return nil
			case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
				return fmt.Errorf("%w: %s answered %d", ErrGone, path, resp.StatusCode)
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				lastErr = &StatusError{Path: path, Status: resp.StatusCode}
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
					retryAfter = time.Duration(s) * time.Second
				}
			default:
				return &StatusError{Path: path, Status: resp.StatusCode}
			}
		}
		if attempt >= len(retries) {
			return lastErr
		}
		if err := c.sleep(ctx, max(retries[attempt], retryAfter)); err != nil {
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
	if err := c.do(ctx, http.MethodGet, "/api/v1/log", nil, &li); err != nil {
		return nil, err
	}
	return &li, nil
}

// ConsistencyProof returns the hashes proving the tree of size first
// consistent with the one of size last, in the shard treeID (the active
// shard if empty).
func (c *Client) ConsistencyProof(ctx context.Context, first, last int64, treeID string) ([]string, error) {
	q := "/api/v1/log/proof?firstSize=" + strconv.FormatInt(first, 10) + "&lastSize=" + strconv.FormatInt(last, 10)
	if treeID != "" {
		q += "&treeID=" + treeID
	}
	var p struct {
		Hashes   []string `json:"hashes"`
		RootHash string   `json:"rootHash"`
	}
	if err := c.do(ctx, http.MethodGet, q, nil, &p); err != nil {
		return nil, err
	}
	return p.Hashes, nil
}

// SearchKey returns the entry IDs Rekor's index holds for a public key
// (POST /api/v1/index/retrieve). The index is deprecated and best-effort,
// and holds a key as it was submitted (VOTES-SITE §7, "Not guaranteed").
func (c *Client) SearchKey(ctx context.Context, pem []byte) ([]string, error) {
	type key struct {
		Format  string `json:"format"`
		Content []byte `json:"content"`
	}
	var ids []string
	if err := c.do(ctx, http.MethodPost, "/api/v1/index/retrieve", map[string]key{"publicKey": {Format: "x509", Content: pem}}, &ids); err != nil {
		return nil, err
	}
	return ids, nil
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
// IDs Rekor returns them under; one it doesn't hold is absent.
func (c *Client) Entries(ctx context.Context, ids []string) (map[string]*Entry, error) {
	if len(ids) == 0 || len(ids) > MaxBatch {
		return nil, fmt.Errorf("rekor: %d entry IDs in one request", len(ids))
	}
	return c.entries(ctx, map[string]any{"entryUUIDs": ids})
}

// EntriesAt returns the entries at these log indexes (at most MaxBatch).
func (c *Client) EntriesAt(ctx context.Context, indexes []int64) (map[string]*Entry, error) {
	if len(indexes) == 0 || len(indexes) > MaxBatch {
		return nil, fmt.Errorf("rekor: %d log indexes in one request", len(indexes))
	}
	return c.entries(ctx, map[string]any{"logIndexes": indexes})
}

func (c *Client) entries(ctx context.Context, body map[string]any) (map[string]*Entry, error) {
	var answer []map[string]*Entry
	if err := c.do(ctx, http.MethodPost, "/api/v1/log/entries/retrieve", body, &answer); err != nil {
		return nil, err
	}
	out := map[string]*Entry{}
	for _, m := range answer {
		for id, e := range m {
			if e == nil {
				return nil, fmt.Errorf("rekor: entry %s without content", id)
			}
			out[strings.ToLower(id)] = e
		}
	}
	return out, nil
}
