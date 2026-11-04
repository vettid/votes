package site

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tuffetcher "github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// The Sigstore trusted roots, embedded so that a start doesn't depend on
// the TUF repository being reachable, and refreshed through it
// (docs/VOTES-SITE.md §4 item 4). roots/embedded_at is when
// they were fetched; refresh them with `go generate ./site`.
//
//go:generate go run ./internal/rootgen -out roots
//go:embed roots/production.json roots/staging.json roots/embedded_at
var embeddedRoots embed.FS

// Bounds of the trusted root's refresh.
const (
	// RootRefresh: the TUF repository is asked at most this often.
	RootRefresh = 24 * time.Hour
	// MaxEmbeddedAge: a start whose TUF fetch fails proceeds on the
	// embedded root only if it is at most this old.
	MaxEmbeddedAge = 90 * 24 * time.Hour
	// RootFetchTimeout bounds a whole TUF fetch, well inside the upload
	// function's timeout: a slow repository costs a request this long, at
	// most once per RootRefresh.
	RootFetchTimeout = 5 * time.Second
)

// EmbeddedRoot is the instance's embedded trusted root (its JSON) and
// when it was embedded.
func EmbeddedRoot(instance string) ([]byte, time.Time, error) {
	if instance != Production && instance != Staging {
		return nil, time.Time{}, fmt.Errorf("site: unknown Sigstore instance %q", instance)
	}
	b, err := embeddedRoots.ReadFile("roots/" + instance + ".json")
	if err != nil {
		return nil, time.Time{}, err
	}
	at, err := embeddedRoots.ReadFile("roots/embedded_at")
	if err != nil {
		return nil, time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(at)))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("site: roots/embedded_at: %w", err)
	}
	return b, t, nil
}

// FetchRootJSON fetches the instance's trusted root through its TUF
// repository, with no local cache (Lambda's file system is read-only),
// giving up after RootFetchTimeout.
func FetchRootJSON(instance string) ([]byte, error) {
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() { b, err := fetchRootJSON(instance); done <- result{b, err} }()
	select {
	case r := <-done:
		return r.b, r.err
	case <-time.After(RootFetchTimeout):
		return nil, fmt.Errorf("site: TUF: no answer in %s", RootFetchTimeout)
	}
}

func fetchRootJSON(instance string) ([]byte, error) {
	opts := tuf.DefaultOptions().WithDisableLocalCache()
	switch instance {
	case Production:
	case Staging:
		opts.Root, opts.RepositoryBaseURL = tuf.StagingRoot(), tuf.StagingMirror
	default:
		return nil, fmt.Errorf("site: unknown Sigstore instance %q", instance)
	}
	f := tuffetcher.NewDefaultFetcher().NewFetcherWithHTTPClient(&http.Client{Timeout: RootFetchTimeout})
	f.SetRetry(time.Second, 1) // one try: the default with a custom client is 15 minutes of retries
	opts.Fetcher = f
	c, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("site: TUF: %w", err)
	}
	b, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("site: TUF: %w", err)
	}
	return b, nil
}

// Where an Anchors' trusted root came from.
const (
	RootFromTUF      = "tuf"
	RootFromEmbedded = "embedded"
	RootFromFile     = "file"
)

// refresher keeps a trusted root fresh: fetched through TUF at most once
// per RootRefresh, keeping the one it has when a fetch fails.
type refresher struct {
	mu      sync.Mutex
	current root.TrustedMaterial
	source  string
	tried   time.Time
	fetch   func() (root.TrustedMaterial, error)
	now     func() time.Time
}

// newRefresher starts on a fetched root, or on the embedded one (made
// at embeddedAt) if the fetch fails and it is at most MaxEmbeddedAge old.
func newRefresher(embedded []byte, embeddedAt time.Time, fetch func() (root.TrustedMaterial, error), now func() time.Time) (*refresher, error) {
	r := &refresher{fetch: fetch, now: now, tried: now()}
	tr, err := fetch()
	if err == nil {
		r.current, r.source = tr, RootFromTUF
		return r, nil
	}
	if age := now().Sub(embeddedAt); age > MaxEmbeddedAge {
		return nil, fmt.Errorf("site: trusted root: the TUF fetch failed (%v) and the embedded root, of %s, is over %d days old: refresh it (go generate ./site)",
			err, embeddedAt.UTC().Format(time.DateOnly), int(MaxEmbeddedAge/(24*time.Hour)))
	}
	if r.current, err = root.NewTrustedRootFromJSON(embedded); err != nil {
		return nil, fmt.Errorf("site: the embedded trusted root: %w", err)
	}
	r.source = RootFromEmbedded
	return r, nil
}

// material is the root in use. A refresh that is due is claimed under
// the lock (tried is set first, so one caller fetches) and fetched
// outside it: a slow TUF repository holds up only the caller that
// fetches, while the others go on with the root they have.
func (r *refresher) material() root.TrustedMaterial {
	r.mu.Lock()
	cur := r.current
	due := r.now().Sub(r.tried) >= RootRefresh
	if due {
		r.tried = r.now()
	}
	r.mu.Unlock()
	if !due {
		return cur
	}
	tr, err := r.fetch()
	if err != nil {
		return cur
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current, r.source = tr, RootFromTUF
	return r.current
}

func (r *refresher) from() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.source
}
