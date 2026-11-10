package rekor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock records the pauses the client takes instead of sleeping.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
	return nil
}

func testClient(t *testing.T, h http.HandlerFunc) (*Client, *fakeClock) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	return &Client{Base: srv.URL, HTTP: srv.Client(), Now: clk.now, Sleep: clk.sleep}, clk
}

// Requests go one at a time, at least Gap apart.
func TestClientPacing(t *testing.T) {
	c, clk := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"treeSize":1}`) })
	for range 3 {
		if _, err := c.LogInfo(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(clk.slept) != 2 || clk.slept[0] != Gap || clk.slept[1] != Gap || c.Requests() != 3 {
		t.Fatalf("pauses %v, %d requests", clk.slept, c.Requests())
	}
}

// A 429 or 5xx is retried after 1, 2, 4 and 8 seconds, or Retry-After if
// longer; then it fails. A 404 or 410 is ErrGone at once; another 4xx a
// StatusError at once.
func TestClientRetries(t *testing.T) {
	ctx := context.Background()
	n := 0
	c, clk := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		switch {
		case n == 1:
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		case n == 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			io.WriteString(w, `{"treeSize":5}`)
		}
	})
	c.Gap = time.Nanosecond
	li, err := c.LogInfo(ctx)
	if err != nil || li.TreeSize != 5 || n != 3 {
		t.Fatalf("%v %v %d", li, err, n)
	}
	if len(clk.slept) < 2 || clk.slept[0] != 30*time.Second || clk.slept[len(clk.slept)-1] != 2*time.Second {
		t.Errorf("pauses %v", clk.slept)
	}

	c2, clk2 := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	c2.Gap = time.Nanosecond
	var se *StatusError
	if _, err := c2.LogInfo(ctx); !errors.As(err, &se) || se.Status != 503 || c2.Requests() != 5 {
		t.Fatalf("after the retries: %v, %d requests", err, c2.Requests())
	}
	var waits []time.Duration
	for _, d := range clk2.slept {
		if d >= time.Second {
			waits = append(waits, d)
		}
	}
	if len(waits) != 4 || waits[0] != time.Second || waits[3] != 8*time.Second {
		t.Errorf("retry pauses %v", waits)
	}

	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		c3, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		if _, err := c3.SearchKey(ctx, []byte("pem")); !errors.Is(err, ErrGone) || c3.Requests() != 1 {
			t.Errorf("%d: %v, %d requests", code, err, c3.Requests())
		}
	}
	c4, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	if _, err := c4.LogInfo(ctx); !errors.As(err, &se) || se.Status != 400 || c4.Requests() != 1 {
		t.Errorf("400: %v", err)
	}
}

// At the cap no further request is sent: ErrCap.
func TestClientCap(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	c.Max, c.Gap = 2, time.Nanosecond
	for range 2 {
		if _, err := c.LogInfo(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.LogInfo(context.Background()); !errors.Is(err, ErrCap) || c.Requests() != 2 {
		t.Fatalf("%v, %d requests", err, c.Requests())
	}
}

// The search sends the key as Rekor's API takes it; entries are asked for
// at most MaxBatch at a time, and returned by lower-case ID.
func TestClientRequests(t *testing.T) {
	ctx := context.Background()
	var got []string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			io.WriteString(w, `["AB12"]`)
		case "/api/v1/log/entries/retrieve":
			io.WriteString(w, `[{"AB12":{"body":"e30=","logIndex":7}}]`)
		case "/api/v1/log/proof":
			io.WriteString(w, `{"hashes":["00"]}`)
		}
	})
	c.Gap = time.Nanosecond
	ids, err := c.SearchKey(ctx, []byte("-----BEGIN PUBLIC KEY-----\n"))
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	es, err := c.Entries(ctx, ids)
	if err != nil || es["ab12"] == nil || es["ab12"].LogIndex != 7 {
		t.Fatalf("%v %v", es, err)
	}
	if _, err := c.EntriesAt(ctx, []int64{1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConsistencyProof(ctx, 3, 9, "42"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Entries(ctx, make([]string, MaxBatch+1)); err == nil {
		t.Error("more than MaxBatch entry IDs sent")
	}
	if _, err := c.EntriesAt(ctx, nil); err == nil {
		t.Error("no log indexes sent")
	}
	var search struct {
		PublicKey struct {
			Format  string `json:"format"`
			Content []byte `json:"content"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal([]byte(strings.SplitN(got[0], " ", 3)[2]), &search)
	want := []string{
		`POST /api/v1/log/entries/retrieve {"entryUUIDs":["AB12"]}`,
		`POST /api/v1/log/entries/retrieve {"logIndexes":[1,2]}`,
		`GET /api/v1/log/proof?firstSize=3&lastSize=9&treeID=42 `,
	}
	if search.PublicKey.Format != "x509" || !strings.HasPrefix(string(search.PublicKey.Content), "-----BEGIN") || len(got) != 4 {
		t.Fatalf("search %q", got[0])
	}
	for i, w := range want {
		if got[i+1] != w {
			t.Errorf("request %d: %q, want %q", i+1, got[i+1], w)
		}
	}
}
