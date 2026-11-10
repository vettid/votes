package rekor

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// Only the allowlist is ever sent; nothing that adds to the log.
func TestClientAllowlist(t *testing.T) {
	ctx := context.Background()
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{}`) })
	for _, req := range [][2]string{
		{http.MethodPost, "/api/v1/log/entries"},
		{http.MethodGet, "/api/v1/log/entries"},
		{http.MethodGet, "/api/v1/index/retrieve"},
		{http.MethodPost, "/api/v1/log"},
		{http.MethodPut, "/api/v1/log/entries/retrieve"},
		{http.MethodGet, "/api/v1/log/publicKey"},
	} {
		var out any
		if err := c.do(ctx, req[0], req[1], nil, map[string]any{}, &out); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s %s: %v", req[0], req[1], err)
		}
	}
	if c.Requests() != 0 {
		t.Fatalf("%d requests sent", c.Requests())
	}
}

// The kinds of failure: no answer is ErrUnavailable; an answer that is
// malformed, too big, without an entry, or another 4xx is ErrBadAnswer
// (not retried); 404, 410 and 501 are ErrGone.
func TestClientErrorKinds(t *testing.T) {
	ctx := context.Background()
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); io.WriteString(w, body) }
	}
	cases := []struct {
		name string
		h    http.HandlerFunc
		want error
		n    int
		call func(c *Client) error
	}{
		{"503", answer(503, ""), ErrUnavailable, 5, nil},
		{"429", answer(429, ""), ErrUnavailable, 5, nil},
		{"501", answer(501, ""), ErrGone, 1, nil},
		{"404", answer(404, ""), ErrGone, 1, nil},
		{"400", answer(400, ""), ErrBadAnswer, 1, nil},
		{"malformed 200", answer(200, "{"), ErrBadAnswer, 1, nil},
		{"too big", answer(200, `"`+strings.Repeat("a", maxBody)+`"`), ErrBadAnswer, 1, nil},
		{"too big, valid once cut", answer(200, `{}`+strings.Repeat(" ", maxBody)), ErrBadAnswer, 1, nil},
		{"entry without content", answer(200, `[{"ab":null}]`), ErrBadAnswer, 1, func(c *Client) error { _, err := c.Entries(ctx, []string{"ab"}); return err }},
	}
	for _, tc := range cases {
		c, _ := testClient(t, tc.h)
		c.Gap = time.Nanosecond
		call := tc.call
		if call == nil {
			call = func(c *Client) error { _, err := c.LogInfo(ctx); return err }
		}
		if err := call(c); !errors.Is(err, tc.want) || c.Requests() != tc.n {
			t.Errorf("%s: %v, %d requests", tc.name, err, c.Requests())
		}
		if errors.Is(tc.want, ErrUnavailable) {
			continue
		}
		if err := call(c); errors.Is(err, ErrUnavailable) {
			t.Errorf("%s counted as unavailable", tc.name)
		}
	}
	// A network error: no answer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c := &Client{Base: srv.URL, HTTP: srv.Client(), Now: clk.now, Sleep: clk.sleep, Gap: time.Nanosecond}
	if _, err := c.LogInfo(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("network error: %v", err)
	}
	// A cancelled context: nothing sent.
	c2, _ := testClient(t, answer(200, `{}`))
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c2.LogInfo(cctx); !errors.Is(err, context.Canceled) || c2.Requests() != 0 {
		t.Errorf("cancelled: %v, %d requests", err, c2.Requests())
	}
}

// Retry-After is taken up to MaxRetryAfter.
func TestClientRetryAfterCap(t *testing.T) {
	n := 0
	c, clk := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "86400")
			w.WriteHeader(429)
			return
		}
		io.WriteString(w, `{}`)
	})
	c.Gap = time.Nanosecond
	if _, err := c.LogInfo(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, d := range clk.slept {
		if d > MaxRetryAfter {
			t.Fatalf("paused %v", d)
		}
	}
	if clk.slept[0] != MaxRetryAfter {
		t.Errorf("pauses %v", clk.slept)
	}
}

// Callers in several goroutines still send one request at a time, Gap
// apart.
func TestClientOneAtATime(t *testing.T) {
	var inFlight, most atomic.Int32
	c, clk := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		io.WriteString(w, `{}`)
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.LogInfo(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most.Load() != 1 || c.Requests() != 8 {
		t.Fatalf("%d at once, %d requests", most.Load(), c.Requests())
	}
	gaps := 0
	for _, d := range clk.slept {
		if d == Gap {
			gaps++
		}
	}
	if gaps != 7 {
		t.Errorf("pauses %v", clk.slept)
	}
}

// A checkpoint signed by a test log at host: verified, with its tree ID;
// an origin naming another host, or no numeric tree ID, is
// ErrInconsistent; a signature by a key the hint doesn't name, or by a
// log at another host, is ErrUnverified.
func TestCheckpointOrigin(t *testing.T) {
	k := testKey("votes rekor test log")
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	id := sha256.Sum256(spki)
	signer, err := signature.LoadECDSASignerVerifier(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	logs := Logs{hex.EncodeToString(id[:]): {BaseURL: "https://" + host, PublicKey: &k.PublicKey, HashFunc: crypto.SHA256,
		ValidityPeriodStart: time.Unix(0, 0), ID: id[:]}}
	sign := func(origin string, size uint64) string {
		sc, err := util.CreateSignedCheckpoint(util.Checkpoint{Origin: origin, Size: size, Hash: make([]byte, 32)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sc.Sign(host, signer, options.WithContext(context.Background())); err != nil {
			t.Fatal(err)
		}
		b, err := sc.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cp, err := VerifyCheckpoint(sign(host+" - 42", 7), host, logs, at)
	if err != nil || cp.TreeID != "42" || cp.Size != 7 {
		t.Fatalf("%+v %v", cp, err)
	}
	for _, origin := range []string{"rekor.example - 42", host + " - x", host + " - ", host} {
		if _, err := VerifyCheckpoint(sign(origin, 7), host, logs, at); !errors.Is(err, ErrInconsistent) {
			t.Errorf("origin %q: %v", origin, err)
		}
	}
	short, err := util.CreateSignedCheckpoint(util.Checkpoint{Origin: host + " - 42", Size: 7, Hash: make([]byte, 31)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := short.Sign(host, signer, options.WithContext(context.Background())); err != nil {
		t.Fatal(err)
	}
	sb, _ := short.MarshalText()
	if _, err := VerifyCheckpoint(string(sb), host, logs, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("a 31-byte root: %v", err)
	}
	other := testKey("another log")
	ospki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	oid := sha256.Sum256(ospki)
	wrongHint := Logs{hex.EncodeToString(oid[:]): {BaseURL: "https://" + host, PublicKey: &k.PublicKey, HashFunc: crypto.SHA256,
		ValidityPeriodStart: time.Unix(0, 0), ID: oid[:]}}
	if _, err := VerifyCheckpoint(sign(host+" - 42", 7), host, wrongHint, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("a key the hint doesn't name: %v", err)
	}
	if _, err := VerifyCheckpoint(sign(host+" - 42", 7), "rekor.example", logs, at); !errors.Is(err, ErrUnverified) {
		t.Errorf("a log at another host: %v", err)
	}
}

// A redirect is not followed: a bad answer.
func TestClientNoRedirect(t *testing.T) {
	hits := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/api/v1/log/entries", http.StatusTemporaryRedirect)
	})
	if _, err := c.SearchKey(context.Background(), []byte("pem")); !errors.Is(err, ErrBadAnswer) || hits != 1 {
		t.Fatalf("%v, %d requests", err, hits)
	}
}

// An attempt that hangs past its timeout got no answer: retried, then
// ErrUnavailable. The run's own deadline, or a cancel, during an attempt
// is the context's error, not the log's silence.
func TestClientAttemptTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	c.Gap, c.Attempt = time.Nanosecond, 20*time.Millisecond
	if _, err := c.LogInfo(context.Background()); !errors.Is(err, ErrUnavailable) || c.Requests() != 5 {
		t.Fatalf("hanging: %v, %d requests", err, c.Requests())
	}
	c2, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	c2.Gap, c2.Attempt = time.Nanosecond, time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c2.LogInfo(ctx); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("deadline during an attempt: %v", err)
	}
}

// A 200 without the answer's content is a bad answer: a proof without
// hashes, a search answering null.
func TestClientMissingContent(t *testing.T) {
	ctx := context.Background()
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/log/proof" {
			io.WriteString(w, `{"rootHash":"00"}`)
			return
		}
		io.WriteString(w, `null`)
	})
	c.Gap = time.Nanosecond
	if _, err := c.ConsistencyProof(ctx, 1, 2, ""); !errors.Is(err, ErrBadAnswer) {
		t.Errorf("proof without hashes: %v", err)
	}
	if _, err := c.SearchKey(ctx, []byte("pem")); !errors.Is(err, ErrBadAnswer) {
		t.Errorf("null search: %v", err)
	}
}

// The run's deadline during the last attempt, after four answers of 503:
// the context's error, not "no answer".
func TestClientDeadlineLastAttempt(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var n atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 5 {
			w.WriteHeader(503)
			return
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	c.Gap, c.Attempt = time.Nanosecond, time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.LogInfo(ctx); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUnavailable) || n.Load() != 5 {
		t.Fatalf("%v after %d attempts", err, n.Load())
	}
}
