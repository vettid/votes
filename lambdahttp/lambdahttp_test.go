package lambdahttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A fake runtime API hands out two events, then makes Serve stop.
func TestServe(t *testing.T) {
	events := []string{
		`{"rawPath":"/api/v1/echo","rawQueryString":"x=1","headers":{"content-type":"text/plain"},"body":"aGk=","isBase64Encoded":true,"requestContext":{"http":{"method":"POST"}}}`,
		`{"not":"an event"}`,
		`{"rawPath":"/panic","requestContext":{"http":{"method":"GET"}}}`,
	}
	var mu sync.Mutex
	got := map[string][]byte{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/2018-06-01/runtime/invocation/next":
			if len(events) == 0 {
				cancel()
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Lambda-Runtime-Aws-Request-Id", "req-"+string(rune('a'+len(events))))
			_, _ = io.WriteString(w, events[0])
			events = events[1:]
		default:
			b, _ := io.ReadAll(r.Body)
			got[r.URL.Path] = b
		}
	}))
	defer srv.Close()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panic" {
			panic("boom")
		}
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen", r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+r.Header.Get("Content-Type"))
		w.WriteHeader(201)
		_, _ = w.Write(b)
	})
	_ = Serve(ctx, strings.TrimPrefix(srv.URL, "http://"), h)
	var res response
	if err := json.Unmarshal(got["/2018-06-01/runtime/invocation/req-d/response"], &res); err != nil {
		t.Fatalf("response: %v %v", err, got)
	}
	body, _ := base64.StdEncoding.DecodeString(res.Body)
	if res.StatusCode != 201 || string(body) != "hi" || res.Headers["X-Seen"] != "POST /api/v1/echo?x=1 text/plain" {
		t.Fatalf("response %+v %q", res, body)
	}
	if got["/2018-06-01/runtime/invocation/req-c/error"] == nil {
		t.Fatal("a bad event wasn't reported as an error")
	}
	var pr response
	if err := json.Unmarshal(got["/2018-06-01/runtime/invocation/req-b/response"], &pr); err != nil || pr.StatusCode != 500 {
		t.Fatalf("a panic: %v %+v (the loop must go on and answer 500)", err, pr)
	}
}
