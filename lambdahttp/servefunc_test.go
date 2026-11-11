package lambdahttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ServeFunc answers a directly invoked function's events, and reports an
// error or a panic as a function error with its type.
func TestServeFunc(t *testing.T) {
	events := []string{`"ok"`, `"fail"`, `"typed"`, `"panic"`}
	var mu sync.Mutex
	got := map[string][]byte{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/2018-06-01/runtime/invocation/next" {
			b, _ := io.ReadAll(r.Body)
			got[r.URL.Path] = b
			return
		}
		if n == len(events) {
			cancel()
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Lambda-Runtime-Aws-Request-Id", "r"+string(rune('0'+n)))
		_, _ = io.WriteString(w, events[n])
		n++
	}))
	defer srv.Close()
	var deadlineSet bool
	_ = ServeFunc(ctx, strings.TrimPrefix(srv.URL, "http://"), func(ctx context.Context, ev []byte) ([]byte, error) {
		_, deadlineSet = ctx.Deadline()
		switch string(ev) {
		case `"fail"`:
			return nil, errors.New("no luck")
		case `"typed"`:
			return nil, &Failure{Type: "Refused", Message: "why"}
		case `"panic"`:
			panic("boom")
		}
		return []byte(`{"done":true}`), nil
	})
	base := "/2018-06-01/runtime/invocation/"
	if string(got[base+"r0/response"]) != `{"done":true}` || !deadlineSet {
		t.Fatalf("answer %q, deadline %v", got[base+"r0/response"], deadlineSet)
	}
	for id, want := range map[string]string{
		"r1": `{"errorMessage":"no luck","errorType":"Failed"}`,
		"r2": `{"errorMessage":"why","errorType":"Refused"}`,
		"r3": `{"errorMessage":"the function panicked","errorType":"Panic"}`,
	} {
		if string(got[base+id+"/error"]) != want {
			t.Fatalf("%s: %q, want %q", id, got[base+id+"/error"], want)
		}
	}
}
