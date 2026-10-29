// Package lambdahttp runs a net/http Handler on AWS Lambda's custom
// runtime (provided.al2023) behind an API Gateway HTTP API (payload format
// 2.0), with the standard library only: it takes each invocation from the
// runtime API, turns the event into a request, and posts the response.
package lambdahttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// event is an API Gateway HTTP API event (payload format 2.0), the parts
// used.
type event struct {
	RawPath         string            `json:"rawPath"`
	RawQueryString  string            `json:"rawQueryString"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
	RequestContext  struct {
		HTTP struct {
			Method string `json:"method"`
		} `json:"http"`
	} `json:"requestContext"`
}

// response is the 2.0 format's answer.
type response struct {
	StatusCode      int               `json:"statusCode"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
}

const apiVersion = "/2018-06-01/runtime/invocation/"

// Serve runs h for every invocation until ctx ends or the runtime API
// fails. api is the AWS_LAMBDA_RUNTIME_API host:port.
func Serve(ctx context.Context, api string, h http.Handler) error {
	c := &http.Client{} // the next-invocation call long-polls: no timeout
	base := "http://" + api + apiVersion
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"next", nil)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("lambdahttp: next: %w", err)
		}
		payload, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		id := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")
		if id == "" {
			return errors.New("lambdahttp: an invocation without an id")
		}
		deadline := time.Now().Add(30 * time.Second)
		if ms, err := parseMS(resp.Header.Get("Lambda-Runtime-Deadline-Ms")); err == nil {
			deadline = ms
		}
		out, err := invoke(ctx, h, payload, deadline)
		path := base + id + "/response"
		if err != nil {
			path, out = base+id+"/error", []byte(`{"errorMessage":"bad event","errorType":"BadEvent"}`)
		}
		post, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(out))
		if err != nil {
			return err
		}
		pr, err := c.Do(post)
		if err != nil {
			return fmt.Errorf("lambdahttp: respond: %w", err)
		}
		pr.Body.Close()
		if pr.StatusCode/100 != 2 {
			// The runtime refused the response (one over Lambda's size
			// limit, for one): say so in place of it.
			ep, err := http.NewRequestWithContext(ctx, http.MethodPost, base+id+"/error",
				strings.NewReader(`{"errorMessage":"response refused","errorType":"ResponseRefused"}`))
			if err != nil {
				return err
			}
			if er, err := c.Do(ep); err == nil {
				er.Body.Close()
			}
		}
	}
	return ctx.Err()
}

func parseMS(s string) (time.Time, error) {
	var ms int64
	if _, err := fmt.Sscanf(s, "%d", &ms); err != nil || ms <= 0 {
		return time.Time{}, errors.New("no deadline")
	}
	return time.UnixMilli(ms), nil
}

// invoke runs one event through h, within the invocation's deadline.
func invoke(ctx context.Context, h http.Handler, payload []byte, deadline time.Time) ([]byte, error) {
	var ev event
	if err := json.Unmarshal(payload, &ev); err != nil || ev.RequestContext.HTTP.Method == "" || !strings.HasPrefix(ev.RawPath, "/") {
		return nil, errors.New("lambdahttp: not an HTTP API event")
	}
	body := []byte(ev.Body)
	if ev.IsBase64Encoded {
		b, err := base64.StdEncoding.DecodeString(ev.Body)
		if err != nil {
			return nil, err
		}
		body = b
	}
	// A second before Lambda's deadline, so that an answer still goes out.
	ctx, cancel := context.WithDeadline(ctx, deadline.Add(-time.Second))
	defer cancel()
	target := ev.RawPath
	if ev.RawQueryString != "" {
		target += "?" + ev.RawQueryString
	}
	req, err := http.NewRequestWithContext(ctx, ev.RequestContext.HTTP.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range ev.Headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if err := serve(h, rec, req); err != nil {
		rec = httptest.NewRecorder()
		rec.WriteHeader(http.StatusInternalServerError)
	}
	res := response{StatusCode: rec.Code, Headers: map[string]string{}, Body: base64.StdEncoding.EncodeToString(rec.Body.Bytes()), IsBase64Encoded: true}
	for k, v := range rec.Header() {
		res.Headers[k] = strings.Join(v, ", ")
	}
	return json.Marshal(res)
}

// serve runs h, turning a panic into an error: one bad request must not
// end the runtime process.
func serve(h http.Handler, w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("lambdahttp: panic: %v", p)
		}
	}()
	h.ServeHTTP(w, r)
	return nil
}
