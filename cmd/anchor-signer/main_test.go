package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vettid/votes/signer"
)

func TestReadEnv(t *testing.T) {
	good := map[string]string{"SIGNER_KEY_ID": "k", "SIGNER_CLAIMS_TABLE": "c", "SIGNER_JOURNAL_GROUP": "g",
		"SIGNER_JOURNAL_STREAM": "s", "VOTES_BUCKET": "b", "VOTES_API": "https://votes.example/", "VOTES_SIGSTORE": "staging",
		"VOTES_SITE_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	e, err := readEnv(func(k string) string { return good[k] })
	if err != nil || e.api != "https://votes.example" {
		t.Fatalf("%+v %v", e, err)
	}
	for k, bad := range map[string]string{"SIGNER_KEY_ID": "", "VOTES_API": "http://votes.example", "VOTES_SIGSTORE": "other",
		"VOTES_SITE_KEY": "AAAA"} {
		env := map[string]string{}
		for kk, v := range good {
			env[kk] = v
		}
		env[k] = bad
		if _, err := readEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s=%q taken", k, bad)
		}
	}
}

// An event that isn't a request is answered bad_request, before anything.
func TestHandleStrict(t *testing.T) {
	for _, ev := range []string{`{"proposal_id":"p","name":"proposal","doc":"AA==","sig":"AA==","extra":1}`, `[]`, `{} {}`} {
		out, err := handle(context.Background(), &signer.Signer{}, []byte(ev))
		var r signer.Result
		if err != nil || json.Unmarshal(out, &r) != nil || r.Code != signer.CodeBadRequest {
			t.Fatalf("%s: %s %v", ev, out, err)
		}
	}
}
