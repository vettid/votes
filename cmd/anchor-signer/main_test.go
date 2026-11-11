package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

var (
	b64Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	b64IK  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
)

// setCompiled sets the build constants for a test, and restores them.
func setCompiled(t *testing.T, over map[string]string) {
	t.Helper()
	vars := map[string]*string{"region": &compiledRegion, "alias": &compiledKeyAlias, "table": &compiledClaimsTable,
		"group": &compiledJournalGroup, "stream": &compiledJournalStream, "bucket": &compiledVotesBucket,
		"api": &compiledVotesAPI, "sigstore": &compiledSigstore, "sitekey": &compiledSiteKey, "iks": &compiledServiceIKs}
	good := map[string]string{"region": "us-east-1", "alias": "arn:aws:kms:us-east-1:111122223333:alias/vettid-anchor",
		"table": "claims", "group": "/vettid/anchor-journal", "stream": "signs", "bucket": "votes-staging",
		"api": "https://votes.example.org", "sigstore": "staging", "sitekey": b64Key, "iks": b64IK}
	old := map[string]string{}
	for k, p := range vars {
		old[k] = *p
		v := good[k]
		if o, ok := over[k]; ok {
			v = o
		}
		*p = v
	}
	t.Cleanup(func() {
		for k, p := range vars {
			*p = old[k]
		}
	})
}

func TestCompiled(t *testing.T) {
	setCompiled(t, nil)
	c, err := compiled()
	if err != nil || len(c.serviceIKs) != 1 || len(c.siteKey) != 32 {
		t.Fatalf("%+v %v", c, err)
	}
	for k, bad := range map[string]string{"region": "", "alias": "arn:aws:kms:us-east-1:111122223333:key/1234",
		"api": "https://votes.example.org/api", "sigstore": "other", "sitekey": "AAAA", "iks": b64IK + ",AAAA", "table": ""} {
		setCompiled(t, map[string]string{k: bad})
		if _, err := compiled(); err == nil {
			t.Errorf("%s=%q taken", k, bad)
		}
	}
}

func TestCheckEnv(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ok := []string{"AWS_REGION=us-east-1", "PATH=/usr/bin", "LANG=C", "AWS_LAMBDA_LOG_FORMAT=JSON", "AWS_SESSION_TOKEN=x"}
	if err := checkEnv(ok, log); err != nil || logs.Len() != 0 {
		t.Fatalf("%v %s", err, logs.String())
	}
	for _, bad := range []string{"AWS_ENDPOINT_URL=x", "AWS_ENDPOINT_URL_KMS=x", "https_proxy=x", "HTTPS_PROXY=x",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=x", "SSL_CERT_FILE=x", "GODEBUG=x", "LD_PRELOAD=x", "AWS_LAMBDA_EXEC_WRAPPER=x",
		"AWS_PROFILE=x", "AWS_CA_BUNDLE=x", "AWS_MAX_ATTEMPTS=9"} {
		if err := checkEnv(append(ok, bad), log); err == nil {
			t.Errorf("%s taken", bad)
		}
	}
	logs.Reset()
	if err := checkEnv(append(ok, "SOMETHING_NEW=secret-value"), log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "SOMETHING_NEW") || strings.Contains(logs.String(), "secret-value") {
		t.Fatalf("the notice: %s", logs.String())
	}
}

func TestKeyListed(t *testing.T) {
	ik := bytes.Repeat([]byte{8}, 32)
	spki := []byte("spki")
	l := &site.ServiceList{Services: []site.Service{{IKs: [][]byte{ik}, AnchorKeys: []site.AnchorKey{{Key: spki}}}}}
	if err := keyListed(l, [][]byte{ik}, spki); err != nil {
		t.Fatal(err)
	}
	if err := keyListed(l, [][]byte{ik}, []byte("other")); err == nil {
		t.Fatal("an unlisted key taken")
	}
	if err := keyListed(l, [][]byte{bytes.Repeat([]byte{9}, 32)}, spki); err == nil {
		t.Fatal("an unlisted service taken")
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
