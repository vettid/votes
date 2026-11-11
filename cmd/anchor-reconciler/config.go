package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/votes/reconcile"
)

// The configuration, compiled in per environment by
// scripts/build-reconciler.sh (-ldflags -X), so that the code signature
// covers it: the function reads nothing it trusts from its environment.
var (
	compiledRegion         string // the signer account's region
	compiledKeyAlias       string // the anchor key's alias ARN
	compiledJournalGroup   string
	compiledJournalStream  string
	compiledTrailGroup     string // the trail's log group in the signer account
	compiledVotesBucket    string
	compiledSigstore       string // staging or production
	compiledSignerFunction string // the signer function's name
	compiledSignerRole     string // the signer role's ARN
	compiledCodeSha256     string // the signer release's CodeSha256 (base64, as Lambda reports it)
	compiledPolicy         string // base64 of the signer function's resource policy, as released
	compiledAcknowledged   string // base64 of monitor/acknowledged-signs-<env>.json
)

type cfg struct {
	region, keyAlias, journalGroup, journalStream, trailGroup, bucket, instance, function, role string
	codeSha256, policy                                                                          string
	acks                                                                                        []reconcile.Acknowledgement
}

var (
	roleARN   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	sha256B64 = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// compiled checks the compiled configuration: every value present and
// well formed, or the function doesn't start.
func compiled() (*cfg, error) {
	c := &cfg{region: compiledRegion, keyAlias: compiledKeyAlias, journalGroup: compiledJournalGroup, journalStream: compiledJournalStream,
		trailGroup: compiledTrailGroup, bucket: compiledVotesBucket, instance: compiledSigstore, function: compiledSignerFunction,
		role: compiledSignerRole, codeSha256: compiledCodeSha256}
	for name, v := range map[string]string{"region": c.region, "key alias": c.keyAlias, "journal group": c.journalGroup,
		"journal stream": c.journalStream, "trail group": c.trailGroup, "votes bucket": c.bucket, "sigstore": c.instance,
		"signer function": c.function, "signer role": c.role, "code SHA-256": c.codeSha256, "policy": compiledPolicy,
		"acknowledged": compiledAcknowledged} {
		if v == "" {
			return nil, fmt.Errorf("the build left the %s empty (scripts/build-reconciler.sh)", name)
		}
	}
	switch {
	case !strings.HasPrefix(c.keyAlias, "arn:aws") || !strings.Contains(c.keyAlias, ":alias/"):
		return nil, errors.New("the key must be compiled as its alias ARN")
	case c.instance != anchor.Staging && c.instance != anchor.Production:
		return nil, errors.New("sigstore must be staging or production")
	case !roleARN.MatchString(c.role):
		return nil, errors.New("the signer role must be a role ARN")
	case !sha256B64.MatchString(c.codeSha256):
		return nil, errors.New("the code SHA-256 must be base64, as Lambda reports CodeSha256")
	}
	policy, err := base64.StdEncoding.Strict().DecodeString(compiledPolicy)
	if err != nil || !json.Valid(policy) {
		return nil, errors.New("the policy must be base64 of a JSON policy")
	}
	c.policy = string(policy)
	ackJSON, err := base64.StdEncoding.Strict().DecodeString(compiledAcknowledged)
	if err != nil {
		return nil, errors.New("the acknowledged signs must be base64")
	}
	if c.acks, err = ParseAcknowledged(ackJSON); err != nil {
		return nil, err
	}
	return c, nil
}

// ParseAcknowledged reads monitor/acknowledged-signs-<env>.json: a JSON
// array of acknowledgements, each with its rule, slot, digest and reason,
// and nothing else.
func ParseAcknowledged(b []byte) ([]reconcile.Acknowledgement, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var acks []reconcile.Acknowledgement
	if err := dec.Decode(&acks); err != nil || acks == nil {
		return nil, errors.New("acknowledged signs: not a JSON array of acknowledgements")
	}
	if dec.More() {
		return nil, errors.New("acknowledged signs: something after the array")
	}
	hexDigest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for i, a := range acks {
		if a.Rule == "" || a.Reason == "" || !strings.Contains(a.Slot, "/") || !hexDigest.MatchString(a.Digest) {
			return nil, fmt.Errorf("acknowledged signs: entry %d needs a rule, a slot, a hex SHA-256 digest and a reason", i)
		}
	}
	return acks, nil
}

// log writes the compiled configuration at start (all of it public).
func (c *cfg) log(log *slog.Logger) {
	log.Info("compiled configuration", "region", c.region, "key_alias", c.keyAlias, "journal_group", c.journalGroup,
		"journal_stream", c.journalStream, "trail_group", c.trailGroup, "votes_bucket", c.bucket, "sigstore", c.instance,
		"signer_function", c.function, "signer_role", c.role, "code_sha256", c.codeSha256, "acknowledged", len(c.acks))
}
