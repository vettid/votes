package main

import (
	"crypto/ed25519"
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
	compiledKeyARN         string // the anchor key's own ARN: the alias must resolve to it
	compiledKeySPKISHA256  string // hex SHA-256 of the anchor key's public key (DER SPKI)
	compiledClaimsTable    string
	compiledTrailName      string // the signer account's trail
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
	compiledSiteKey        string // the votes site's public key (base64 Ed25519): services.json's signer
	compiledOwnLogGroup    string // the reconciler's own log group: where a run finds the last complete one
)

type cfg struct {
	region, keyAlias, keyARN, keySPKISHA256, claimsTable, trailName           string
	journalGroup, journalStream, trailGroup, bucket, instance, function, role string
	codeSha256, policy, ownLogGroup                                           string
	partition, account                                                        string // the signer role's
	siteKey                                                                   []byte
	acks                                                                      []reconcile.Acknowledgement
}

var (
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	roleARN   = regexp.MustCompile(`^arn:(aws[a-z-]*):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)
	sha256B64 = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	logGroup  = regexp.MustCompile(`^/aws/lambda/[A-Za-z0-9_-]{1,64}$`)
	requestID = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
)

// compiled checks the compiled configuration: every value present and
// well formed, or the function doesn't start.
func compiled() (*cfg, error) {
	c := &cfg{region: compiledRegion, keyAlias: compiledKeyAlias, keyARN: compiledKeyARN, keySPKISHA256: compiledKeySPKISHA256,
		claimsTable: compiledClaimsTable, trailName: compiledTrailName, journalGroup: compiledJournalGroup, journalStream: compiledJournalStream,
		trailGroup: compiledTrailGroup, bucket: compiledVotesBucket, instance: compiledSigstore, function: compiledSignerFunction,
		role: compiledSignerRole, codeSha256: compiledCodeSha256, ownLogGroup: compiledOwnLogGroup}
	for name, v := range map[string]string{"region": c.region, "key alias": c.keyAlias, "key ARN": c.keyARN,
		"key SPKI SHA-256": c.keySPKISHA256, "claims table": c.claimsTable, "trail name": c.trailName, "journal group": c.journalGroup,
		"journal stream": c.journalStream, "trail group": c.trailGroup, "votes bucket": c.bucket, "sigstore": c.instance,
		"signer function": c.function, "signer role": c.role, "code SHA-256": c.codeSha256, "policy": compiledPolicy,
		"acknowledged": compiledAcknowledged, "site key": compiledSiteKey, "own log group": c.ownLogGroup} {
		if v == "" {
			return nil, fmt.Errorf("the build left the %s empty (scripts/build-reconciler.sh)", name)
		}
	}
	switch {
	case !strings.HasPrefix(c.keyAlias, "arn:aws") || !strings.Contains(c.keyAlias, ":alias/"):
		return nil, errors.New("the key must be compiled as its alias ARN")
	case !strings.HasPrefix(c.keyARN, "arn:aws") || !strings.Contains(c.keyARN, ":key/"):
		return nil, errors.New("the key's own ARN must be compiled too")
	case !hexSHA256.MatchString(c.keySPKISHA256):
		return nil, errors.New("the key's SPKI SHA-256 must be 64 lowercase hex digits")
	case c.instance != anchor.Staging && c.instance != anchor.Production:
		return nil, errors.New("sigstore must be staging or production")
	case !roleARN.MatchString(c.role):
		return nil, errors.New("the signer role must be a role ARN")
	case !sha256B64.MatchString(c.codeSha256):
		return nil, errors.New("the code SHA-256 must be base64, as Lambda reports CodeSha256")
	case !logGroup.MatchString(c.ownLogGroup):
		return nil, errors.New("the own log group must be a Lambda function's (/aws/lambda/<name>)")
	}
	m := roleARN.FindStringSubmatch(c.role)
	c.partition, c.account = m[1], m[2]
	key, err := base64.StdEncoding.Strict().DecodeString(compiledSiteKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("the site key must be base64 of an Ed25519 public key (32 bytes)")
	}
	c.siteKey = key
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
// array of acknowledgements, each with its rule, slot, digest, r (if
// any), reason, and the KMS request id or the signature hash of the one
// Sign or bundle it excuses (at least one), and nothing else. An
// acknowledgement that names neither would excuse every finding of its
// slot and digest, so there is none.
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
	hexR := regexp.MustCompile(`^([0-9a-f]{2}){1,33}$`)
	for i, a := range acks {
		if a.Rule == "" || a.Reason == "" || !strings.Contains(a.Slot, "/") || !hexSHA256.MatchString(a.Digest) || (a.R != "" && !hexR.MatchString(a.R)) {
			return nil, fmt.Errorf("acknowledged signs: entry %d needs a rule, a slot, a hex SHA-256 digest, a hex r if any, and a reason", i)
		}
		if (a.RequestID == "" && a.SigSHA256 == "") || (a.RequestID != "" && !requestID.MatchString(a.RequestID)) ||
			(a.SigSHA256 != "" && !hexSHA256.MatchString(a.SigSHA256)) {
			return nil, fmt.Errorf("acknowledged signs: entry %d must name the one Sign or bundle it excuses: its kms_request_id, or its sig_sha256", i)
		}
	}
	return acks, nil
}

// log writes the compiled configuration at start (all of it public).
func (c *cfg) log(log *slog.Logger) {
	log.Info("compiled configuration", "region", c.region, "key_alias", c.keyAlias, "key_arn", c.keyARN, "key_spki_sha256", c.keySPKISHA256,
		"claims_table", c.claimsTable, "trail", c.trailName, "journal_group", c.journalGroup,
		"journal_stream", c.journalStream, "trail_group", c.trailGroup, "votes_bucket", c.bucket, "sigstore", c.instance,
		"signer_function", c.function, "signer_role", c.role, "code_sha256", c.codeSha256, "acknowledged", len(c.acks),
		"site_key", base64.StdEncoding.EncodeToString(c.siteKey), "own_log_group", c.ownLogGroup)
}
