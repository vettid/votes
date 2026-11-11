package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vettid/service-vault/anchor"
)

// The configuration, compiled in per environment by scripts/build-signer.sh
// (-ldflags -X), so that the code signature covers it (GC #7606 §1, #7638
// item 5): the function reads nothing it trusts from its environment.
var (
	compiledRegion        string // the signer account's region
	compiledKeyAlias      string // the anchor key's alias ARN
	compiledClaimsTable   string
	compiledJournalGroup  string
	compiledJournalStream string
	compiledVotesBucket   string
	compiledVotesAPI      string // https://votes.vettid.org, or staging's
	compiledSigstore      string // staging or production
	compiledSiteKey       string // base64 Ed25519: signs the service list
	compiledServiceIKs    string // base64 Ed25519, comma-separated: the services this signer anchors for
)

// cfg is the compiled configuration, checked.
type cfg struct {
	region, keyAlias, table, group, stream, bucket, api, instance string
	siteKey                                                       ed25519.PublicKey
	serviceIKs                                                    [][]byte
}

// compiled checks the compiled configuration: every value present and
// well-formed, or the function doesn't start.
func compiled() (*cfg, error) {
	c := &cfg{region: compiledRegion, keyAlias: compiledKeyAlias, table: compiledClaimsTable, group: compiledJournalGroup,
		stream: compiledJournalStream, bucket: compiledVotesBucket, api: compiledVotesAPI, instance: compiledSigstore}
	for name, v := range map[string]string{"region": c.region, "key alias": c.keyAlias, "claims table": c.table,
		"journal group": c.group, "journal stream": c.stream, "votes bucket": c.bucket, "votes API": c.api,
		"sigstore": c.instance, "site key": compiledSiteKey, "service IKs": compiledServiceIKs} {
		if v == "" {
			return nil, fmt.Errorf("the build left the %s empty (scripts/build-signer.sh)", name)
		}
	}
	switch {
	case !strings.HasPrefix(c.keyAlias, "arn:aws") || !strings.Contains(c.keyAlias, ":alias/"):
		return nil, errors.New("the key must be compiled as its alias ARN")
	case !strings.HasPrefix(c.api, "https://") || strings.Count(c.api, "/") != 2:
		return nil, errors.New("the votes API must be an https:// origin with no path")
	case c.instance != anchor.Staging && c.instance != anchor.Production:
		return nil, errors.New("sigstore must be staging or production")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(compiledSiteKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("the site key must be a base64 Ed25519 public key")
	}
	c.siteKey = key
	for _, s := range strings.Split(compiledServiceIKs, ",") {
		ik, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || len(ik) != ed25519.PublicKeySize {
			return nil, errors.New("each service IK must be a base64 Ed25519 public key")
		}
		c.serviceIKs = append(c.serviceIKs, ik)
	}
	return c, nil
}

// log writes the compiled configuration at start (all of it public).
func (c *cfg) log(log *slog.Logger) {
	iks := make([]string, len(c.serviceIKs))
	for i, ik := range c.serviceIKs {
		iks[i] = base64.StdEncoding.EncodeToString(ik)
	}
	log.Info("compiled configuration", "region", c.region, "key_alias", c.keyAlias, "claims_table", c.table,
		"journal_group", c.group, "journal_stream", c.stream, "votes_bucket", c.bucket, "votes_api", c.api,
		"sigstore", c.instance, "site_key", base64.StdEncoding.EncodeToString(c.siteKey), "service_iks", iks)
}

// deniedEnv are the environment variables that could point the function's
// clients elsewhere or change what runs (GC #7647 item 1): any of them set,
// it refuses to start.
var deniedEnv = []string{
	"AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
	"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
	"AWS_ENABLE_ENDPOINT_DISCOVERY", "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_RETRY_MODE",
	"AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
	"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_MAX_ATTEMPTS",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG", "LD_PRELOAD", "LD_AUDIT", "AWS_LAMBDA_EXEC_WRAPPER",
}

// deniedPrefixes are denied as prefixes.
var deniedPrefixes = []string{"AWS_ENDPOINT_URL_", "AWS_CONTAINER_CREDENTIALS_"}

// knownEnv are Lambda's documented variables for a custom runtime: any
// other name is logged once, as a notice (its name only).
var knownEnv = map[string]bool{
	"AWS_REGION": true, "AWS_DEFAULT_REGION": true, "AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN": true, "AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true,
	"AWS_LAMBDA_FUNCTION_VERSION": true, "AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true,
	"AWS_LAMBDA_LOG_STREAM_NAME": true, "AWS_LAMBDA_RUNTIME_API": true, "AWS_EXECUTION_ENV": true,
	"AWS_XRAY_CONTEXT_MISSING": true, "AWS_XRAY_DAEMON_ADDRESS": true, "_AWS_XRAY_DAEMON_ADDRESS": true,
	"_AWS_XRAY_DAEMON_PORT": true, "_X_AMZN_TRACE_ID": true, "_HANDLER": true, "LAMBDA_TASK_ROOT": true,
	"LAMBDA_RUNTIME_DIR": true, "LANG": true, "PATH": true, "TZ": true, "LD_LIBRARY_PATH": true,
}

// checkEnv refuses a denied variable and notes an unknown one.
func checkEnv(environ []string, log *slog.Logger) error {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		for _, d := range deniedEnv {
			if name == d {
				return fmt.Errorf("refusing to start: %s is set", name)
			}
		}
		for _, p := range deniedPrefixes {
			if strings.HasPrefix(name, p) {
				return fmt.Errorf("refusing to start: %s is set", name)
			}
		}
		if !knownEnv[name] && !strings.HasPrefix(name, "AWS_LAMBDA_LOG_") {
			log.Warn("an unknown environment variable is set", "name", name)
		}
	}
	return nil
}
