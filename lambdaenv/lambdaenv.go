// Package lambdaenv refuses a Lambda environment that could point a
// function's AWS clients elsewhere or change what runs (the key protection
// design's environment deny-list): a function whose configuration is
// compiled in reads nothing it trusts from its environment.
package lambdaenv

import (
	"fmt"
	"log/slog"
	"strings"
)

// Denied are the variables that, set, stop the start.
var Denied = []string{
	"AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
	"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
	"AWS_ENABLE_ENDPOINT_DISCOVERY", "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_RETRY_MODE",
	"AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
	"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_MAX_ATTEMPTS",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG", "LD_PRELOAD", "LD_AUDIT", "AWS_LAMBDA_EXEC_WRAPPER",
}

// DeniedPrefixes are denied as prefixes.
var DeniedPrefixes = []string{"AWS_ENDPOINT_URL_", "AWS_CONTAINER_CREDENTIALS_"}

// Known are Lambda's documented variables for a custom runtime: any other
// name is logged once, as a notice (its name only, never its value).
var Known = map[string]bool{
	"AWS_REGION": true, "AWS_DEFAULT_REGION": true, "AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN": true, "AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true,
	"AWS_LAMBDA_FUNCTION_VERSION": true, "AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true,
	"AWS_LAMBDA_LOG_STREAM_NAME": true, "AWS_LAMBDA_RUNTIME_API": true, "AWS_EXECUTION_ENV": true,
	"AWS_XRAY_CONTEXT_MISSING": true, "AWS_XRAY_DAEMON_ADDRESS": true, "_AWS_XRAY_DAEMON_ADDRESS": true,
	"_AWS_XRAY_DAEMON_PORT": true, "_X_AMZN_TRACE_ID": true, "_HANDLER": true, "LAMBDA_TASK_ROOT": true,
	"LAMBDA_RUNTIME_DIR": true, "LANG": true, "PATH": true, "TZ": true, "LD_LIBRARY_PATH": true,
}

// Check refuses a denied variable and notes an unknown one.
func Check(environ []string, log *slog.Logger) error {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		for _, d := range Denied {
			if name == d {
				return fmt.Errorf("refusing to start: %s is set", name)
			}
		}
		for _, p := range DeniedPrefixes {
			if strings.HasPrefix(name, p) {
				return fmt.Errorf("refusing to start: %s is set", name)
			}
		}
		if !Known[name] && !strings.HasPrefix(name, "AWS_LAMBDA_LOG_") {
			log.Warn("an unknown environment variable is set", "name", name)
		}
	}
	return nil
}
