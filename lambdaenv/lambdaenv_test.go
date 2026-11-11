package lambdaenv

import (
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, env := range [][]string{{"HTTPS_PROXY=x"}, {"AWS_ENDPOINT_URL_KMS=x"}, {"https_proxy=x"}, {"GODEBUG=x"}, {"AWS_CONTAINER_CREDENTIALS_FULL_URI=x"}} {
		if Check(env, log) == nil {
			t.Fatalf("%v accepted", env)
		}
	}
	if err := Check([]string{"AWS_REGION=us-east-1", "PATH=/bin", "SOMETHING_ELSE=1", "AWS_LAMBDA_LOG_FORMAT=JSON"}, log); err != nil {
		t.Fatal(err)
	}
}

// The signer's own list (cmd/anchor-signer) and this one deny the same:
// a name added there and not here, or here and not there, fails.
func TestSameAsTheSigner(t *testing.T) {
	src, err := os.ReadFile("../cmd/anchor-signer/config.go")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var deniedEnv = \[\]string\{(.*?)\n\}`).FindSubmatch(src)
	if block == nil {
		t.Fatal("the signer's deniedEnv isn't where it was")
	}
	theirs := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(block[1], -1) {
		theirs[string(m[1])] = true
	}
	ours := map[string]bool{}
	for _, d := range Denied {
		ours[d] = true
		if !theirs[d] {
			t.Errorf("%s is denied here, not in the signer", d)
		}
	}
	for d := range theirs {
		if !ours[d] {
			t.Errorf("%s is denied in the signer, not here", d)
		}
	}
	// The prefixes and the known names too.
	for _, l := range []struct {
		re   string
		ours []string
	}{
		{`(?s)var deniedPrefixes = \[\]string\{(.*?)\}`, DeniedPrefixes},
		{`(?s)var knownEnv = map\[string\]bool\{(.*?)\n\}`, keys(Known)},
	} {
		b := regexp.MustCompile(l.re).FindSubmatch(src)
		if b == nil {
			t.Fatalf("the signer's list %s isn't where it was", l.re)
		}
		var theirs []string
		for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(b[1], -1) {
			theirs = append(theirs, string(m[1]))
		}
		sort.Strings(theirs)
		mine := append([]string(nil), l.ours...)
		sort.Strings(mine)
		if strings.Join(theirs, ",") != strings.Join(mine, ",") {
			t.Errorf("the signer has %v, this has %v", theirs, mine)
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
