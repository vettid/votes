package lambdaenv

import (
	"io"
	"log/slog"
	"os"
	"regexp"
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
}
