// Command rootgen refreshes the site's embedded Sigstore trusted roots
// (site/roots): it fetches each instance's trusted root through its TUF
// repository, checks that it parses, and writes it with the time it was
// fetched. Run it with `go generate ./site`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/vettid/votes/site"
)

func main() {
	out := flag.String("out", "roots", "the directory to write")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "rootgen:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	// Fetched first, written after: a failure leaves the old set whole.
	roots := map[string][]byte{}
	for _, instance := range []string{site.Production, site.Staging} {
		b, err := site.FetchRootJSON(instance)
		if err != nil {
			return fmt.Errorf("%s: %w", instance, err)
		}
		if _, err := root.NewTrustedRootFromJSON(b); err != nil {
			return fmt.Errorf("%s: %w", instance, err)
		}
		roots[instance] = b
	}
	for instance, b := range roots {
		if err := os.WriteFile(filepath.Join(out, instance+".json"), b, 0o644); err != nil {
			return err
		}
	}
	at := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339) + "\n"
	return os.WriteFile(filepath.Join(out, "embedded_at"), []byte(at), 0o644)
}
