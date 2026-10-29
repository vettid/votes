package site

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Anchors checks documents' Sigstore bundles (BALLOT-PROTOCOL §8.5
// "Rekor profile") with Sigstore's own verifier, against one instance's
// trusted root.
type Anchors struct {
	trusted root.TrustedMaterial
}

// Sigstore instances, as the service vault's SV_SIGSTORE names them.
const (
	Staging    = "staging"
	Production = "production"
)

// NewAnchors fetches the instance's trusted root through its TUF
// repository, with no local cache (Lambda's file system is read-only).
func NewAnchors(instance string) (*Anchors, error) {
	opts := tuf.DefaultOptions().WithDisableLocalCache()
	switch instance {
	case Production:
	case Staging:
		opts.Root, opts.RepositoryBaseURL = tuf.StagingRoot(), tuf.StagingMirror
	default:
		return nil, fmt.Errorf("site: unknown Sigstore instance %q", instance)
	}
	tr, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("site: trusted root: %w", err)
	}
	return &Anchors{trusted: tr}, nil
}

// NewAnchorsWith checks against given trusted material (tests).
func NewAnchorsWith(trusted root.TrustedMaterial) *Anchors { return &Anchors{trusted: trusted} }

// Verify checks that bundleJSON anchors exactly doc under the anchor key
// with SubjectPublicKeyInfo spki: the ECDSA P-256 signature over doc, the
// Rekor entry and its inclusion proof, and one RFC 3161 timestamp. It
// returns the timestamp's time.
func (a *Anchors) Verify(bundleJSON, doc, spki []byte) (time.Time, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return time.Time{}, errors.New("site: the anchor key doesn't parse")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return time.Time{}, errors.New("site: the anchor key isn't P-256")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return time.Time{}, fmt.Errorf("site: bundle: %w", err)
	}
	hint := Hint(spki)
	vc, err := b.VerificationContent()
	if err != nil || vc.PublicKey() == nil || vc.PublicKey().Hint() != hint {
		return time.Time{}, errors.New("site: the bundle names another key")
	}
	keys := root.NewTrustedPublicKeyMaterial(func(h string) (root.TimeConstrainedVerifier, error) {
		if h != hint {
			return nil, errors.New("site: not the anchor key")
		}
		v, err := signature.LoadECDSAVerifier(ec, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(v, time.Time{}, time.Time{}), nil
	})
	v, err := verify.NewVerifier(root.TrustedMaterialCollection{a.trusted, keys},
		verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	if err != nil {
		return time.Time{}, err
	}
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(doc)), verify.WithKey()))
	if err != nil {
		return time.Time{}, fmt.Errorf("site: bundle: %w", err)
	}
	var ts time.Time
	for _, t := range res.VerifiedTimestamps {
		if t.Type == "TimestampAuthority" {
			ts = t.Timestamp
		}
	}
	if ts.IsZero() {
		return time.Time{}, errors.New("site: the bundle has no verified RFC 3161 timestamp")
	}
	return ts, nil
}

// Hint is how a bundle names the anchor key: base64 of SHA-256 of its
// SubjectPublicKeyInfo.
func Hint(spki []byte) string {
	h := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(h[:])
}
