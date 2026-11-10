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

	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Anchors checks documents' Sigstore bundles (BALLOT-PROTOCOL §8.5
// "Rekor profile") with Sigstore's own verifier, against one instance's
// trusted root.
type Anchors struct {
	fixed root.TrustedMaterial // given material, never refreshed
	r     *refresher           // or the instance's, refreshed through TUF
}

// Sigstore instances, as the service vault's SV_SIGSTORE names them.
const (
	Staging    = "staging"
	Production = "production"
)

// NewAnchors checks against the instance's trusted root, fetched through
// its TUF repository at the start and again at most once per RootRefresh.
// If the first fetch fails it starts on the embedded root, unless that is
// over MaxEmbeddedAge old; a later failed fetch keeps the root it has.
func NewAnchors(instance string) (*Anchors, error) {
	emb, at, err := EmbeddedRoot(instance)
	if err != nil {
		return nil, err
	}
	return newAnchorsFrom(emb, at, func() (root.TrustedMaterial, error) {
		b, err := FetchRootJSON(instance)
		if err != nil {
			return nil, err
		}
		return root.NewTrustedRootFromJSON(b)
	}, time.Now)
}

func newAnchorsFrom(emb []byte, at time.Time, fetch func() (root.TrustedMaterial, error), now func() time.Time) (*Anchors, error) {
	r, err := newRefresher(emb, at, fetch, now)
	if err != nil {
		return nil, err
	}
	return &Anchors{r: r}, nil
}

// NewAnchorsWith checks against given trusted material: a trusted root
// file, or tests.
func NewAnchorsWith(trusted root.TrustedMaterial) *Anchors { return &Anchors{fixed: trusted} }

// RootSource says where the trusted root in use came from: RootFromTUF,
// RootFromEmbedded, or RootFromFile for given material.
func (a *Anchors) RootSource() string {
	if a.r == nil {
		return RootFromFile
	}
	return a.r.from()
}

// Trusted is the trusted material in use (for the Rekor check's log keys).
func (a *Anchors) Trusted() root.TrustedMaterial { return a.trusted() }

func (a *Anchors) trusted() root.TrustedMaterial {
	if a.r == nil {
		return a.fixed
	}
	return a.r.material()
}

// AnchorTimes are a bundle's two verified times: the RFC 3161
// timestamp's, which the site goes by, and the time Rekor integrated the
// entry, signed in its inclusion promise (zero if it has none).
type AnchorTimes struct {
	TSA   time.Time
	Rekor time.Time
	// Entry is the bundle's own Rekor v1 entry, as Sigstore's verifier
	// checked it, for the Rekor check (VOTES-SITE §7), which verifies its
	// checkpoint itself. It is nil unless the bundle has a single v1 entry
	// with both an inclusion promise (which signs the global log index and
	// the integrated time) and an inclusion proof whose tree size and root
	// are its checkpoint's signed ones (Sigstore's verifier compares only
	// the root, and a right-edge leaf verifies at other index and size
	// pairs, smaller or larger, so the shard index is bound only by that
	// size). §4 doesn't
	// require the promise: a bundle without one passes the upload, and the
	// Rekor check reports "anchored, no signed entry" for it. (Bundles of
	// the profile's v0.3 always carry a proof; the v2 and proof guards
	// below can't be reached by them, and have no test.)
	Entry *RekorEntry
}

// RekorEntry is a bundle's Rekor entry: its leaf hash (the last 64 hex
// digits of its entry ID), its global log index and integrated time (as
// the inclusion promise signs them), its shard's index (the proof's), and
// the proof's checkpoint, a signed note whose own size and root are the
// ones to use once it is verified.
type RekorEntry struct {
	Leaf       []byte
	LogIndex   int64
	ShardIndex int64
	Integrated time.Time
	Checkpoint string
}

// Verify checks that bundleJSON anchors exactly doc under the anchor key
// with SubjectPublicKeyInfo spki: the ECDSA P-256 signature over doc, the
// Rekor entry and its inclusion proof, and one RFC 3161 timestamp. It
// returns the timestamp's time.
func (a *Anchors) Verify(bundleJSON, doc, spki []byte) (time.Time, error) {
	t, err := a.VerifyTimes(bundleJSON, doc, spki)
	return t.TSA, err
}

// VerifyTimes is Verify, returning both of the bundle's verified times.
func (a *Anchors) VerifyTimes(bundleJSON, doc, spki []byte) (AnchorTimes, error) {
	var none AnchorTimes
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return none, errors.New("site: the anchor key doesn't parse")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return none, errors.New("site: the anchor key isn't P-256")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return none, fmt.Errorf("site: bundle: %w", err)
	}
	hint := Hint(spki)
	vc, err := b.VerificationContent()
	if err != nil || vc.PublicKey() == nil || vc.PublicKey().Hint() != hint {
		return none, errors.New("site: the bundle names another key")
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
	material := root.TrustedMaterialCollection{a.trusted(), keys}
	v, err := verify.NewVerifier(material, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	if err != nil {
		return none, err
	}
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(doc)), verify.WithKey()))
	if err != nil {
		return none, fmt.Errorf("site: bundle: %w", err)
	}
	var t AnchorTimes
	for _, vt := range res.VerifiedTimestamps {
		if vt.Type == "TimestampAuthority" {
			t.TSA = vt.Timestamp
		}
	}
	if t.TSA.IsZero() {
		return none, errors.New("site: the bundle has no verified RFC 3161 timestamp")
	}
	// The verifier checked the entry, and its inclusion promise when it
	// has one (an entry whose promise fails is skipped, and one entry is
	// required): with a single entry, a promised integrated time is
	// signed by the log.
	if es, err := b.TlogEntries(); err == nil && len(es) == 1 && es[0].HasInclusionPromise() {
		t.Rekor = es[0].IntegratedTime()
		// The global index and the time only as the promise signs them,
		// with a v1 proof against the canonical body.
		if tle := es[0].TransparencyLogEntry(); !es[0].IsRekorV2() && tle != nil && tle.GetInclusionProof() != nil && tle.GetInclusionProof().GetCheckpoint() != nil {
			ip := tle.GetInclusionProof()
			var sc util.SignedCheckpoint
			if sc.UnmarshalText([]byte(ip.GetCheckpoint().GetEnvelope())) == nil && ip.GetTreeSize() >= 0 &&
				sc.Size == uint64(ip.GetTreeSize()) && bytes.Equal(sc.Hash, ip.GetRootHash()) {
				t.Entry = &RekorEntry{Leaf: rfc6962.DefaultHasher.HashLeaf(tle.GetCanonicalizedBody()), LogIndex: tle.GetLogIndex(),
					ShardIndex: ip.GetLogIndex(), Integrated: es[0].IntegratedTime(), Checkpoint: ip.GetCheckpoint().GetEnvelope()}
			}
		}
	}
	return t, nil
}

// TimestampOf is the verified RFC 3161 time of a bundle, without the
// document it anchors (the timestamp covers the bundle's signature): for
// dating a partial upload.
func (a *Anchors) TimestampOf(bundleJSON []byte) (time.Time, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return time.Time{}, fmt.Errorf("site: bundle: %w", err)
	}
	ts, err := verify.VerifySignedTimestampWithThreshold(&b, a.trusted(), 1)
	if err != nil {
		return time.Time{}, fmt.Errorf("site: bundle: %w", err)
	}
	return ts[0].Time, nil
}

// Hint is how a bundle names the anchor key: base64 of SHA-256 of its
// SubjectPublicKeyInfo.
func Hint(spki []byte) string {
	h := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(h[:])
}
