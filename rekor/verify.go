package rekor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/util"
	rekorverify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Checkpoint is a verified signed tree head of one shard.
type Checkpoint struct {
	Origin string // "<host> - <tree ID>"
	TreeID string
	Size   uint64
	Root   []byte
}

// Logs are the Rekor logs of a trusted root, by key ID in hex
// (root.TrustedMaterial.RekorLogs).
type Logs map[string]*root.TransparencyLog

func (l Logs) verifier(keyID string, at time.Time) (signature.Verifier, error) {
	tl, ok := l[strings.ToLower(keyID)]
	if !ok {
		return nil, errors.New("rekor: the entry's log is not in the trusted root")
	}
	if tl.ValidityPeriodStart.IsZero() || at.Before(tl.ValidityPeriodStart) || (!tl.ValidityPeriodEnd.IsZero() && at.After(tl.ValidityPeriodEnd)) {
		return nil, errors.New("rekor: the log's key was not valid then")
	}
	return signature.LoadVerifier(tl.PublicKey, tl.HashFunc)
}

// VerifyCheckpoint verifies a signed checkpoint (a signed note) under one
// of the trusted logs' keys, and that its origin names host and a tree
// ID. The note's key hint picks the key; any trusted log's key that
// verifies it is accepted only if it was valid at, a time (the run's).
func VerifyCheckpoint(note, host string, logs Logs, at time.Time) (*Checkpoint, error) {
	var sc util.SignedCheckpoint
	if err := sc.UnmarshalText([]byte(note)); err != nil {
		return nil, fmt.Errorf("rekor: checkpoint: %w", err)
	}
	verified := false
	for id := range logs {
		v, err := logs.verifier(id, at)
		if err != nil {
			continue
		}
		if sc.Verify(v) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("rekor: the checkpoint's signature doesn't verify under the trusted root")
	}
	treeID, ok := strings.CutPrefix(sc.Origin, host+" - ")
	if !ok {
		return nil, fmt.Errorf("rekor: checkpoint origin %q isn't %s's", sc.Origin, host)
	}
	if _, err := strconv.ParseUint(treeID, 10, 64); err != nil {
		return nil, fmt.Errorf("rekor: checkpoint origin %q has no tree ID", sc.Origin)
	}
	if len(sc.Hash) != sha256.Size {
		return nil, errors.New("rekor: checkpoint root hash isn't 32 bytes")
	}
	return &Checkpoint{Origin: sc.Origin, TreeID: treeID, Size: sc.Size, Root: append([]byte(nil), sc.Hash...)}, nil
}

// VerifyConsistency checks that b's tree extends a's: same tree ID, b no
// smaller, and (when b is larger) the proof's hashes verify. Equal sizes
// need equal roots.
func VerifyConsistency(a, b *Checkpoint, hashes []string) error {
	if a.TreeID != b.TreeID {
		return fmt.Errorf("rekor: tree %s, not %s", b.TreeID, a.TreeID)
	}
	if b.Size < a.Size {
		return fmt.Errorf("rekor: the tree shrank from %d to %d", a.Size, b.Size)
	}
	if b.Size == a.Size {
		if !bytes.Equal(a.Root, b.Root) {
			return fmt.Errorf("rekor: another root at size %d", a.Size)
		}
		return nil
	}
	p := make([][]byte, len(hashes))
	for i, h := range hashes {
		var err error
		if p[i], err = hex.DecodeString(h); err != nil {
			return errors.New("rekor: consistency proof isn't hex")
		}
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, a.Size, b.Size, p, a.Root, b.Root); err != nil {
		return fmt.Errorf("rekor: consistency from %d to %d: %w", a.Size, b.Size, err)
	}
	return nil
}

// Verified is an entry under an anchor key, verified.
type Verified struct {
	// ID is the entry's 80-hex entry ID as Rekor gave it; Leaf its last
	// 64 (the leaf hash), which names it whatever the tree ID prefix.
	ID, Leaf string
	// LogIndex is the global log index; ShardIndex the index within its
	// shard (the inclusion proof's).
	LogIndex, ShardIndex int64
	Digest               []byte // the sha256 the entry signs
	SPKI                 []byte // the anchor key's, DER
	Integrated           time.Time
	// Proof is the checkpoint the inclusion proof is against (verified).
	Proof *Checkpoint
}

// ErrNotAnchor is an entry that names none of the anchor keys (from the
// scan: not one the check looks at).
var ErrNotAnchor = errors.New("rekor: the entry names no anchor key")

// ErrUnverified wraps why an entry under an anchor key fails to verify
// (VOTES-SITE §7: "rekor: unverified", whatever its digest).
var ErrUnverified = errors.New("rekor: unverified")

// hashedRekord is the body of a hashedrekord 0.0.1 entry.
type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   []byte `json:"content"`
			PublicKey struct {
				Content []byte `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// keyOf is the SPKI (DER) of the public key or certificate in PEM.
func keyOf(pemBytes []byte) ([]byte, crypto.PublicKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, nil, errors.New("no PEM block")
	}
	switch blk.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return blk.Bytes, pub, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return cert.RawSubjectPublicKeyInfo, cert.PublicKey, nil
	}
	return nil, nil, fmt.Errorf("PEM block %q", blk.Type)
}

// AnchorOf returns which anchor key (an SPKI in anchors) an entry's body
// names, by SPKI whatever its PEM form, in a key or a certificate, or
// nil: for the scan's filter, before the entry is verified.
func AnchorOf(e *Entry, anchors [][]byte) []byte {
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil
	}
	var hr hashedRekord
	if json.Unmarshal(body, &hr) != nil {
		return nil
	}
	spki, _, err := keyOf(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil
	}
	for _, a := range anchors {
		if bytes.Equal(a, spki) {
			return a
		}
	}
	return nil
}

// checkBody checks a body is a hashedrekord 0.0.1 over a sha256 digest
// whose ECDSA signature verifies under the key it names, and returns the
// digest.
func checkBody(body []byte) ([]byte, error) {
	var hr hashedRekord
	if err := json.Unmarshal(body, &hr); err != nil {
		return nil, fmt.Errorf("body: %v", err)
	}
	if hr.Kind != "hashedrekord" || hr.APIVersion != "0.0.1" {
		return nil, fmt.Errorf("a %s %s entry", hr.Kind, hr.APIVersion)
	}
	if hr.Spec.Data.Hash.Algorithm != "sha256" {
		return nil, fmt.Errorf("a %s digest", hr.Spec.Data.Hash.Algorithm)
	}
	digest, err := hex.DecodeString(hr.Spec.Data.Hash.Value)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != hr.Spec.Data.Hash.Value {
		return nil, errors.New("digest isn't 32 bytes of lowercase hex")
	}
	_, pub, err := keyOf(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, fmt.Errorf("key: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(ec, digest, hr.Spec.Signature.Content) {
		return nil, errors.New("the signature over the digest doesn't verify")
	}
	return digest, nil
}

// VerifyEntry verifies an entry Rekor returned under id (VOTES-SITE §7,
// "Each entry found"): the ID is the entry's leaf hash; the body is a
// hashedrekord 0.0.1 over a sha256 digest naming an anchor key, whose
// ECDSA signature over the digest verifies; its signed entry timestamp
// and its inclusion proof verify under the log's key in the trusted root,
// and the proof's checkpoint is the log's (host). An entry naming no
// anchor key is ErrNotAnchor; one naming one that fails anything else is
// ErrUnverified.
func VerifyEntry(ctx context.Context, id string, e *Entry, host string, logs Logs, anchors [][]byte) (*Verified, error) {
	id = strings.ToLower(id)
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: body isn't base64", ErrUnverified)
	}
	spki := AnchorOf(e, anchors)
	if spki == nil {
		return nil, ErrNotAnchor
	}
	fail := func(format string, a ...any) (*Verified, error) {
		return nil, fmt.Errorf("%w: %s", ErrUnverified, fmt.Sprintf(format, a...))
	}
	if len(id) != 80 && len(id) != 64 {
		return fail("entry ID %q", id)
	}
	leaf := id[len(id)-64:]
	if got := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(body)); got != leaf {
		return fail("entry ID isn't the body's leaf hash")
	}
	digest, err := checkBody(body)
	if err != nil {
		return fail("%v", err)
	}
	ip := e.Verification.InclusionProof
	if ip == nil || len(e.Verification.SignedEntryTimestamp) == 0 {
		return fail("no inclusion proof or signed entry timestamp")
	}
	integrated := time.Unix(e.IntegratedTime, 0)
	v, err := logs.verifier(e.LogID, integrated)
	if err != nil {
		return fail("%v", err)
	}
	anon := &models.LogEntryAnon{
		Body:           e.Body,
		IntegratedTime: &e.IntegratedTime,
		LogID:          &e.LogID,
		LogIndex:       &e.LogIndex,
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				Checkpoint: &ip.Checkpoint,
				Hashes:     ip.Hashes,
				LogIndex:   &ip.LogIndex,
				RootHash:   &ip.RootHash,
				TreeSize:   &ip.TreeSize,
			},
			SignedEntryTimestamp: strfmt.Base64(e.Verification.SignedEntryTimestamp),
		},
	}
	if err := rekorverify.VerifyLogEntry(ctx, anon, v); err != nil {
		return fail("%v", err)
	}
	cp, err := VerifyCheckpoint(ip.Checkpoint, host, logs, integrated)
	if err != nil {
		return fail("%v", err)
	}
	if root, err := hex.DecodeString(ip.RootHash); err != nil || !bytes.Equal(root, cp.Root) || int64(cp.Size) != ip.TreeSize {
		return fail("the proof's root or size isn't its checkpoint's")
	}
	return &Verified{ID: id, Leaf: leaf, LogIndex: e.LogIndex, ShardIndex: ip.LogIndex, Digest: digest, SPKI: spki,
		Integrated: integrated.UTC(), Proof: cp}, nil
}
