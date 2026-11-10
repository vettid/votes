package rekor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
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

// Skew is the clock skew allowed for an entry's integrated time
// against the time it is verified (chosen; not in the spec).
const Skew = 60 * time.Second

// ErrInconsistent is a checkpoint that contradicts another: a smaller
// tree, another root at a size, a failed consistency proof, or an origin
// that isn't the instance's (VOTES-SITE §7, "rekor: inconsistent").
var ErrInconsistent = errors.New("rekor: inconsistent")

// forHost is the logs of the trusted root at host (their base URL's).
func (l Logs) forHost(host string) Logs {
	out := Logs{}
	for id, tl := range l {
		if u, err := url.Parse(tl.BaseURL); err == nil && u.Host == host {
			out[id] = tl
		}
	}
	return out
}

// verifier is the key of the trusted log keyID (hex) at host, valid at
// at.
func (l Logs) verifier(keyID, host string, at time.Time) (signature.Verifier, error) {
	tl, ok := l.forHost(host)[strings.ToLower(keyID)]
	if !ok {
		return nil, errors.New("rekor: the log is not the instance's in the trusted root")
	}
	if tl.ValidityPeriodStart.IsZero() || at.Before(tl.ValidityPeriodStart) || (!tl.ValidityPeriodEnd.IsZero() && at.After(tl.ValidityPeriodEnd)) {
		return nil, errors.New("rekor: the log's key was not valid then")
	}
	return signature.LoadVerifier(tl.PublicKey, tl.HashFunc)
}

// VerifyCheckpoint verifies a signed checkpoint (a signed note) under the
// key of the trusted log at host that its key hint names, valid at at
// (the run's time), and that its origin is "<host> - <tree ID>". A
// signature that doesn't verify is ErrUnverified; another origin is
// ErrInconsistent.
func VerifyCheckpoint(note, host string, logs Logs, at time.Time) (*Checkpoint, error) {
	var sc util.SignedCheckpoint
	if err := sc.UnmarshalText([]byte(note)); err != nil {
		return nil, fmt.Errorf("%w: checkpoint: %v", ErrUnverified, err)
	}
	hints := map[uint32]bool{}
	for _, sig := range sc.Signatures {
		hints[sig.Hash] = true
	}
	verified := false
	for id := range logs.forHost(host) {
		b, err := hex.DecodeString(id)
		if err != nil || len(b) < 4 || !hints[binary.BigEndian.Uint32(b)] {
			continue
		}
		v, err := logs.verifier(id, host, at)
		if err == nil && sc.Verify(v) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("%w: the checkpoint's signature doesn't verify under %s's key in the trusted root", ErrUnverified, host)
	}
	treeID, ok := strings.CutPrefix(sc.Origin, host+" - ")
	if !ok {
		return nil, fmt.Errorf("%w: checkpoint origin %q isn't %s's", ErrInconsistent, sc.Origin, host)
	}
	if _, err := strconv.ParseUint(treeID, 10, 64); err != nil {
		return nil, fmt.Errorf("%w: checkpoint origin %q has no tree ID", ErrInconsistent, sc.Origin)
	}
	if len(sc.Hash) != sha256.Size {
		return nil, fmt.Errorf("%w: checkpoint root hash isn't 32 bytes", ErrUnverified)
	}
	return &Checkpoint{Origin: sc.Origin, TreeID: treeID, Size: sc.Size, Root: append([]byte(nil), sc.Hash...)}, nil
}

// VerifyConsistency checks that b's tree extends a's: same tree ID, b no
// smaller, and (when b is larger) the proof's hashes verify. Equal sizes
// need equal roots.
func VerifyConsistency(a, b *Checkpoint, hashes []string) error {
	if a.TreeID != b.TreeID {
		return fmt.Errorf("%w: tree %s, not %s", ErrInconsistent, b.TreeID, a.TreeID)
	}
	if b.Size < a.Size {
		return fmt.Errorf("%w: the tree shrank from %d to %d", ErrInconsistent, a.Size, b.Size)
	}
	if b.Size == a.Size {
		if !bytes.Equal(a.Root, b.Root) {
			return fmt.Errorf("%w: another root at size %d", ErrInconsistent, a.Size)
		}
		return nil
	}
	p := make([][]byte, len(hashes))
	for i, h := range hashes {
		var err error
		if p[i], err = hex.DecodeString(h); err != nil {
			return fmt.Errorf("%w: consistency proof isn't hex", ErrInconsistent)
		}
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, a.Size, b.Size, p, a.Root, b.Root); err != nil {
		return fmt.Errorf("%w: consistency from %d to %d: %v", ErrInconsistent, a.Size, b.Size, err)
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

// ErrNotAnchor is an entry that passed the log's checks and names none of
// the anchor keys (from the scan: not one the check looks at).
var ErrNotAnchor = errors.New("rekor: the entry names no anchor key")

// ErrUnverified wraps why an entry under an anchor key fails the log's
// checks (its ID's leaf hash, signed entry timestamp, inclusion proof,
// checkpoint or time; VOTES-SITE §7, "rekor: unverified"): the answer
// can't be trusted to be the log's.
var ErrUnverified = errors.New("rekor: unverified")

// ErrWrongKind wraps why an entry that passes the log's checks, and
// names an anchor key, isn't a hashedrekord 0.0.1 over a sha256 digest
// whose signature verifies under that key ("rekor: wrong kind"). Anyone
// may log an anchor key's public key in an entry of their own, so this is
// logged truth, and may be acknowledged; ErrUnverified never is.
var ErrWrongKind = errors.New("rekor: wrong kind")

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
// names anywhere, of any kind (a hashedrekord's key, a DSSE or in-toto
// envelope's verifiers), as a PEM public key or certificate, raw or in
// base64, compared by SPKI whatever its PEM form; or nil. It is the
// scan's filter, before the entry is verified: an entry it finds is then
// verified, and fails as ErrUnverified unless it is a hashedrekord 0.0.1
// signed by that key.
func AnchorOf(e *Entry, anchors [][]byte) []byte {
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	var found []byte
	var walk func(any)
	walk = func(v any) {
		if found != nil {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		case string:
			found = anchorIn([]byte(x), anchors)
			if found == nil {
				if d, err := base64.StdEncoding.DecodeString(x); err == nil {
					found = anchorIn(d, anchors)
				}
			}
		}
	}
	walk(v)
	return found
}

// maxPEMBlocks bounds the PEM markers tried in one string (chosen; not
// in the spec): a decode that fails scans the rest of the string, so a
// hostile string of markers would otherwise take quadratic time. Keys
// and certificate chains have a few.
const maxPEMBlocks = 16

// anchorIn returns the anchor key among the PEM blocks in b, if any.
func anchorIn(b []byte, anchors [][]byte) []byte {
	for tries := 0; tries < maxPEMBlocks; tries++ {
		i := bytes.Index(b, []byte("-----BEGIN "))
		if i < 0 {
			return nil
		}
		blk, rest := pem.Decode(b[i:])
		if blk == nil {
			// Past this marker's line.
			b = b[i+len("-----BEGIN "):]
			if j := bytes.IndexByte(b, '\n'); j >= 0 {
				b = b[j+1:]
			}
			continue
		}
		b = rest
		spki, _, err := keyOf(pem.EncodeToMemory(blk))
		if err != nil {
			continue
		}
		for _, a := range anchors {
			if bytes.Equal(a, spki) {
				return a
			}
		}
	}
	return nil
}

// checkBody checks a body is a hashedrekord 0.0.1 over a sha256 digest
// whose ECDSA signature verifies under the key it names, and returns the
// digest.
func checkBody(body []byte) (digest, spki []byte, err error) {
	var hr hashedRekord
	if err = json.Unmarshal(body, &hr); err != nil {
		return nil, nil, fmt.Errorf("body: %v", err)
	}
	if hr.Kind != "hashedrekord" || hr.APIVersion != "0.0.1" {
		return nil, nil, fmt.Errorf("a %s %s entry", hr.Kind, hr.APIVersion)
	}
	if hr.Spec.Data.Hash.Algorithm != "sha256" {
		return nil, nil, fmt.Errorf("a %s digest", hr.Spec.Data.Hash.Algorithm)
	}
	digest, err = hex.DecodeString(hr.Spec.Data.Hash.Value)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != hr.Spec.Data.Hash.Value {
		return nil, nil, errors.New("digest isn't 32 bytes of lowercase hex")
	}
	spki, pub, err := keyOf(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("key: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(ec, digest, hr.Spec.Signature.Content) {
		return nil, nil, errors.New("the signature over the digest doesn't verify")
	}
	return digest, spki, nil
}

// ErrUnparsed is an entry that passed the log's checks but whose body
// doesn't parse as JSON: a warning, counted (VOTES-SITE §7, "Staging's
// scan", rekor.unparsed), as nothing in it can be read as an anchor
// key's.
var ErrUnparsed = errors.New("rekor: the entry's body doesn't parse")

// Place says where an entry is checked: Offset, the sizes of the shards
// before the proof's (LogInfo.InactiveShards), so that the global log
// index is the shard's plus Offset; and CheckpointAt, the time the proof's
// checkpoint key must be valid at: the run's for the active shard, or
// zero for an inactive shard's, whose key is checked at the entry's
// integrated time.
type Place struct {
	Offset       int64
	CheckpointAt time.Time
}

// VerifyEntry verifies an entry Rekor returned under id (VOTES-SITE §7,
// "Each entry found"), the log's part first, any failure of which is
// ErrUnverified (never acknowledged):
//
//   - the ID is 80 lowercase hex digits ending in the body's leaf hash;
//   - its integrated time is not after verifiedAt plus Skew;
//   - the log's key is the instance's (host) in the trusted root, valid
//     then; its signed entry timestamp (over the global log index) and its
//     inclusion proof (at the shard's) verify; the proof's checkpoint
//     verifies, with the proof's root and size;
//   - the global index is the shard's plus pl.Offset.
//
// Then the body: one that doesn't parse is ErrUnparsed; one naming no
// anchor key ErrNotAnchor; one naming one that isn't a hashedrekord 0.0.1
// over a sha256 digest signed by that key ErrWrongKind. With each of these
// the Verified is returned too, without a Digest.
//
// Whether the proof's checkpoint is the run's or consistent with it is
// the caller's to check (Verified.Proof), for every entry: one that isn't
// is inconsistent, whatever else it is. Only then is wrong kind a finding
// that may be acknowledged.
func VerifyEntry(ctx context.Context, id string, e *Entry, host string, logs Logs, anchors [][]byte, pl Place, verifiedAt time.Time) (*Verified, error) {
	fail := func(format string, a ...any) (*Verified, error) {
		return nil, fmt.Errorf("%w: %s", ErrUnverified, fmt.Sprintf(format, a...))
	}
	id = strings.ToLower(id)
	if len(id) != 80 || strings.Trim(id, "0123456789abcdef") != "" {
		return fail("entry ID %q isn't 80 hex digits", id)
	}
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return fail("body isn't base64")
	}
	leaf := id[16:]
	if got := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(body)); got != leaf {
		return fail("entry ID isn't the body's leaf hash")
	}
	ip := e.Verification.InclusionProof
	if ip == nil || len(e.Verification.SignedEntryTimestamp) == 0 {
		return fail("no inclusion proof or signed entry timestamp")
	}
	integrated := time.Unix(e.IntegratedTime, 0)
	if integrated.After(verifiedAt.Add(Skew)) {
		return fail("integrated at %s, after it is verified", integrated.UTC().Format(time.RFC3339))
	}
	v, err := logs.verifier(e.LogID, host, integrated)
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
	cpAt := pl.CheckpointAt
	if cpAt.IsZero() {
		cpAt = integrated
	}
	cp, err := VerifyCheckpoint(ip.Checkpoint, host, logs, cpAt)
	if err != nil {
		return fail("%v", err)
	}
	if root, err := hex.DecodeString(ip.RootHash); err != nil || !bytes.Equal(root, cp.Root) || int64(cp.Size) != ip.TreeSize {
		return fail("the proof's root or size isn't its checkpoint's")
	}
	if e.LogIndex != ip.LogIndex+pl.Offset {
		return fail("global index %d isn't the shard's %d plus %d", e.LogIndex, ip.LogIndex, pl.Offset)
	}
	// The log's checks hold: the body is what the log holds under this ID.
	out := &Verified{ID: id, Leaf: leaf, LogIndex: e.LogIndex, ShardIndex: ip.LogIndex,
		Integrated: integrated.UTC(), Proof: cp}
	if !json.Valid(body) {
		return out, ErrUnparsed
	}
	spki := AnchorOf(e, anchors)
	if spki == nil {
		return out, ErrNotAnchor
	}
	out.SPKI = spki
	digest, keySPKI, err := checkBody(body)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrWrongKind, err)
	}
	if !bytes.Equal(keySPKI, spki) {
		return out, fmt.Errorf("%w: the anchor key isn't the entry's signing key", ErrWrongKind)
	}
	out.Digest = digest
	return out, nil
}
