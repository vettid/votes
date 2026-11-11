package awsio

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/votes/signer"
)

// Anchor is service-vault's Anchorer with the token's time read, as the
// signer's Anchor wants it, and its Sign done here: a signature that
// doesn't verify under the key read at start (the alias repointed, say)
// comes back as a *signer.KeyMismatchError carrying it, so the signer
// journals it and stops signing.
type Anchor struct {
	*anchor.Anchorer
	key anchor.DigestSigner
	pub *ecdsa.PublicKey
}

// NewAnchor wraps a for key, fixing the key's public half now.
func NewAnchor(a *anchor.Anchorer, key anchor.DigestSigner) Anchor {
	pub := *key.Public()
	return Anchor{Anchorer: a, key: key, pub: &pub}
}

// Sign implements signer.Anchor.
func (a Anchor) Sign(ctx context.Context, doc []byte) ([]byte, []byte, error) {
	d := sha256.Sum256(doc)
	sig, err := a.key.SignDigest(ctx, d[:])
	if err != nil {
		return nil, nil, err
	}
	if !ecdsa.VerifyASN1(a.pub, d[:], sig) {
		return d[:], nil, &signer.KeyMismatchError{Sig: sig}
	}
	return d[:], sig, nil
}

// TokenTime implements signer.Anchor: the token's genTime, unverified (it
// only decides whether to ask for a fresh one; Bundle and the site verify
// the token).
func (Anchor) TokenTime(token []byte) (time.Time, error) {
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return time.Time{}, errors.New("awsio: the kept token doesn't parse")
	}
	return ts.Time, nil
}

// EntryTime implements signer.Anchor: the entry's integratedTime, as the
// bundle's JSON form carries it (a decimal string), unverified.
func (Anchor) EntryTime(entry json.RawMessage) (time.Time, error) {
	var e struct {
		IntegratedTime string `json:"integratedTime"`
	}
	if err := json.Unmarshal(entry, &e); err != nil {
		return time.Time{}, errors.New("awsio: the kept entry doesn't parse")
	}
	n, err := strconv.ParseInt(e.IntegratedTime, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("awsio: the kept entry has no integrated time")
	}
	return time.Unix(n, 0), nil
}
