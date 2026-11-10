package awsio

import (
	"errors"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/vettid/service-vault/anchor"
)

// Anchor is service-vault's Anchorer with the token's time read, as the
// signer's Anchor wants it.
type Anchor struct{ *anchor.Anchorer }

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
