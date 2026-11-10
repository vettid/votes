package awsio

import (
	"encoding/json"
	"errors"
	"strconv"
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
