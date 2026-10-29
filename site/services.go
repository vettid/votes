package site

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vettid/service-vault/vote"
)

// The service list (BALLOT-PROTOCOL §3.3, §8.5): the registered services,
// their identity keys and their anchor keys, signed by the site's key.

// AnchorKey is a service's anchor key with its certificate by an identity
// key of the service.
type AnchorKey struct {
	Key        []byte `json:"key"`         // SubjectPublicKeyInfo, DER
	AnchorCert []byte `json:"anchor_cert"` // Sign(ik, LabelAnchorKey, H(key))
	IK         []byte `json:"ik"`
}

// Service is one registered service.
type Service struct {
	ServiceID  string      `json:"service_id"`
	Name       string      `json:"name"`
	IKs        [][]byte    `json:"iks"` // every identity key it has had, first first
	AnchorKeys []AnchorKey `json:"anchor_keys"`
}

// ServiceList is the list as published.
type ServiceList struct {
	V        int64     `json:"v"`
	Version  int64     `json:"version"`
	Previous []byte    `json:"previous"`
	Services []Service `json:"services"`
}

// ServiceID is the lower-case hex of H(first ik)[0:16].
func ServiceID(firstIK []byte) string {
	h := sha256.Sum256(firstIK)
	return hex.EncodeToString(h[:16])
}

// ParseServiceList checks the list's signature under siteKey, its exact
// canonical bytes, and every entry, and returns it.
func ParseServiceList(data, sig []byte, siteKey ed25519.PublicKey) (*ServiceList, error) {
	if vote.Verify(siteKey, vote.LabelServiceList, sha(data), sig) != nil {
		return nil, errors.New("site: the service list's signature fails")
	}
	canon, err := vote.Canonicalize(data)
	if err != nil || !bytes.Equal(canon, data) {
		return nil, errors.New("site: the service list isn't canonical")
	}
	var l ServiceList
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil || l.V != 1 || l.Version < 1 || len(l.Previous) != vote.HashLen {
		return nil, errors.New("site: the service list's fields")
	}
	for _, s := range l.Services {
		if err := s.check(); err != nil {
			return nil, err
		}
	}
	return &l, nil
}

func (s *Service) check() error {
	if len(s.IKs) == 0 || s.ServiceID != ServiceID(s.IKs[0]) {
		return fmt.Errorf("site: service %q: id", s.ServiceID)
	}
	for i, k := range s.IKs {
		if len(k) != vote.VKLen {
			return fmt.Errorf("site: service %s: identity key %d", s.ServiceID, i)
		}
	}
	for i, a := range s.AnchorKeys {
		if !s.hasIK(a.IK) || vote.Verify(a.IK, vote.LabelAnchorKey, sha(a.Key), a.AnchorCert) != nil {
			return fmt.Errorf("site: service %s: anchor key %d isn't certified by its identity key", s.ServiceID, i)
		}
	}
	return nil
}

func (s *Service) hasIK(ik []byte) bool {
	for _, k := range s.IKs {
		if bytes.Equal(k, ik) {
			return true
		}
	}
	return false
}

// ByIK returns the service with identity key ik, or nil.
func (l *ServiceList) ByIK(ik []byte) *Service {
	for i := range l.Services {
		if l.Services[i].hasIK(ik) {
			return &l.Services[i]
		}
	}
	return nil
}

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
