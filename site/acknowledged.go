package site

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/vettid/service-vault/vote"
)

// Acknowledgement is a partial upload a monitor reports without failing
// on (docs/VOTES-SITE.md §7): one the site can never complete, added to
// the acknowledged list by PR, with its reason.
type Acknowledgement struct {
	ProposalID     string `json:"proposal_id"`
	Document       string `json:"document"` // proposal, extension-<n> or results
	Reason         string `json:"reason"`
	AcknowledgedAt string `json:"acknowledged_at"` // YYYY-MM-DD
}

// ParseAcknowledged reads an acknowledged list: a JSON array of
// acknowledgements, each field present and well formed, none twice, no
// other members and nothing after the array.
func ParseAcknowledged(b []byte) ([]Acknowledgement, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var acks []Acknowledgement
	if err := dec.Decode(&acks); err != nil {
		return nil, fmt.Errorf("acknowledged: %w", err)
	}
	if acks == nil {
		return nil, errors.New("acknowledged: not an array")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("acknowledged: data after the array")
	}
	seen := map[[2]string]bool{}
	for i, a := range acks {
		if !vote.ValidProposalID(a.ProposalID) || nameRe.FindStringSubmatch(a.Document) == nil || a.Reason == "" {
			return nil, fmt.Errorf("acknowledged: entry %d: proposal_id, document and reason are required", i)
		}
		if _, err := time.Parse(time.DateOnly, a.AcknowledgedAt); err != nil {
			return nil, fmt.Errorf("acknowledged: entry %d: acknowledged_at is YYYY-MM-DD", i)
		}
		k := [2]string{a.ProposalID, a.Document}
		if seen[k] {
			return nil, fmt.Errorf("acknowledged: entry %d: listed twice", i)
		}
		seen[k] = true
	}
	return acks, nil
}

// Acknowledge applies the acknowledgements of this report's proposal: a
// partial upload they list is reported in Acknowledged and is no longer a
// mismatch; one they list that isn't partial (completed, or a wrong entry)
// is a mismatch, so that the list stays true.
func (r *Report) Acknowledge(acks []Acknowledgement) {
	for _, a := range acks {
		if a.ProposalID != r.ProposalID {
			continue
		}
		if !slices.Contains(r.Partial, a.Document) {
			r.Mismatches = append(r.Mismatches, StaleAcknowledgement(a))
			continue
		}
		r.Acknowledged = append(r.Acknowledged, a.Document)
		if m, ok := r.partialMismatches[a.Document]; ok {
			r.Mismatches = slices.DeleteFunc(r.Mismatches, func(s string) bool { return s == m })
		}
	}
}

// StaleAcknowledgement is the mismatch for an acknowledgement that
// matches no partial upload.
func StaleAcknowledgement(a Acknowledgement) string {
	return "acknowledged: " + a.ProposalID + " " + a.Document + ": not a partial upload (remove the entry)"
}
