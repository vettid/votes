package site

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vettid/service-vault/vote"
)

// Acknowledgement is a partial upload a monitor reports without failing
// on (docs/VOTES-SITE.md §7): one the site can never complete, added to
// the acknowledged list by PR, with its reason. It names the partial's
// served objects by key and hash, so that a changed or added object, or
// another partial, is still a mismatch.
type Acknowledgement struct {
	ProposalID     string   `json:"proposal_id"`
	Document       string   `json:"document"` // proposal, extension-<n> or results
	Reason         string   `json:"reason"`
	AcknowledgedAt string   `json:"acknowledged_at"` // YYYY-MM-DD
	Objects        []Object `json:"objects"`
}

// Object is one served object: its key (v1/p/<proposal_id>/...) and the
// SHA-256 of its bytes, in lowercase hex.
type Object struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// partialKeys are the keys a document's partial upload may leave: the
// document itself, its signature and its bundle.
func partialKeys(id, name string) []string {
	base := docPath(id, name)
	return []string{base, base + ".sig", base + ".sigstore.json"}
}

// ParseAcknowledged reads an acknowledged list: a JSON array of
// acknowledgements, each field present and well formed, none twice, no
// other members and nothing after the array. Each entry has at least one
// object, each a key of its document's (partialKeys) with a hex SHA-256,
// none twice.
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
		if len(a.Objects) == 0 {
			return nil, fmt.Errorf("acknowledged: entry %d: objects are required (the partial's served objects, by key and sha256)", i)
		}
		keys := partialKeys(a.ProposalID, a.Document)
		prefix := "v1/p/" + a.ProposalID + "/"
		seenKey := map[string]bool{}
		for j, o := range a.Objects {
			switch {
			case !strings.HasPrefix(o.Key, prefix):
				return nil, fmt.Errorf("acknowledged: entry %d: object %d: the key is not under %s", i, j, prefix)
			case !slices.Contains(keys, o.Key):
				return nil, fmt.Errorf("acknowledged: entry %d: object %d: the key is not one of %s's objects (%s)", i, j, a.Document, strings.Join(keys, ", "))
			case !hexSHA256.MatchString(o.SHA256):
				return nil, fmt.Errorf("acknowledged: entry %d: object %d: sha256 is 64 lowercase hex digits", i, j)
			case seenKey[o.Key]:
				return nil, fmt.Errorf("acknowledged: entry %d: object %d: listed twice", i, j)
			}
			seenKey[o.Key] = true
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
// partial upload they list that the site can no longer complete, and
// whose served objects are exactly the entry's, is reported in
// Acknowledged and is no longer a mismatch. One they list that isn't such
// a partial (completed, still retryable, or a wrong entry) is a mismatch,
// so that the list stays true; so is one whose served objects differ from
// the entry's (an object missing, added or changed), and its partial
// stays a mismatch too.
func (r *Report) Acknowledge(acks []Acknowledgement) {
	for _, a := range acks {
		if a.ProposalID != r.ProposalID {
			continue
		}
		// Only a partial the site can never complete may be acknowledged
		// (PartialPermanent); a retryable one stays a mismatch.
		if !slices.Contains(r.PartialPermanent, a.Document) {
			r.Mismatches = append(r.Mismatches, StaleAcknowledgement(a))
			continue
		}
		if diff := objectsDiff(a.Objects, r.PartialObjects[a.Document]); diff != "" {
			r.Mismatches = append(r.Mismatches, "acknowledged: "+a.ProposalID+" "+a.Document+
				": the served objects differ from the entry's ("+diff+")")
			continue
		}
		r.Acknowledged = append(r.Acknowledged, a.Document)
		if m, ok := r.partialMismatches[a.Document]; ok {
			r.Mismatches = slices.DeleteFunc(r.Mismatches, func(s string) bool { return s == m })
		}
	}
}

// objectsDiff says how the served objects differ from the listed ones:
// "" when they are the same keys, each with the same hash.
func objectsDiff(listed, served []Object) string {
	want := map[string]string{}
	for _, o := range listed {
		want[o.Key] = o.SHA256
	}
	got := map[string]string{}
	for _, o := range served {
		got[o.Key] = o.SHA256
	}
	var out []string
	for _, o := range listed {
		h, ok := got[o.Key]
		switch {
		case !ok:
			out = append(out, "not served: "+o.Key)
		case h != o.SHA256:
			out = append(out, "changed: "+o.Key+" is served with sha256 "+h)
		}
	}
	for _, o := range served {
		if _, ok := want[o.Key]; !ok {
			out = append(out, "not listed: "+o.Key+" with sha256 "+o.SHA256)
		}
	}
	return strings.Join(out, "; ")
}

// objectOf is a served object's entry.
func objectOf(key string, b []byte) Object {
	return Object{Key: key, SHA256: hex.EncodeToString(sha(b))}
}

// StaleAcknowledgement is the mismatch for an acknowledgement that
// matches no permanent partial upload.
func StaleAcknowledgement(a Acknowledgement) string {
	return "acknowledged: " + a.ProposalID + " " + a.Document + ": not a partial upload the site can no longer complete (remove the entry)"
}
