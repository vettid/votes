// Package awsread reads what one reconcile pass needs, read-only: the
// signer's journal and KMS's Sign calls (from the trail's log group), what
// the votes site holds, and the signer function as deployed.
package awsread

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/reconcile"
	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

// LogsAPI is the CloudWatch Logs call a pass makes.
type LogsAPI interface {
	FilterLogEvents(ctx context.Context, in *cloudwatchlogs.FilterLogEventsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error)
}

// maxEvents bounds a read: past it the pass reports itself incomplete
// rather than check part of a period.
const maxEvents = 100000

func filter(ctx context.Context, c LogsAPI, group string, streams []string, pattern string, from, to time.Time, each func(msg string) error) error {
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(group), StartTime: aws.Int64(from.UnixMilli()), EndTime: aws.Int64(to.UnixMilli()),
	}
	if len(streams) > 0 {
		in.LogStreamNames = streams
	}
	if pattern != "" {
		in.FilterPattern = aws.String(pattern)
	}
	n := 0
	for {
		out, err := c.FilterLogEvents(ctx, in)
		if err != nil {
			return err
		}
		for _, e := range out.Events {
			if n++; n > maxEvents {
				return fmt.Errorf("more than %d events in the period", maxEvents)
			}
			if err := each(aws.ToString(e.Message)); err != nil {
				return err
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == aws.ToString(in.NextToken) {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

// Journal reads the signer's journal for the period: one JSON event per
// entry, {"kind": "sign" | "note" | "complete", ...}. An entry it can't
// read stops the read: a journal the pass can't read whole is incomplete.
func Journal(ctx context.Context, c LogsAPI, group, stream string, from, to time.Time) (signs []signer.SignEntry, done []signer.CompletionEntry, notes []signer.NoteEntry, err error) {
	err = filter(ctx, c, group, []string{stream}, "", from, to, func(msg string) error {
		var k struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(msg), &k); err != nil {
			return errors.New("journal: an entry isn't JSON")
		}
		dec := json.NewDecoder(strings.NewReader(msg))
		switch k.Kind {
		case "sign":
			var e struct {
				Kind string `json:"kind"`
				signer.SignEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a sign entry: %w", err)
			}
			signs = append(signs, e.SignEntry)
		case "complete":
			var e struct {
				Kind string `json:"kind"`
				signer.CompletionEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a completion entry: %w", err)
			}
			done = append(done, e.CompletionEntry)
		case "note":
			var e struct {
				Kind string `json:"kind"`
				signer.NoteEntry
			}
			if err := dec.Decode(&e); err != nil {
				return fmt.Errorf("journal: a note: %w", err)
			}
			notes = append(notes, e.NoteEntry)
		default:
			return fmt.Errorf("journal: an entry of kind %q", k.Kind)
		}
		return nil
	})
	return signs, done, notes, err
}

// SignPattern selects KMS Sign calls in the trail's log group.
const SignPattern = `{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }`

// cloudTrailRecord is the part of a CloudTrail record a pass reads.
type cloudTrailRecord struct {
	EventTime    time.Time `json:"eventTime"`
	RequestID    string    `json:"requestID"`
	ErrorCode    string    `json:"errorCode"`
	UserIdentity struct {
		ARN            string `json:"arn"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	RequestParameters struct {
		KeyID            string `json:"keyId"`
		SigningAlgorithm string `json:"signingAlgorithm"`
		MessageType      string `json:"messageType"`
	} `json:"requestParameters"`
	Resources []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

// KMSSigns reads every KMS Sign on keyARN in the period from the trail's
// log group. A Sign on another key is no concern of the anchor's (the
// account holds none other; its own alarms cover a new key).
func KMSSigns(ctx context.Context, c LogsAPI, trailGroup, keyARN string, from, to time.Time) ([]reconcile.KMSSign, error) {
	var out []reconcile.KMSSign
	err := filter(ctx, c, trailGroup, nil, SignPattern, from, to, func(msg string) error {
		var r cloudTrailRecord
		if err := json.Unmarshal([]byte(msg), &r); err != nil {
			return errors.New("trail: a record isn't JSON")
		}
		onKey := false
		for _, res := range r.Resources {
			onKey = onKey || res.ARN == keyARN
		}
		if !onKey {
			return nil
		}
		principal := r.UserIdentity.SessionContext.SessionIssuer.ARN
		if principal == "" {
			principal = r.UserIdentity.ARN
		}
		out = append(out, reconcile.KMSSign{RequestID: r.RequestID, At: r.EventTime, Principal: principal,
			Algorithm: r.RequestParameters.SigningAlgorithm, MessageType: r.RequestParameters.MessageType, ErrorCode: r.ErrorCode})
		return nil
	})
	return out, err
}

// ListAPI lists the site bucket's keys under a prefix.
type ListAPI interface {
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

const bundleSuffix = ".json.sigstore.json"

// Slots lists the documents the site holds for the proposals its index
// shows (every proposal it keeps there, §3.3), as proposal_id/name.
func Slots(ctx context.Context, store site.Storage, list ListAPI, bucket string) ([]string, error) {
	raw, _, err := store.Get(ctx, "v1/index.json")
	if err != nil {
		return nil, fmt.Errorf("the index: %w", err)
	}
	var idx []site.IndexEntry
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, errors.New("the index isn't a list of entries")
	}
	var slots []string
	for _, e := range idx {
		prefix := "v1/p/" + e.ProposalID + "/"
		in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)}
		for {
			out, err := list.ListObjectsV2(ctx, in)
			if err != nil {
				return nil, fmt.Errorf("listing %s: %w", prefix, err)
			}
			for _, o := range out.Contents {
				k := aws.ToString(o.Key)
				if name, ok := strings.CutSuffix(strings.TrimPrefix(k, prefix), bundleSuffix); ok && name != "" && !strings.Contains(name, "/") {
					slots = append(slots, e.ProposalID+"/"+name)
				}
			}
			if !aws.ToBool(out.IsTruncated) {
				break
			}
			in.ContinuationToken = out.NextContinuationToken
		}
	}
	return slots, nil
}

// Verifier checks a bundle for a document under the anchor key.
type Verifier interface {
	VerifyTimes(bundleJSON, doc, spki []byte) (site.AnchorTimes, error)
}

// Holding reads what the site holds for one slot: its bundle and
// document, the bundle verified under the anchor key, and its message
// signature. ok is false when it couldn't be read (an error other than a
// missing object).
func Holding(ctx context.Context, store site.Storage, v Verifier, spki []byte, slot string) (reconcile.Published, error) {
	base := "v1/p/" + slot
	bundle, _, err := store.Get(ctx, base+bundleSuffix)
	if errors.Is(err, site.ErrNotExist) {
		return reconcile.Published{}, nil
	}
	if err != nil {
		return reconcile.Published{}, err
	}
	sig, err := MessageSignature(bundle)
	if err != nil {
		return reconcile.Published{Held: true, VerifyErr: err.Error()}, nil
	}
	doc, _, err := store.Get(ctx, base+".json")
	if err != nil {
		if errors.Is(err, site.ErrNotExist) {
			return reconcile.Published{Held: true, Signature: sig, VerifyErr: "a bundle with no document"}, nil
		}
		return reconcile.Published{}, err
	}
	if _, err := v.VerifyTimes(bundle, doc, spki); err != nil {
		return reconcile.Published{Held: true, Signature: sig, VerifyErr: err.Error()}, nil
	}
	return reconcile.Published{Held: true, Signature: sig}, nil
}

// MessageSignature reads a bundle's message signature (unverified).
func MessageSignature(bundle []byte) ([]byte, error) {
	var b struct {
		MessageSignature *struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || b.MessageSignature == nil {
		return nil, errors.New("the bundle has no message signature")
	}
	sig, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("the bundle's message signature isn't base64")
	}
	return sig, nil
}

// LambdaAPI is the read-only Lambda calls a pass makes.
type LambdaAPI interface {
	GetFunctionConfiguration(ctx context.Context, in *lambda.GetFunctionConfigurationInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionConfigurationOutput, error)
	GetPolicy(ctx context.Context, in *lambda.GetPolicyInput, opts ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// Function reads the signer function's CodeSha256 and its resource
// policy, canonical (compact JSON, its statements' Sid order as AWS
// returns them).
func Function(ctx context.Context, c LambdaAPI, fn string) (codeSha256, policy string, err error) {
	cfg, err := c.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(fn)})
	if err != nil {
		return "", "", fmt.Errorf("the function: %w", err)
	}
	p, err := c.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(fn)})
	if err != nil {
		return "", "", fmt.Errorf("its policy: %w", err)
	}
	return aws.ToString(cfg.CodeSha256), Canonical(aws.ToString(p.Policy)), nil
}

// Canonical compacts a JSON policy so that two copies compare equal
// whatever their spacing; anything not JSON is returned as given.
func Canonical(policy string) string {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(policy)); err != nil {
		return policy
	}
	return b.String()
}
