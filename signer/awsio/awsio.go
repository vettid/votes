// Package awsio is the AnchorSigner's AWS side (key protection, GC #7406
// §1–§4): the anchor key in KMS, the claim table in DynamoDB, the journal
// in CloudWatch Logs, and the votes site, read from its bucket and
// written through its upload API.
package awsio

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmw "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

// KMSAPI is the part of the KMS client the key uses.
type KMSAPI interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Key is the anchor key in KMS, as service-vault's anchor.DigestSigner:
// ECDSA P-256, signing SHA-256 digests (ECDSA_SHA_256, DIGEST). It records
// each Sign's request id where signer.RequestIDSink says, for the journal
// and the reconciler's match with CloudTrail.
type Key struct {
	Client KMSAPI
	KeyID  string
	pub    *ecdsa.PublicKey
}

// NewKey reads the key's public half and checks it is a P-256 signing key.
func NewKey(ctx context.Context, c KMSAPI, keyID string) (*Key, error) {
	out, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("awsio: the anchor key: %w", err)
	}
	if out.KeySpec != kmstypes.KeySpecEccNistP256 || out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("awsio: the anchor key is %s for %s, not ECC_NIST_P256 for SIGN_VERIFY", out.KeySpec, out.KeyUsage)
	}
	pk, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awsio: the anchor key: %w", err)
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("awsio: the anchor key isn't ECDSA P-256")
	}
	return &Key{Client: c, KeyID: keyID, pub: ec}, nil
}

// Public implements anchor.DigestSigner.
func (k *Key) Public() *ecdsa.PublicKey { return k.pub }

// SignDigest implements anchor.DigestSigner. The anchor package checks the
// signature against Public before it is used.
func (k *Key) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	out, err := k.Client.Sign(ctx, &kms.SignInput{KeyId: aws.String(k.KeyID), Message: digest,
		MessageType: kmstypes.MessageTypeDigest, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256})
	if sink := signer.RequestIDSink(ctx); sink != nil {
		switch {
		case out != nil:
			*sink, _ = awsmw.GetRequestIDMetadata(out.ResultMetadata)
		case err != nil:
			var re *awshttp.ResponseError
			if errors.As(err, &re) {
				*sink = re.ServiceRequestID()
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("awsio: sign: %w", err)
	}
	return out.Signature, nil
}

// DynamoAPI is the part of the DynamoDB client the claims use.
type DynamoAPI interface {
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// Claims is the claim table (GC #7406 §2): one item per slot, key `slot`,
// created only if absent and each artifact set only if unset, on an item
// that names the same digest. Reads are strongly consistent.
type Claims struct {
	Client DynamoAPI
	Table  string
}

var _ signer.Claims = (*Claims)(nil)

// Get implements signer.Claims.
func (c *Claims) Get(ctx context.Context, slot string) (*signer.Claim, error) {
	out, err := c.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(c.Table), ConsistentRead: aws.Bool(true),
		Key: map[string]ddbtypes.AttributeValue{"slot": &ddbtypes.AttributeValueMemberS{Value: slot}}})
	if err != nil {
		return nil, err
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return decodeClaim(out.Item)
}

func decodeClaim(it map[string]ddbtypes.AttributeValue) (*signer.Claim, error) {
	cl := &signer.Claim{}
	b := func(name string) []byte {
		if v, ok := it[name].(*ddbtypes.AttributeValueMemberB); ok {
			return v.Value
		}
		return nil
	}
	if v, ok := it["slot"].(*ddbtypes.AttributeValueMemberS); ok {
		cl.Slot = v.Value
	}
	if v, ok := it["request_id"].(*ddbtypes.AttributeValueMemberS); ok {
		cl.RequestID = v.Value
	}
	if v, ok := it["journaled"].(*ddbtypes.AttributeValueMemberBOOL); ok {
		cl.Journaled = v.Value
	}
	if v, ok := it["lease_until"].(*ddbtypes.AttributeValueMemberN); ok {
		if n, err := strconv.ParseInt(v.Value, 10, 64); err == nil {
			cl.LeaseUntil = time.UnixMilli(n)
		}
	}
	if v, ok := it["created"].(*ddbtypes.AttributeValueMemberN); ok {
		if n, err := strconv.ParseInt(v.Value, 10, 64); err == nil {
			cl.Created = time.Unix(n, 0)
		}
	}
	cl.Digest, cl.Sig, cl.R, cl.TSAToken = b("digest"), b("sig"), b("r"), b("tsa_token")
	if e := b("rekor_entry"); e != nil {
		cl.RekorEntry = json.RawMessage(e)
	}
	if cl.Slot == "" || len(cl.Digest) != 32 {
		return nil, errors.New("awsio: a claim without its slot or digest")
	}
	return cl, nil
}

// Create implements signer.Claims.
func (c *Claims) Create(ctx context.Context, slot string, digest []byte, at time.Time) error {
	_, err := c.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.Table),
		Item: map[string]ddbtypes.AttributeValue{
			"slot":    &ddbtypes.AttributeValueMemberS{Value: slot},
			"digest":  &ddbtypes.AttributeValueMemberB{Value: digest},
			"created": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(at.Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(slot)")})
	var ccf *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return signer.ErrExists
	}
	return err
}

// set sets fields on the slot's item, only if the item names digest (and
// r, if r isn't nil) and the first field is unset.
func (c *Claims) set(ctx context.Context, slot string, digest, r []byte, fields map[string]ddbtypes.AttributeValue, first string) error {
	names := map[string]string{"#s": "slot", "#d": "digest", "#f": first}
	values := map[string]ddbtypes.AttributeValue{":d": &ddbtypes.AttributeValueMemberB{Value: digest}}
	cond := "attribute_exists(#s) AND #d = :d AND attribute_not_exists(#f)"
	if r != nil {
		names["#r"], values[":r"] = "r", &ddbtypes.AttributeValueMemberB{Value: r}
		cond += " AND #r = :r"
	}
	expr := "SET "
	i := 0
	for name, v := range fields {
		n, p := "#n"+strconv.Itoa(i), ":v"+strconv.Itoa(i)
		names[n], values[p] = name, v
		if i > 0 {
			expr += ", "
		}
		expr += n + " = " + p
		i++
	}
	_, err := c.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(c.Table),
		Key:                       map[string]ddbtypes.AttributeValue{"slot": &ddbtypes.AttributeValueMemberS{Value: slot}},
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	var ccf *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return signer.ErrSet
	}
	return err
}

// SetSig implements signer.Claims.
func (c *Claims) SetSig(ctx context.Context, slot string, digest, sig, r []byte, requestID string) error {
	f := map[string]ddbtypes.AttributeValue{
		"sig": &ddbtypes.AttributeValueMemberB{Value: sig},
		"r":   &ddbtypes.AttributeValueMemberB{Value: r},
	}
	if requestID != "" {
		f["request_id"] = &ddbtypes.AttributeValueMemberS{Value: requestID}
	}
	return c.set(ctx, slot, digest, nil, f, "sig")
}

// Lease implements signer.Claims: lease_until (Unix milliseconds) is set
// only on a claim with no signature and no live lease.
func (c *Claims) Lease(ctx context.Context, slot string, digest []byte, until, now time.Time) error {
	_, err := c.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(c.Table),
		Key:              map[string]ddbtypes.AttributeValue{"slot": &ddbtypes.AttributeValueMemberS{Value: slot}},
		UpdateExpression: aws.String("SET #l = :until"),
		ConditionExpression: aws.String("attribute_exists(#s) AND #d = :d AND attribute_not_exists(#sig) AND " +
			"(attribute_not_exists(#l) OR #l <= :now)"),
		ExpressionAttributeNames: map[string]string{"#s": "slot", "#d": "digest", "#sig": "sig", "#l": "lease_until"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":d":     &ddbtypes.AttributeValueMemberB{Value: digest},
			":until": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(until.UnixMilli(), 10)},
			":now":   &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(now.UnixMilli(), 10)},
		},
	})
	var ccf *ddbtypes.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return signer.ErrSet
	}
	return err
}

// SetJournaled implements signer.Claims.
func (c *Claims) SetJournaled(ctx context.Context, slot string, digest, r []byte) error {
	return c.set(ctx, slot, digest, r, map[string]ddbtypes.AttributeValue{"journaled": &ddbtypes.AttributeValueMemberBOOL{Value: true}}, "journaled")
}

// SetToken implements signer.Claims.
func (c *Claims) SetToken(ctx context.Context, slot string, digest, r, token []byte) error {
	return c.set(ctx, slot, digest, r, map[string]ddbtypes.AttributeValue{"tsa_token": &ddbtypes.AttributeValueMemberB{Value: token}}, "tsa_token")
}

// SetEntry implements signer.Claims.
func (c *Claims) SetEntry(ctx context.Context, slot string, digest, r []byte, entry json.RawMessage) error {
	return c.set(ctx, slot, digest, r, map[string]ddbtypes.AttributeValue{"rekor_entry": &ddbtypes.AttributeValueMemberB{Value: entry}}, "rekor_entry")
}

// LogsAPI is the part of the CloudWatch Logs client the journal uses.
type LogsAPI interface {
	PutLogEvents(ctx context.Context, in *cloudwatchlogs.PutLogEventsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

// Journal is the signer's journal (GC #7406 §3): one JSON event per entry,
// {"kind": "sign" | "complete", ...}, in a log group and stream only the
// signer's role writes.
type Journal struct {
	Client LogsAPI
	Group  string
	Stream string
	Now    func() time.Time
}

var _ signer.Journal = (*Journal)(nil)

func (j *Journal) put(ctx context.Context, kind string, e any) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	msg := `{"kind":"` + kind + `",` + string(b[1:])
	out, err := j.Client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{LogGroupName: aws.String(j.Group),
		LogStreamName: aws.String(j.Stream),
		LogEvents:     []cwtypes.InputLogEvent{{Message: aws.String(msg), Timestamp: aws.Int64(j.Now().UnixMilli())}}})
	if err != nil {
		return err
	}
	if r := out.RejectedLogEventsInfo; r != nil {
		return errors.New("awsio: the journal rejected the entry")
	}
	return nil
}

// Sign implements signer.Journal.
func (j *Journal) Sign(ctx context.Context, e signer.SignEntry) error { return j.put(ctx, "sign", e) }

// Complete implements signer.Journal.
func (j *Journal) Complete(ctx context.Context, e signer.CompletionEntry) error {
	return j.put(ctx, "complete", e)
}

// ReadOnly is a site store that refuses every write: the signer reads the
// site's bucket and writes only through the upload API.
type ReadOnly struct{ site.Storage }

// PutOnce refuses.
func (ReadOnly) PutOnce(context.Context, string, []byte, string) error {
	return errors.New("awsio: the signer doesn't write the site's bucket")
}

// PutIf refuses.
func (ReadOnly) PutIf(context.Context, string, []byte, string, string) error {
	return errors.New("awsio: the signer doesn't write the site's bucket")
}

// Site is the votes site for the signer: its checks and its documents
// read from the bucket (no CDN cache), and uploads through its API.
type Site struct {
	Site    *site.Site // over a ReadOnly store
	API     string     // the site's base URL, https://votes.vettid.org
	Client  *http.Client
	Anchors *site.Anchors
}

var _ signer.Site = (*Site)(nil)

// Prepare implements signer.Site.
func (s *Site) Prepare(ctx context.Context, id, name string, doc, sig, rows []byte, lead time.Duration) (site.Prepared, error) {
	return s.Site.Prepare(ctx, id, name, doc, sig, rows, lead)
}

// Bundle implements signer.Site.
func (s *Site) Bundle(ctx context.Context, id, name string) ([]byte, error) {
	b, _, err := s.Site.Store.Get(ctx, "v1/p/"+id+"/"+name+".json.sigstore.json")
	if errors.Is(err, site.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Upload implements signer.Site.
func (s *Site) Upload(ctx context.Context, id, name string, u *site.Upload) (int, string, bool, error) {
	body, err := json.Marshal(u)
	if err != nil {
		return 0, "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.API+"/api/v1/p/"+id+"/"+name, bytes.NewReader(body))
	if err != nil {
		return 0, "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, "", false, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, "", false, err
	}
	var ans struct {
		Error        string `json:"error"`
		IndexUpdated bool   `json:"index_updated"`
	}
	_ = json.Unmarshal(raw, &ans)
	return resp.StatusCode, ans.Error, ans.IndexUpdated, nil
}

// Times implements signer.Site.
func (s *Site) Times(bundle, doc, spki []byte) (time.Time, time.Time, int64, error) {
	t, err := s.Anchors.VerifyTimes(bundle, doc, spki)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	var idx int64
	if t.Entry != nil {
		idx = t.Entry.LogIndex
	}
	return t.TSA, t.Rekor, idx, nil
}
