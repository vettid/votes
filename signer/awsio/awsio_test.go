package awsio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmw "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/vettid/votes/signer"
	"github.com/vettid/votes/site"
)

type fakeKMS struct {
	spec  kmstypes.KeySpec
	usage kmstypes.KeyUsageType
	key   *ecdsa.PrivateKey
	in    *kms.SignInput
	fail  bool
}

func (f *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	return &kms.GetPublicKeyOutput{KeySpec: f.spec, KeyUsage: f.usage, PublicKey: der}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.in = in
	if f.fail {
		return nil, &awshttp.ResponseError{RequestID: "req-failed",
			ResponseError: &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 400}}, Err: errors.New("denied")}}
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, in.Message)
	out := &kms.SignOutput{Signature: sig}
	awsmw.SetRequestIDMetadata(&out.ResultMetadata, "req-ok")
	return out, err
}

func TestKeyUnit(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeKMS{spec: kmstypes.KeySpecEccNistP256, usage: kmstypes.KeyUsageTypeSignVerify, key: k}
	key, err := NewKey(context.Background(), f, "key-1")
	if err != nil || !key.Public().Equal(&k.PublicKey) {
		t.Fatal(err)
	}
	var id string
	d := make([]byte, 32)
	if _, err := key.SignDigest(signer.WithRequestIDSink(context.Background(), &id), d); err != nil || id != "req-ok" {
		t.Fatalf("%v %q", err, id)
	}
	if f.in.MessageType != kmstypes.MessageTypeDigest || f.in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || *f.in.KeyId != "key-1" {
		t.Fatalf("%+v", f.in)
	}
	f.fail = true
	if _, err := key.SignDigest(signer.WithRequestIDSink(context.Background(), &id), d); err == nil || id != "req-failed" {
		t.Fatalf("%v %q", err, id)
	}
	for _, bad := range []*fakeKMS{
		{spec: kmstypes.KeySpecEccNistP384, usage: kmstypes.KeyUsageTypeSignVerify, key: k},
		{spec: kmstypes.KeySpecEccNistP256, usage: kmstypes.KeyUsageTypeEncryptDecrypt, key: k},
	} {
		if _, err := NewKey(context.Background(), bad, "key-2"); err == nil {
			t.Fatalf("%s %s taken", bad.spec, bad.usage)
		}
	}
}

type fakeDynamo struct {
	put    *dynamodb.PutItemInput
	update *dynamodb.UpdateItemInput
	err    error
}

func (f *fakeDynamo) GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.put = in
	return &dynamodb.PutItemOutput{}, f.err
}

func (f *fakeDynamo) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.update = in
	return &dynamodb.UpdateItemOutput{}, f.err
}

// The conditions the table is asked for, and how a failed one is told.
func TestClaimsUnit(t *testing.T) {
	f := &fakeDynamo{}
	c := &Claims{Client: f, Table: "claims"}
	ctx := context.Background()
	if err := c.Create(ctx, "s", make([]byte, 32), time.Unix(5, 0)); err != nil || *f.put.ConditionExpression != "attribute_not_exists(slot)" {
		t.Fatalf("%v %+v", err, f.put)
	}
	if err := c.SetSig(ctx, "s", make([]byte, 32), []byte("sig"), []byte{1}, "req"); err != nil {
		t.Fatal(err)
	}
	if *f.update.ConditionExpression != "attribute_exists(#s) AND #d = :d AND attribute_not_exists(#f)" || f.update.ExpressionAttributeNames["#r"] != "" ||
		f.update.ExpressionAttributeNames["#f"] != "sig" || len(f.update.ExpressionAttributeValues) != 4 {
		t.Fatalf("%+v", f.update)
	}
	if err := c.SetEntry(ctx, "s", make([]byte, 32), []byte{1}, []byte("{}")); err != nil ||
		*f.update.ConditionExpression != "attribute_exists(#s) AND #d = :d AND attribute_not_exists(#f) AND #r = :r" {
		t.Fatalf("%v %+v", err, f.update)
	}
	if err := c.Lease(ctx, "s", make([]byte, 32), time.Unix(9, 0), time.Unix(8, 0)); err != nil ||
		f.update.ExpressionAttributeValues[":now"].(*ddbtypes.AttributeValueMemberN).Value != "8000" {
		t.Fatalf("%v %+v", err, f.update)
	}
	f.err = &ddbtypes.ConditionalCheckFailedException{}
	if err := c.Lease(ctx, "s", make([]byte, 32), time.Unix(9, 0), time.Unix(8, 0)); !errors.Is(err, signer.ErrSet) {
		t.Fatal(err)
	}
	if err := c.Create(ctx, "s", make([]byte, 32), time.Unix(5, 0)); !errors.Is(err, signer.ErrExists) {
		t.Fatal(err)
	}
	if err := c.SetToken(ctx, "s", make([]byte, 32), []byte{1}, []byte("t")); !errors.Is(err, signer.ErrSet) {
		t.Fatal(err)
	}
	if got, err := c.Get(ctx, "s"); got != nil || err != nil {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := decodeClaim(map[string]ddbtypes.AttributeValue{"slot": &ddbtypes.AttributeValueMemberS{Value: "s"}}); err == nil {
		t.Fatal("a claim without a digest decoded")
	}
}

type fakeLogs struct{ msgs []string }

func (f *fakeLogs) PutLogEvents(_ context.Context, in *cloudwatchlogs.PutLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	f.msgs = append(f.msgs, *in.LogEvents[0].Message)
	return &cloudwatchlogs.PutLogEventsOutput{}, nil
}

func TestJournalUnit(t *testing.T) {
	f := &fakeLogs{}
	j := &Journal{Client: f, Group: "g", Stream: "s", Now: time.Now}
	if err := j.Sign(context.Background(), signer.SignEntry{ProposalID: "p", Digest: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(f.msgs[0]), &m); err != nil || m["kind"] != "sign" || m["proposal_id"] != "p" {
		t.Fatalf("%s %v", f.msgs[0], err)
	}
}

// The upload goes to the site's API, and its answer is read.
func TestUpload(t *testing.T) {
	var path string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, body = r.URL.Path, must(io.ReadAll(r.Body))
		if strings.HasSuffix(path, "/results") {
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"error":"too_early"}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"published":"proposal","index_updated":true}`)
	}))
	defer srv.Close()
	s := &Site{API: srv.URL, Client: srv.Client()}
	st, code, idx, err := s.Upload(context.Background(), "id", "proposal", &site.Upload{Doc: []byte("d"), Sig: []byte("s"), Bundle: json.RawMessage(`{}`)})
	if err != nil || st != 201 || code != "" || !idx || path != "/api/v1/p/id/proposal" {
		t.Fatalf("%d %q %v %v %s", st, code, idx, err, path)
	}
	var u site.Upload
	if err := json.Unmarshal(body, &u); err != nil || string(u.Doc) != "d" {
		t.Fatalf("%s %v", body, err)
	}
	if st, code, _, _ := s.Upload(context.Background(), "id", "results", &site.Upload{}); st != 422 || code != "too_early" {
		t.Fatalf("%d %q", st, code)
	}
	if (ReadOnly{}).PutOnce(context.Background(), "x", nil, "") == nil || (ReadOnly{}).PutIf(context.Background(), "x", nil, "", "") == nil {
		t.Fatal("the read-only store wrote")
	}
	_ = aws.String
}

func must[T any](v T, _ error) T { return v }
