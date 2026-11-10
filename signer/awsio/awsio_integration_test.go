//go:build integration

package awsio

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/vettid/votes/signer"
)

// endpoint is LocalStack's (VOTES_IT_LOCALSTACK).
func endpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("VOTES_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("set VOTES_IT_LOCALSTACK")
	}
	return ep
}

var creds = credentials.NewStaticCredentialsProvider("test", "test", "")

// The claim table's conditions against DynamoDB: a slot is claimed once,
// of two racing creates exactly one wins, each artifact is set once and
// only on the claim of the same digest.
func TestClaims(t *testing.T) {
	ep := endpoint(t)
	ctx := context.Background()
	c := dynamodb.New(dynamodb.Options{Region: "us-east-1", BaseEndpoint: aws.String(ep), Credentials: creds})
	table := fmt.Sprintf("claims-it-%d", time.Now().UnixNano())
	if _, err := c.CreateTable(ctx, &dynamodb.CreateTableInput{TableName: aws.String(table), BillingMode: ddbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []ddbtypes.AttributeDefinition{{AttributeName: aws.String("slot"), AttributeType: ddbtypes.ScalarAttributeTypeS}},
		KeySchema:            []ddbtypes.KeySchemaElement{{AttributeName: aws.String("slot"), KeyType: ddbtypes.KeyTypeHash}}}); err != nil {
		t.Fatal(err)
	}
	cl := &Claims{Client: c, Table: table}
	d := sha256.Sum256([]byte("doc"))
	other := sha256.Sum256([]byte("other"))
	slot := "01KC0000000000000000000001/proposal"
	if got, err := cl.Get(ctx, slot); err != nil || got != nil {
		t.Fatalf("an empty table: %+v %v", got, err)
	}
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cl.Create(ctx, slot, d[:], time.Unix(100, 0))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, signer.ErrExists):
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d creates won", wins)
	}
	if err := cl.SetSig(ctx, slot, other[:], []byte("sig"), []byte{1}, "req"); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a set on another digest's claim: %v", err)
	}
	if err := cl.SetSig(ctx, "nobody/proposal", d[:], []byte("sig"), []byte{1}, "req"); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a set on no claim: %v", err)
	}
	// The lease: refused while live, taken again once it has passed, and
	// never once a signature is kept; nothing is set before the signature.
	now := time.Unix(1000, 0)
	if err := cl.Lease(ctx, slot, d[:], "a1", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := cl.Lease(ctx, slot, d[:], "a1", now.Add(2*time.Minute), now.Add(time.Second)); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a live lease taken again: %v", err)
	}
	if err := cl.Lease(ctx, slot, d[:], "a1", now.Add(3*time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatalf("a passed lease: %v", err)
	}
	if err := cl.SetToken(ctx, slot, d[:], []byte{1}, []byte("early")); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a token before the signature: %v", err)
	}
	steps := []func() error{
		func() error { return cl.SetSig(ctx, slot, d[:], []byte("sig"), []byte{1}, "req-1") },
		func() error { return cl.SetJournaled(ctx, slot, d[:], []byte{1}) },
		func() error { return cl.SetToken(ctx, slot, d[:], []byte{1}, []byte("token")) },
		func() error { return cl.ReplaceToken(ctx, slot, d[:], []byte{1}, []byte("token"), []byte("token2")) },
		func() error { return cl.SetEnterAttempted(ctx, slot, d[:], []byte{1}) },
		func() error { return cl.SetEntry(ctx, slot, d[:], []byte{1}, []byte(`{"logIndex":"7"}`)) },
	}
	for i, f := range steps {
		if err := f(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if err := f(); !errors.Is(err, signer.ErrSet) {
			t.Fatalf("step %d again: %v", i, err)
		}
	}
	if err := cl.Lease(ctx, slot, d[:], "a1", now.Add(time.Hour), now.Add(time.Hour)); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a lease after the signature: %v", err)
	}
	// The token is never replaced once an entry is attempted.
	if err := cl.ReplaceToken(ctx, slot, d[:], []byte{1}, []byte("token2"), []byte("token3")); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("a token replaced after the attempt: %v", err)
	}
	if err := cl.SetEntry(ctx, "x", d[:], []byte{2}, []byte("{}")); !errors.Is(err, signer.ErrSet) {
		t.Fatalf("no claim: %v", err)
	}
	got, err := cl.Get(ctx, slot)
	if err != nil || string(got.Sig) != "sig" || got.RequestID != "req-1" || !got.Journaled || string(got.TSAToken) != "token2" || !got.EnterAttempted || got.LeaseOwner != "a1" ||
		string(got.RekorEntry) != `{"logIndex":"7"}` || got.Created.Unix() != 100 || string(got.Digest) != string(d[:]) {
		t.Fatalf("%+v %v", got, err)
	}
}

// The key signs digests in KMS, and the signature verifies under the key
// it read; the request id is recorded.
func TestKey(t *testing.T) {
	ep := endpoint(t)
	ctx := context.Background()
	c := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(ep), Credentials: creds})
	k, err := c.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: kmstypes.KeySpecEccNistP256, KeyUsage: kmstypes.KeyUsageTypeSignVerify})
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(ctx, c, *k.KeyMetadata.KeyId)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("doc"))
	var id string
	sctx := signer.WithRequestIDSink(ctx, &id)
	sig, err := key.SignDigest(sctx, d[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(key.Public(), d[:], sig) {
		t.Fatal("the signature doesn't verify")
	}
	if id == "" {
		t.Fatal("no request id recorded")
	}
	enc, err := c.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKey(ctx, c, *enc.KeyMetadata.KeyId); err == nil {
		t.Fatal("an encryption key was taken")
	}
}

// The journal writes both kinds of entry.
func TestJournal(t *testing.T) {
	ep := endpoint(t)
	ctx := context.Background()
	c := cloudwatchlogs.New(cloudwatchlogs.Options{Region: "us-east-1", BaseEndpoint: aws.String(ep), Credentials: creds})
	group := fmt.Sprintf("journal-it-%d", time.Now().UnixNano())
	if _, err := c.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{LogGroupName: aws.String(group)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{LogGroupName: aws.String(group), LogStreamName: aws.String("signs")}); err != nil {
		t.Fatal(err)
	}
	j := &Journal{Client: c, Group: group, Stream: "signs", Now: time.Now}
	if err := j.Sign(ctx, signer.SignEntry{ProposalID: "p", Name: "proposal", Digest: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := j.Complete(ctx, signer.CompletionEntry{ProposalID: "p", Name: "proposal", SiteStatus: 201}); err != nil {
		t.Fatal(err)
	}
	out, err := c.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(group), LogStreamName: aws.String("signs"),
		StartFromHead: aws.Bool(true)})
	if err != nil || len(out.Events) != 2 {
		t.Fatalf("%v %v", out, err)
	}
	for i, kind := range []string{`{"kind":"sign",`, `{"kind":"complete",`} {
		if m := *out.Events[i].Message; len(m) < len(kind) || m[:len(kind)] != kind {
			t.Fatalf("entry %d: %s", i, m)
		}
	}
}
