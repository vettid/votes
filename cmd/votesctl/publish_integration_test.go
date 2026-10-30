//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/votes/site"
)

// publish-services against LocalStack (VOTES_IT_LOCALSTACK): a first
// list, a next one, an interrupted publish finished by a rerun, and the
// refusals.
func TestPublishServices(t *testing.T) {
	ep := os.Getenv("VOTES_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("set VOTES_IT_LOCALSTACK")
	}
	ctx := context.Background()
	c := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(ep), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})
	bucket := fmt.Sprintf("votesctl-it-%d", time.Now().UnixNano())
	if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("votesctl test site key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	ik := bytes.Repeat([]byte{3}, 32)
	list := func(version int64, previous []byte, services ...site.Service) []byte {
		if services == nil {
			services = []site.Service{}
		}
		b, _ := json.Marshal(&site.ServiceList{V: 1, Version: version, Previous: previous, Services: services})
		b, _ = vote.Canonicalize(b)
		return b
	}
	svc := site.Service{ServiceID: site.ServiceID(ik), Name: "A", IKs: [][]byte{ik}, AnchorKeys: []site.AnchorKey{}}
	v1 := list(1, make([]byte, 32), svc)
	if err := publishList(ctx, c, bucket, key, list(2, make([]byte, 32), svc)); err == nil {
		t.Fatal("a first list that isn't version 1")
	}
	if err := publishList(ctx, c, bucket, key, v1); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(v1)
	ik2 := bytes.Repeat([]byte{4}, 32)
	v2 := list(2, h[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "B", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if err := publishList(ctx, c, bucket, key, list(2, h[:])); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("a list that drops a service: %v", err)
	}

	// Interrupted after the signature: the rerun finishes it.
	data, _ := vote.Canonicalize(v2)
	sig, _ := signList(key, data)
	cur, _ := get(ctx, c, bucket, "v1/services.json.sig")
	if err := put(ctx, c, bucket, "v1/services.json.sig", sig, "application/octet-stream", cur.tag); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, c, bucket, key, v2); err != nil {
		t.Fatalf("finishing the interrupted publish: %v", err)
	}
	got, _ := get(ctx, c, bucket, "v1/services.json")
	gotSig, _ := get(ctx, c, bucket, "v1/services.json.sig")
	if _, err := site.ParseServiceList(got.data, gotSig.data, key.Public().(ed25519.PublicKey)); err != nil || !bytes.Equal(got.data, data) {
		t.Fatalf("the published pair: %v", err)
	}

	// Every version is kept, write-once, beside the current list.
	kept := func(version int64, want []byte) {
		t.Helper()
		d, _ := get(ctx, c, bucket, fmt.Sprintf("v1/services/%d.json", version))
		sg, _ := get(ctx, c, bucket, fmt.Sprintf("v1/services/%d.json.sig", version))
		if !bytes.Equal(d.data, want) {
			t.Fatalf("version %d's history", version)
		}
		if _, err := site.ParseServiceList(d.data, sg.data, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatalf("version %d's history: %v", version, err)
		}
	}
	kept(1, v1)
	kept(2, data)
	// The current list again: its history is written if missing.
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("v1/services/2.json")}); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, c, bucket, key, v2); err != nil {
		t.Fatalf("the current list again: %v", err)
	}
	kept(2, data)
	// A version's history is never rewritten: the publish stops before
	// the current list moves.
	h2 := sha256.Sum256(data)
	v3 := list(3, h2[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "B2", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if err := put(ctx, c, bucket, "v1/services/3.json.sig", []byte("other"), "application/octet-stream", ""); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, c, bucket, key, v3); err == nil || !strings.Contains(err.Error(), "other bytes") {
		t.Fatalf("over another version 3: %v", err)
	}
	if got, _ := get(ctx, c, bucket, "v1/services.json"); !bytes.Equal(got.data, data) {
		t.Fatal("the current list moved")
	}

	// A stale write is refused: another publish moved the list.
	if err := put(ctx, c, bucket, "v1/services.json", v1, "application/json", cur.tag); err == nil {
		t.Fatal("a write over a stale tag")
	}

	// A list with no signature is a broken bucket, not a first publish.
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("v1/services.json.sig")}); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, c, bucket, key, v1); err == nil || !strings.Contains(err.Error(), "without the other") {
		t.Fatalf("a list without its signature: %v", err)
	}
}
