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
	// No copy of a version that has not been the current list: a copy is
	// written only after the move (VOTES-SITE §3).
	noCopy := func(version int64, when string) {
		t.Helper()
		for _, k := range []string{fmt.Sprintf("v1/services/%d.json", version), fmt.Sprintf("v1/services/%d.json.sig", version)} {
			if got, _ := get(ctx, c, bucket, k); got.data != nil {
				t.Fatalf("%s: %s exists", when, k)
			}
		}
	}
	if err := publishList(ctx, c, bucket, key, list(2, make([]byte, 32), svc)); err == nil {
		t.Fatal("a first list that isn't version 1")
	}
	if err := publishList(ctx, c, bucket, key, v1); err != nil {
		t.Fatal(err)
	}
	// Both written by publishList: the current pair is cached briefly, so
	// a reader that met a list and a signature of different versions gets
	// the matching pair on a retry; the copies never change (VOTES-SITE §3).
	for k, want := range map[string]string{
		"v1/services.json":       "public, max-age=10",
		"v1/services.json.sig":   "public, max-age=10",
		"v1/services/1.json":     "public, max-age=31536000, immutable",
		"v1/services/1.json.sig": "public, max-age=31536000, immutable",
	} {
		o, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(k)})
		if err != nil || aws.ToString(o.CacheControl) != want {
			t.Fatalf("%s: Cache-Control %q (%v), want %q", k, aws.ToString(o.CacheControl), err, want)
		}
	}
	h := sha256.Sum256(v1)
	ik2 := bytes.Repeat([]byte{4}, 32)
	v2 := list(2, h[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "B", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if err := publishList(ctx, c, bucket, key, list(2, h[:])); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("a list that drops a service: %v", err)
	}
	noCopy(2, "a list refused by Extends")

	// Interrupted after the signature: the rerun finishes it.
	data, _ := vote.Canonicalize(v2)
	sig, _ := signList(key, data)
	cur, _ := get(ctx, c, bucket, "v1/services.json.sig")
	if err := put(ctx, c, bucket, "v1/services.json.sig", sig, "application/octet-stream", cur.tag); err != nil {
		t.Fatal(err)
	}
	// Another list over the interrupted one is refused: the pair doesn't
	// verify, and neither list gets a copy.
	other := list(2, h[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "C", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if err := publishList(ctx, c, bucket, key, other); err == nil || !strings.Contains(err.Error(), "doesn't verify") {
		t.Fatalf("another list over an interrupted publish: %v", err)
	}
	noCopy(2, "another list over an interrupted publish")
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
	if got, _ := get(ctx, c, bucket, "v1/services/3.json"); got.data != nil {
		t.Fatal("a copy of a list that was never current")
	}
	// Versions are consecutive.
	v4 := list(4, h2[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "B2", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if err := publishList(ctx, c, bucket, key, v4); err == nil || !strings.Contains(err.Error(), "next version is 3") {
		t.Fatalf("a version gap: %v", err)
	}
	noCopy(4, "a version gap")
	// A move that loses a race after every check passed: another
	// publisher replaced the signature. The list stays where it was, and
	// the version that didn't become current gets no copy.
	v3ok := list(3, h2[:], svc, site.Service{ServiceID: site.ServiceID(ik2), Name: "B3", IKs: [][]byte{ik2}, AnchorKeys: []site.AnchorKey{}})
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("v1/services/3.json.sig")}); err != nil {
		t.Fatal(err)
	}
	held, _ := get(ctx, c, bucket, "v1/services.json.sig")
	ran := false
	t.Cleanup(func() { beforeMove = func() {} })
	beforeMove = func() {
		ran = true
		if err := put(ctx, c, bucket, "v1/services.json.sig", []byte("another publisher"), "application/octet-stream", held.tag); err != nil {
			t.Fatal(err)
		}
	}
	err := publishList(ctx, c, bucket, key, v3ok)
	beforeMove = func() {}
	if !ran || err == nil || !strings.Contains(err.Error(), "changed while publishing") {
		t.Fatalf("a move over a signature that changed (hook ran: %v): %v", ran, err)
	}
	if got, _ := get(ctx, c, bucket, "v1/services.json"); !bytes.Equal(got.data, data) {
		t.Fatal("the current list moved")
	}
	noCopy(3, "a move that lost a race")
	raced, _ := get(ctx, c, bucket, "v1/services.json.sig")
	if err := put(ctx, c, bucket, "v1/services.json.sig", held.data, "application/octet-stream", raced.tag); err != nil {
		t.Fatal(err)
	}
	// A missing signature copy of the current list is restored too.
	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("v1/services/2.json.sig")}); err != nil {
		t.Fatal(err)
	}
	if err := publishList(ctx, c, bucket, key, v2); err != nil {
		t.Fatal(err)
	}
	kept(2, data)

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
