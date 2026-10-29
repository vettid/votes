//go:build integration

package s3store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/votes/site"
)

// S3's conditional writes, against LocalStack (VOTES_IT_LOCALSTACK): an
// object is written once, and of uploads racing to write it exactly one
// wins; the index is replaced only over the version read.
func TestConditionalWrites(t *testing.T) {
	ep := os.Getenv("VOTES_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("set VOTES_IT_LOCALSTACK")
	}
	ctx := context.Background()
	c := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(ep), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})
	if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("votes-it")}); err != nil {
		t.Fatal(err)
	}
	st := &Store{Client: c, Bucket: "votes-it"}
	if _, _, err := st.Get(ctx, "v1/p/x/proposal.json"); !errors.Is(err, site.ErrNotExist) {
		t.Fatalf("a missing object: %v", err)
	}
	var wins, losses int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.PutOnce(ctx, "v1/p/x/proposal.json", []byte{byte(i)}, "application/json")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, site.ErrExists):
				losses++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || losses != 7 {
		t.Fatalf("%d writes won, %d lost", wins, losses)
	}
	if err := st.PutIf(ctx, "v1/index.json", []byte("[1]"), "application/json", ""); err != nil {
		t.Fatal(err)
	}
	_, tag, err := st.Get(ctx, "v1/index.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutIf(ctx, "v1/index.json", []byte("[1,2]"), "application/json", tag); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIf(ctx, "v1/index.json", []byte("[stale]"), "application/json", tag); !errors.Is(err, site.ErrChanged) {
		t.Fatalf("a write over a stale tag: %v", err)
	}
	if err := st.PutIf(ctx, "v1/index.json", []byte("[new]"), "application/json", ""); !errors.Is(err, site.ErrChanged) {
		t.Fatalf("a first write over an existing index: %v", err)
	}
}
