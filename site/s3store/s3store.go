// Package s3store is the site's Storage on S3: write-once with
// If-None-Match: *, and the index replaced with If-Match on its ETag (S3's
// conditional writes), so two uploads at once can't both win.
package s3store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/vettid/votes/site"
)

// Store is a bucket.
type Store struct {
	Client *s3.Client
	Bucket string
}

var _ site.Storage = (*Store)(nil)

// maxObject bounds a read: the largest object the site writes is rows,
// within Lambda's 6 MB request.
const maxObject = 8 << 20

// Cache-Control by kind (docs/VOTES-SITE.md §3): documents are immutable;
// the index and archive change.
func cacheControl(path string) string {
	if strings.HasPrefix(path, "v1/p/") {
		return "public, max-age=31536000, immutable"
	}
	return "public, max-age=60"
}

// Get implements site.Storage.
func (s *Store) Get(ctx context.Context, path string) ([]byte, string, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(path)})
	if err != nil {
		if code(err) == "NoSuchKey" {
			return nil, "", site.ErrNotExist
		}
		return nil, "", err
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, maxObject+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxObject {
		return nil, "", errors.New("s3store: object too large")
	}
	return b, aws.ToString(out.ETag), nil
}

// PutOnce implements site.Storage.
func (s *Store) PutOnce(ctx context.Context, path string, data []byte, contentType string) error {
	_, err := s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(path),
		Body: bytes.NewReader(data), ContentType: aws.String(contentType), CacheControl: aws.String(cacheControl(path)),
		IfNoneMatch: aws.String("*")})
	switch c := code(err); {
	case err == nil:
		return nil
	case c == "PreconditionFailed" || c == "ConditionalRequestConflict":
		return site.ErrExists
	default:
		return err
	}
}

// PutIf implements site.Storage.
func (s *Store) PutIf(ctx context.Context, path string, data []byte, contentType, tag string) error {
	in := &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(path),
		Body: bytes.NewReader(data), ContentType: aws.String(contentType), CacheControl: aws.String(cacheControl(path))}
	if tag == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(tag)
	}
	_, err := s.Client.PutObject(ctx, in)
	switch c := code(err); {
	case err == nil:
		return nil
	case c == "PreconditionFailed" || c == "ConditionalRequestConflict" || c == "NoSuchKey":
		return site.ErrChanged
	default:
		return err
	}
}

func code(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}
