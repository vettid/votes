// Command votesctl is the operator's tool for votes.vettid.org:
//
//	votesctl site-key -secret <arn>
//	    prints the site's Ed25519 public key (base64) from its secret
//	votesctl publish-services -secret <arn> -bucket <name> -in services.json
//	    signs the service list and publishes it, if it extends the one
//	    published: a higher version, the previous one's hash, and every
//	    service, identity key and anchor key it had (BALLOT-PROTOCOL §3.3)
//
// The site's key is derived from its Secrets Manager secret as
// Ed25519(seed = SHA-256(secret string)).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/votes/site"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "site-key":
		fs := flag.NewFlagSet("site-key", flag.ExitOnError)
		secret := fs.String("secret", "", "the site key's Secrets Manager secret")
		_ = fs.Parse(os.Args[2:])
		var k ed25519.PrivateKey
		if k, err = siteKey(ctx, *secret); err == nil {
			fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		}
	case "publish-services":
		fs := flag.NewFlagSet("publish-services", flag.ExitOnError)
		secret := fs.String("secret", "", "the site key's Secrets Manager secret")
		bucket := fs.String("bucket", "", "the site's bucket")
		in := fs.String("in", "services.json", "the service list")
		_ = fs.Parse(os.Args[2:])
		err = publish(ctx, *secret, *bucket, *in)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "votesctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: votesctl site-key -secret <arn> | publish-services -secret <arn> -bucket <name> -in <file>")
	os.Exit(2)
}

func siteKey(ctx context.Context, secret string) (ed25519.PrivateKey, error) {
	if secret == "" {
		return nil, errors.New("-secret is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secret)})
	if err != nil {
		return nil, err
	}
	s := aws.ToString(out.SecretString)
	if len(s) < 32 {
		return nil, errors.New("the site key's secret is too short")
	}
	seed := sha256.Sum256([]byte(s))
	return ed25519.NewKeyFromSeed(seed[:]), nil
}

func publish(ctx context.Context, secret, bucket, in string) error {
	if bucket == "" {
		return errors.New("-bucket is required")
	}
	key, err := siteKey(ctx, secret)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	return publishList(ctx, s3.NewFromConfig(cfg), bucket, key, raw)
}

// publishList signs raw and publishes it on c's bucket (publish's work,
// apart from the key and the client).
func publishList(ctx context.Context, c *s3.Client, bucket string, key ed25519.PrivateKey, raw []byte) error {
	data, err := vote.Canonicalize(raw)
	if err != nil {
		return err
	}
	sig, err := signList(key, data)
	if err != nil {
		return err
	}
	next, err := site.ParseServiceList(data, sig, key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	cur, err := get(ctx, c, bucket, "v1/services.json")
	if err != nil {
		return err
	}
	curSig, err := get(ctx, c, bucket, "v1/services.json.sig")
	if err != nil {
		return err
	}
	// Both objects are written conditionally, the signature first, so two
	// publishes can't interleave; one that stopped between the two writes
	// is finished by running it again with the same file.
	resuming := curSig.data != nil && bytes.Equal(curSig.data, sig)
	switch {
	case cur.data == nil && curSig.data == nil:
		if next.Version != 1 || !bytes.Equal(next.Previous, make([]byte, 32)) {
			return errors.New("the first list is version 1 with an all-zero previous")
		}
	case resuming && (cur.data == nil || bytes.Equal(next.Previous, sum(cur.data))):
		// An interrupted publish of this same list: only the list is left.
	case cur.data == nil || curSig.data == nil:
		return errors.New("the bucket holds a service list or a signature without the other: restore the pair from the bucket's object versions")
	default:
		prev, err := site.ParseServiceList(cur.data, curSig.data, pub)
		if err != nil {
			return fmt.Errorf("the published list doesn't verify (%w): restore the pair from the bucket's object versions", err)
		}
		if err := site.Extends(prev, cur.data, next); err != nil {
			return err
		}
	}
	if !resuming {
		if err := put(ctx, c, bucket, "v1/services.json.sig", sig, "application/octet-stream", curSig.tag); err != nil {
			return err
		}
	}
	if err := put(ctx, c, bucket, "v1/services.json", data, "application/json", cur.tag); err != nil {
		return err
	}
	fmt.Printf("published service list version %d (%d services)\n", next.Version, len(next.Services))
	return nil
}

type object struct {
	data []byte
	tag  string // its ETag, or "" when absent
}

func get(ctx context.Context, c *s3.Client, bucket, key string) (object, error) {
	o, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		var nf interface{ ErrorCode() string }
		if errors.As(err, &nf) && nf.ErrorCode() == "NoSuchKey" {
			return object{}, nil
		}
		return object{}, err
	}
	defer o.Body.Close()
	var b bytes.Buffer
	if _, err := b.ReadFrom(o.Body); err != nil {
		return object{}, err
	}
	return object{data: b.Bytes(), tag: aws.ToString(o.ETag)}, nil
}

// put replaces an object only if it is still the version read (tag), or
// writes it only if there was none ("").
func put(ctx context.Context, c *s3.Client, bucket, key string, data []byte, ct, tag string) error {
	in := &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data),
		// Short: a reader may meet the new list beside the old signature
		// for this long, and retries.
		ContentType: aws.String(ct), CacheControl: aws.String("public, max-age=10")}
	if tag == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(tag)
	}
	if _, err := c.PutObject(ctx, in); err != nil {
		return fmt.Errorf("%s changed while publishing (another publish?): %w", key, err)
	}
	return nil
}

// signList is the site's signature of a list's bytes (BALLOT-PROTOCOL
// §3.3).
func signList(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	return suite.Sign(key, vote.LabelServiceList, sum(data))
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
