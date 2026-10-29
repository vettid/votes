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
	data, err := vote.Canonicalize(raw)
	if err != nil {
		return err
	}
	sig, err := suite.Sign(key, vote.LabelServiceList, sum(data))
	if err != nil {
		return err
	}
	next, err := site.ParseServiceList(data, sig, key.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	c := s3.NewFromConfig(cfg)
	prevData, prevSig, err := get(ctx, c, bucket)
	if err != nil {
		return err
	}
	if prevData != nil {
		prev, err := site.ParseServiceList(prevData, prevSig, key.Public().(ed25519.PublicKey))
		if err != nil {
			return fmt.Errorf("the published list: %w", err)
		}
		if err := site.Extends(prev, prevData, next); err != nil {
			return err
		}
	} else if next.Version != 1 || !bytes.Equal(next.Previous, make([]byte, 32)) {
		return errors.New("the first list is version 1 with an all-zero previous")
	}
	// The signature first: a reader that finds the new list finds its
	// signature (an old list with a new signature fails, and is retried).
	for _, o := range []struct {
		key  string
		data []byte
		ct   string
	}{{"v1/services.json.sig", sig, "application/octet-stream"}, {"v1/services.json", data, "application/json"}} {
		if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(o.key), Body: bytes.NewReader(o.data),
			ContentType: aws.String(o.ct), CacheControl: aws.String("public, max-age=300")}); err != nil {
			return err
		}
	}
	fmt.Printf("published service list version %d (%d services)\n", next.Version, len(next.Services))
	return nil
}

func get(ctx context.Context, c *s3.Client, bucket string) ([]byte, []byte, error) {
	var out [2][]byte
	for i, k := range []string{"v1/services.json", "v1/services.json.sig"} {
		o, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(k)})
		if err != nil {
			var nf interface{ ErrorCode() string }
			if errors.As(err, &nf) && nf.ErrorCode() == "NoSuchKey" {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		var b bytes.Buffer
		_, err = b.ReadFrom(o.Body)
		o.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		out[i] = b.Bytes()
	}
	return out[0], out[1], nil
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
