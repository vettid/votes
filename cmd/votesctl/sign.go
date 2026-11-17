package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/vettid/service-vault/vote"
)

// listSigner signs the service list (BALLOT-PROTOCOL §3.3): with the site
// key in KMS, which can't be exported and which only the publish role may
// use (kmsSigner, VOTE-SITE-KEY-COMPROMISE §6), or, until the staging
// flag day, with the key derived from the Secrets Manager secret
// (secretSigner).
type listSigner interface {
	Public() ed25519.PublicKey
	// Sign returns an Ed25519 signature of msg (pure Ed25519, as
	// suite.Sign makes it), one that verifies under Public.
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// secretSigner is the key derived from the secret (siteKey).
type secretSigner ed25519.PrivateKey

func (s secretSigner) Public() ed25519.PublicKey {
	return ed25519.PrivateKey(s).Public().(ed25519.PublicKey)
}

func (s secretSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(s), msg), nil
}

// kmsAPI is the part of the KMS client a kmsSigner uses.
type kmsAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// kmsKeyARN is a KMS key's ARN: never an alias (which an administrator
// could point at another key) or a bare key id.
var kmsKeyARN = regexp.MustCompile(`^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

// kmsPublicKey reads the site key's public key from KMS, after checking
// that key is an Ed25519 signing key that signs with ED25519_SHA_512.
func kmsPublicKey(ctx context.Context, c kmsAPI, key string) (ed25519.PublicKey, error) {
	if !kmsKeyARN.MatchString(key) {
		return nil, errors.New("-kms takes the site key's ARN (arn:aws:kms:<region>:<account>:key/<id>, the stack's SiteSigningKeyArn), not an alias or a key id")
	}
	out, err := c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("reading the site key's public key: %w", err)
	}
	switch {
	case aws.ToString(out.KeyId) != key:
		return nil, fmt.Errorf("KMS answered for key %q, not %q", aws.ToString(out.KeyId), key)
	case out.KeySpec != kmstypes.KeySpecEccNistEdwards25519:
		return nil, fmt.Errorf("the site key is %s, not ECC_NIST_EDWARDS25519", out.KeySpec)
	case out.KeyUsage != kmstypes.KeyUsageTypeSignVerify:
		return nil, fmt.Errorf("the site key is for %s, not SIGN_VERIFY", out.KeyUsage)
	case !slices.Contains(out.SigningAlgorithms, kmstypes.SigningAlgorithmSpecEd25519Sha512):
		return nil, errors.New("the site key doesn't sign with ED25519_SHA_512")
	}
	pk, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the site key's public key: %w", err)
	}
	pub, ok := pk.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("the site key's public key is not Ed25519")
	}
	return pub, nil
}

// kmsSigner signs with the site key in KMS. Every signature is checked
// under the expected public key before it is returned: a signature that
// doesn't verify (another key behind the ARN, a fault) is an error, and
// nothing is written.
type kmsSigner struct {
	c   kmsAPI
	key string
	pub ed25519.PublicKey
}

// newKMSSigner checks the key (kmsPublicKey) and that its public key is
// expect, the site key the vaults and the site pin.
func newKMSSigner(ctx context.Context, c kmsAPI, key string, expect ed25519.PublicKey) (*kmsSigner, error) {
	if len(expect) != ed25519.PublicKeySize {
		return nil, errors.New("-site-key (the site's public key, base64) is required with -kms")
	}
	pub, err := kmsPublicKey(ctx, c, key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pub, expect) {
		return nil, errors.New("the KMS key's public key is not -site-key: refusing to sign")
	}
	return &kmsSigner{c: c, key: key, pub: pub}, nil
}

func (k *kmsSigner) Public() ed25519.PublicKey { return k.pub }

// noRetry makes one attempt: each signature is emailed (README "The
// watch"), so a publish signs once, or fails and is run again.
func noRetry(o *kms.Options) { o.RetryMaxAttempts = 1 }

func (k *kmsSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	out, err := k.c.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(k.key),
		Message:          msg,
		MessageType:      kmstypes.MessageTypeRaw, // pure Ed25519 over msg, as suite.Sign
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEd25519Sha512,
	}, noRetry)
	if err != nil {
		return nil, fmt.Errorf("signing with the site key: %w", err)
	}
	switch {
	case aws.ToString(out.KeyId) != k.key:
		return nil, fmt.Errorf("KMS signed with key %q, not %q", aws.ToString(out.KeyId), k.key)
	case out.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEd25519Sha512:
		return nil, fmt.Errorf("KMS signed with %s, not ED25519_SHA_512", out.SigningAlgorithm)
	case len(out.Signature) != ed25519.SignatureSize || !ed25519.Verify(k.pub, msg, out.Signature):
		return nil, errors.New("KMS returned a signature that doesn't verify under the site key: nothing written")
	}
	return out.Signature, nil
}

// signList is the site's signature of a list's bytes (BALLOT-PROTOCOL
// §3.3): Ed25519 over label ‖ SHA-256(data), as suite.Sign makes it,
// checked as the site and the vaults check it before it is used.
func signList(ctx context.Context, s listSigner, data []byte) ([]byte, error) {
	msg := append([]byte(vote.LabelServiceList), sum(data)...)
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		return nil, err
	}
	if err := vote.Verify(s.Public(), vote.LabelServiceList, sum(data), sig); err != nil {
		return nil, errors.New("the list's signature doesn't verify: nothing written")
	}
	return sig, nil
}

// snsAPI is the part of the SNS client the watch check uses.
type snsAPI interface {
	ListSubscriptionsByTopic(context.Context, *sns.ListSubscriptionsByTopicInput, ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error)
	GetSubscriptionAttributes(context.Context, *sns.GetSubscriptionAttributesInput, ...func(*sns.Options)) (*sns.GetSubscriptionAttributesOutput, error)
}

var (
	snsTopicARN = regexp.MustCompile(`^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$`)
	subID       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// watchPair reports whether a and b are a stack's two key watch topics:
// SNS topic ARNs <prefix>-key-watch and <prefix>-key-watch-b.
func watchPair(a, b string) bool {
	return snsTopicARN.MatchString(a) && strings.HasSuffix(a, "-key-watch") && b == a+"-b"
}

// confirmedSub reports whether arn is a confirmed subscription of topic.
func confirmedSub(topic, arn string) bool {
	id, ok := strings.CutPrefix(arn, topic+":")
	return ok && subID.MatchString(id)
}

// checkWatch refuses a publish while the key watch can't tell anyone: each
// watch topic (the stack's KeyWatchTopicArn and KeyWatchTopicBArn) must
// have an email subscription, and every email subscription must be
// confirmed (README "The watch"). It fails closed: an answer it can't
// read is a refusal.
func checkWatch(ctx context.Context, c snsAPI, topics []string) error {
	if len(topics) != 2 || !watchPair(topics[0], topics[1]) {
		return errors.New("-watch-topics takes the stack's two key watch topics, KeyWatchTopicArn and KeyWatchTopicBArn (…-key-watch,…-key-watch-b), comma-separated")
	}
	for _, t := range topics {
		email := 0
		var next *string
		for {
			out, err := c.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{TopicArn: aws.String(t), NextToken: next})
			if err != nil {
				return fmt.Errorf("reading the key watch's subscriptions on %s: %w", t, err)
			}
			for _, s := range out.Subscriptions {
				if aws.ToString(s.Protocol) != "email" {
					continue
				}
				if email++; email > 1 {
					return fmt.Errorf("the key watch topic %s has more than one email subscription: it has one, the stack's", t)
				}
				// A confirmed subscription's ARN is the topic's and an id; one
				// waiting is "PendingConfirmation" (or "Deleted").
				arn := aws.ToString(s.SubscriptionArn)
				if !confirmedSub(t, arn) {
					return fmt.Errorf("the key watch's email on %s is not confirmed (%s): confirm it before publishing (README \"The watch\")", t, arn)
				}
				// Confirmed by a signed-in call, so that only a signed-in
				// (watched) call can unsubscribe it, not the email's link;
				// and no filter policy, which could drop every notice.
				attrs, err := c.GetSubscriptionAttributes(ctx, &sns.GetSubscriptionAttributesInput{SubscriptionArn: aws.String(arn)})
				if err != nil {
					return fmt.Errorf("reading the key watch's subscription %s: %w", arn, err)
				}
				if attrs.Attributes["ConfirmationWasAuthenticated"] != "true" {
					return fmt.Errorf("the key watch's email on %s was confirmed by its link, not by a signed-in call: confirm it with --authenticate-on-unsubscribe true (README \"The watch\")", t)
				}
				if attrs.Attributes["FilterPolicy"] != "" {
					return fmt.Errorf("the key watch's email on %s has a filter policy: remove it (README \"The watch\")", t)
				}
			}
			if next = out.NextToken; next == nil {
				break
			}
		}
		if email == 0 {
			return fmt.Errorf("the key watch topic %s has no email subscription: nothing would tell anyone of this publish", t)
		}
	}
	return nil
}
