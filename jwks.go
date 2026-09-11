package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// This file is the RS256 key material of the IdP: a PEM in, a JWK out, and the
// JWS builder both the ID token and IssueIdPTokenPair go through. Nothing here
// knows about routes; the IDP type in idp.go is the only caller inside the
// package, and a host that signs elsewhere (a KMS, a second issuer) can use
// these on their own.

// JWK is one RSA public key as the JWKS endpoint publishes it: the six members
// the reference's JWK interface has (jwks.service.ts:5-12), under the same
// JSON names and in the same order. Only signing keys are published, so Kty is
// always "RSA", Use "sig" and Alg "RS256" for a key NewRSAJWK built; the fields
// are exported so that a host can carry a key it obtained elsewhere into
// IDPConfig.PublicKeys unchanged.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the document the JWKS endpoint serves: {"keys": [...]}
// (jwks.service.ts:14-16, :184-186).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewRSAJWK converts an RSA public key to the JWK the reference's
// publicKeyToJwk emits (jwks.service.ts:168-179): kty "RSA", use "sig", alg
// "RS256", the given kid, and n and e as the unpadded base64url of their
// big-endian bytes (RFC 7518 section 6.3.1).
//
// A nil key, or one with no modulus, is an error rather than a panic: the key
// a host feeds IDPConfig.PublicKeys was obtained elsewhere (kms:GetPublicKey, a
// file), and the failed fetch that leaves it nil should surface as an error at
// the call site, not as a crash when the document is built.
func NewRSAJWK(pub *rsa.PublicKey, kid string) (JWK, error) {
	if pub == nil || pub.N == nil {
		return JWK{}, errors.New("auth: idp: nil RSA public key")
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}

// ParseRSAPrivateKeyPEM decodes a PEM-encoded RSA private key, accepting both
// the PKCS#8 form the reference generates ("PRIVATE KEY", jwks.service.ts:152)
// and the PKCS#1 form openssl genrsa writes ("RSA PRIVATE KEY"). Anything else
// — no PEM block, another block type, a PKCS#8 key of a different algorithm —
// is an error. The result is what IDPConfig.Signer takes: an *rsa.PrivateKey
// is a crypto.Signer.
func ParseRSAPrivateKeyPEM(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("auth: idp: no PEM block in private key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("auth: idp: parse PKCS#1 private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("auth: idp: parse PKCS#8 private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("auth: idp: PKCS#8 private key is %T, want RSA", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("auth: idp: unsupported PEM block type %q, want PRIVATE KEY or RSA PRIVATE KEY", block.Type)
	}
}

// BuildRS256JWT creates a signed RS256 JWT using only standard library
// packages: header {"alg":"RS256","typ":"JWT","kid":kid}, the claims as given,
// both unpadded base64url, and the PKCS#1 v1.5 signature over the SHA-256 of
// base64url(header) + "." + base64url(claims), as RFC 7515 section 5.1 and
// RFC 7518 section 3.3 require.
//
// The signer is asked for exactly one thing: Sign(rand.Reader, digest,
// crypto.SHA256) with the 32-byte SHA-256 digest of the signing input. An
// *rsa.PrivateKey answers with PKCS#1 v1.5, which is what RS256 is; a signer
// backed by a KMS, an HSM or another process must do the same when it sees
// crypto.SHA256 as the option (AWS KMS: RSASSA_PKCS1_V1_5_SHA_256 on a
// MessageType DIGEST request), and its Public must return the matching
// *rsa.PublicKey for the key to be published.
//
// A signer whose Public is not an *rsa.PublicKey — an ECDSA or Ed25519 key —
// is refused with an error before Sign is asked: the alternative is a token
// whose header says RS256 over a signature no RS256 verifier accepts, and no
// error anywhere. NewIDP makes the same check once at construction; this one
// is for a host calling BuildRS256JWT on its own, and it consults Public on
// every call.
func BuildRS256JWT(signer crypto.Signer, kid string, claims map[string]any) (string, error) {
	if signer == nil {
		return "", errors.New("auth: idp: nil signer")
	}
	if pub, ok := signer.Public().(*rsa.PublicKey); !ok || pub == nil || pub.N == nil {
		return "", fmt.Errorf("auth: idp: signer public key is %T, want *rsa.PublicKey (RS256 is RSA)", signer.Public())
	}
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", fmt.Errorf("auth: idp jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: idp jwt payload: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := header + "." + payload

	digest := sha256.Sum256([]byte(sigInput))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("auth: idp rsa sign: %w", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
