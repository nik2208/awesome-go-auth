package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

// TestIssueToken_SignatureCoversHeaderAndPayload recomputes the MAC the way an
// independent JWS verifier would: HMAC-SHA256 over "header.payload". Without
// this, an implementation that signed the claims segment alone would still be
// self-consistent and pass every other test in this file, while producing a
// token no JWT library accepts and whose header is unauthenticated.
func TestIssueToken_SignatureCoversHeaderAndPayload(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_018", TenantID: "t1", Email: "jws@example.com", Role: "admin"}
	token, _, err := svc.issueToken(ctx, user, "ses_018", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(svc.cfg.Secret))
	if _, err := mac.Write([]byte(header + "." + payload)); err != nil {
		t.Fatalf("write mac: %v", err)
	}
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("signature is not HMAC-SHA256 over header.payload: got %q, want %q", sig, want)
	}
}

// TestParseToken_RejectsSwappedHeader swaps the JOSE header of a valid token
// while keeping its claims and its original signature. The alg stays HS256, so
// only the fact that the header is part of the signing input can reject it.
func TestParseToken_RejectsSwappedHeader(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_019", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_019", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	_, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	swapped := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"attacker"}`))
	if _, err := svc.parseToken(swapped+"."+payload+"."+sig, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for a token with a swapped header, got %v", err)
	}
}
