package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testServiceForToken(t *testing.T) *Service {
	t.Helper()
	cfg := DefaultConfig("tokentest12345678901234567890123")
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// decodeSegment decodes one base64url JWT segment into a claim/header map.
func decodeSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
	return out
}

// resignWithHeader rebuilds a token with a different JOSE header, keeping the
// original claims and producing a signature that is valid for the given secret.
func resignWithHeader(t *testing.T, token, secret string, header map[string]any) string {
	t.Helper()
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	sigInput := base64.RawURLEncoding.EncodeToString(raw) + "." + payload
	return sigInput + "." + sign(sigInput, secret)
}

func TestIssueToken_AccessAndParse(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_001", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_001", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims, err := svc.parseToken(token, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims.Sub != "usr_001" {
		t.Fatalf("unexpected sub: %s", claims.Sub)
	}
	if claims.Tid != "t1" {
		t.Fatalf("unexpected tid: %s", claims.Tid)
	}
	if claims.Typ != "access" {
		t.Fatalf("unexpected typ: %s", claims.Typ)
	}
	if claims.Sid != "ses_001" {
		t.Fatalf("unexpected sid: %s", claims.Sid)
	}
	if claims.Iss != svc.cfg.Issuer {
		t.Fatalf("unexpected iss: %s", claims.Iss)
	}
	if claims.Jti == "" {
		t.Fatal("jti should not be empty")
	}
}

func TestIssueToken_RefreshAndParse(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_002", TenantID: "t2"}
	token, _, err := svc.issueToken(ctx, user, "ses_002", "refresh", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	claims, err := svc.parseToken(token, "refresh")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims.Typ != "refresh" {
		t.Fatalf("unexpected typ: %s", claims.Typ)
	}
}

func TestIssueToken_ThreeSegmentJWT(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_010", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_010", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-segment JWT, got %d segments: %q", len(parts), token)
	}
	for i, part := range parts {
		if part == "" {
			t.Fatalf("segment %d is empty", i)
		}
		if strings.ContainsAny(part, "+/=") {
			t.Fatalf("segment %d is not base64url without padding: %q", i, part)
		}
	}
}

func TestIssueToken_JOSEHeader(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_011", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_011", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, _, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	decoded := decodeSegment(t, header)
	if decoded["alg"] != "HS256" {
		t.Fatalf("unexpected alg: %v", decoded["alg"])
	}
	if decoded["typ"] != "JWT" {
		t.Fatalf("unexpected header typ: %v", decoded["typ"])
	}
}

func TestIssueToken_ClaimsSegmentCarriesRegisteredClaims(t *testing.T) {
	svc := testServiceForToken(t)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	ctx := context.Background()
	user := User{ID: "usr_012", TenantID: "t1", Email: "claims@example.com", Role: "admin", IsEmailVerified: true, IsTOTPEnabled: true}
	token, _, err := svc.issueToken(ctx, user, "ses_012", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	if claims["sub"] != "usr_012" || claims["sid"] != "ses_012" || claims["tid"] != "t1" {
		t.Fatalf("unexpected identity claims: %+v", claims)
	}
	if claims["typ"] != "access" || claims["iss"] != svc.cfg.Issuer {
		t.Fatalf("unexpected typ/iss claims: %+v", claims)
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Fatalf("jti claim missing: %+v", claims)
	}
	if claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(15*time.Minute).Unix()) {
		t.Fatalf("unexpected iat/exp claims: %+v", claims)
	}
	if claims["email"] != "claims@example.com" || claims["role"] != "admin" {
		t.Fatalf("unexpected profile claims: %+v", claims)
	}
	if claims["isEmailVerified"] != true || claims["isTotpEnabled"] != true {
		t.Fatalf("unexpected flag claims: %+v", claims)
	}
}

func TestParseToken_WrongType(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_003", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_003", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	_, err = svc.parseToken(token, "refresh")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong type, got %v", err)
	}
}

func TestParseToken_TamperedSignature(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_004", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_004", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	tampered := token[:len(token)-4] + "xxxx"
	_, err = svc.parseToken(tampered, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered token, got %v", err)
	}
}

func TestParseToken_TamperedClaims(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_013", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_013", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	header, payload, sig, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	claims["sub"] = "usr_attacker"
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	forged := header + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + sig
	if _, err := svc.parseToken(forged, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered claims, got %v", err)
	}
}

func TestParseToken_RejectsAlgNone(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_014", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_014", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	// Unsecured JWT: alg "none" with an empty signature segment.
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if _, err := svc.parseToken(noneHeader+"."+payload+".", "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for alg none with empty signature, got %v", err)
	}
	// Same claims, alg "none", but carrying a signature that is valid for the
	// service secret: the allow-list must still refuse it.
	resigned := resignWithHeader(t, token, svc.cfg.Secret, map[string]any{"alg": "none", "typ": "JWT"})
	if _, err := svc.parseToken(resigned, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for alg none with valid mac, got %v", err)
	}
}

func TestParseToken_RejectsAlgConfusion(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_015", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_015", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	for _, alg := range []string{"RS256", "HS512", "hs256", ""} {
		resigned := resignWithHeader(t, token, svc.cfg.Secret, map[string]any{"alg": alg, "typ": "JWT"})
		if _, err := svc.parseToken(resigned, "access"); err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken for alg %q, got %v", alg, err)
		}
	}
}

func TestParseToken_CrossSecret(t *testing.T) {
	issuer := testServiceForToken(t)
	verifier := testServiceForToken(t)
	verifier.cfg.Secret = "othersecret1234567890123456789012"
	ctx := context.Background()
	user := User{ID: "usr_016", TenantID: "t1"}
	token, _, err := issuer.issueToken(ctx, user, "ses_016", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if _, err := verifier.parseToken(token, "access"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for token signed with another secret, got %v", err)
	}
}

func TestParseToken_ExpiredToken(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := User{ID: "usr_005", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_005", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.now = func() time.Time { return now.Add(16*time.Minute + svc.cfg.ClockSkew + time.Second) }
	_, err = svc.parseToken(token, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestParseToken_WithinClockSkew(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := User{ID: "usr_017", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_017", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.now = func() time.Time { return now.Add(15*time.Minute + svc.cfg.ClockSkew - time.Second) }
	if _, err := svc.parseToken(token, "access"); err != nil {
		t.Fatalf("token just inside the clock skew window must parse: %v", err)
	}
}

func TestParseToken_WrongIssuer(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	svc.cfg.Issuer = "wrong-issuer"
	user := User{ID: "usr_006", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_006", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	svc.cfg.Issuer = "awesome-go-auth"
	_, err = svc.parseToken(token, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong issuer, got %v", err)
	}
}

func TestParseToken_InvalidFormat(t *testing.T) {
	svc := testServiceForToken(t)
	for _, token := range []string{"notavalidtoken", "onlytwo.segments"} {
		if _, err := svc.parseToken(token, "access"); err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken for %q, got %v", token, err)
		}
	}
}

func TestParseToken_InvalidBase64Header(t *testing.T) {
	svc := testServiceForToken(t)
	sigInput := "!!!invalid!!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"access"}`))
	_, err := svc.parseToken(sigInput+"."+sign(sigInput, svc.cfg.Secret), "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid base64 header, got %v", err)
	}
}

func TestParseToken_InvalidBase64Payload(t *testing.T) {
	svc := testServiceForToken(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	sigInput := header + ".!!!invalid!!!"
	_, err := svc.parseToken(sigInput+"."+sign(sigInput, svc.cfg.Secret), "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid base64 payload, got %v", err)
	}
}

func TestIssueToken_CustomClaims(t *testing.T) {
	svc := testServiceForToken(t)
	svc.cfg.BuildTokenClaims = func(ctx context.Context, user User) (map[string]any, error) {
		return map[string]any{"custom": "value"}, nil
	}
	ctx := context.Background()
	user := User{ID: "usr_007", TenantID: "t1"}
	token, _, err := svc.issueToken(ctx, user, "ses_007", "access", 15*time.Minute)
	if err != nil {
		t.Fatalf("issueToken with custom claims: %v", err)
	}
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	claims := decodeSegment(t, payload)
	if claims["custom"] != "value" {
		t.Fatalf("custom claim missing from token payload: %+v", claims)
	}
	if claims["sub"] != "usr_007" {
		t.Fatalf("custom claims must not drop the registered claims: %+v", claims)
	}
	if _, err := svc.parseToken(token, "access"); err != nil {
		t.Fatalf("token with custom claims must still parse: %v", err)
	}
}

func TestIssueToken_ExpiryIsCorrect(t *testing.T) {
	svc := testServiceForToken(t)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	ctx := context.Background()
	user := User{ID: "usr_008", TenantID: "t1"}
	ttl := 15 * time.Minute
	_, exp, err := svc.issueToken(ctx, user, "ses_008", "access", ttl)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	expectedExp := now.Add(ttl)
	if !exp.Equal(expectedExp) {
		t.Fatalf("expected expiry %v, got %v", expectedExp, exp)
	}
}

func TestIssueToken_UniqueJTI(t *testing.T) {
	svc := testServiceForToken(t)
	ctx := context.Background()
	user := User{ID: "usr_009", TenantID: "t1"}
	tok1, _, _ := svc.issueToken(ctx, user, "ses_009a", "access", time.Minute)
	tok2, _, _ := svc.issueToken(ctx, user, "ses_009b", "access", time.Minute)
	if tok1 == tok2 {
		t.Fatal("tokens with different session IDs should be different")
	}
	claims1, err := svc.parseToken(tok1, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	claims2, err := svc.parseToken(tok2, "access")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims1.Jti == claims2.Jti {
		t.Fatalf("jti must be unique per token, got %q twice", claims1.Jti)
	}
}
