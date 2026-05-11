package auth

import (
	"context"
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
	_, err := svc.parseToken("notavalidtoken", "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid format, got %v", err)
	}
}

func TestParseToken_InvalidBase64Payload(t *testing.T) {
	svc := testServiceForToken(t)
	sig := sign("!!!invalid!!!", svc.cfg.Secret)
	_, err := svc.parseToken("!!!invalid!!!."+sig, "access")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid base64, got %v", err)
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
	if token == "" {
		t.Fatal("expected non-empty token")
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
}
