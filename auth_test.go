package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if a.Service() == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNew_WithSecret(t *testing.T) {
	a, err := newTestAuth(WithSecret("abcdefghijklmnopqrstuvwxyz012345"))
	if err != nil {
		t.Fatalf("New with secret: %v", err)
	}
	if a.service.cfg.Secret != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatal("secret not set")
	}
}

func TestNew_WithInvalidSecret(t *testing.T) {
	_, err := newTestAuth(WithSecret("short"))
	if err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestNew_WithIssuer(t *testing.T) {
	a, err := newTestAuth(WithIssuer("my-issuer"))
	if err != nil {
		t.Fatalf("New with issuer: %v", err)
	}
	if a.service.cfg.Issuer != "my-issuer" {
		t.Fatalf("issuer not set: %s", a.service.cfg.Issuer)
	}
}

func TestNew_WithTokenTTLs_Valid(t *testing.T) {
	a, err := newTestAuth(WithTokenTTLs(5*time.Minute, 7*24*time.Hour))
	if err != nil {
		t.Fatalf("New with TTLs: %v", err)
	}
	if a.service.cfg.AccessTokenTTL != 5*time.Minute {
		t.Fatal("access TTL not set")
	}
	if a.service.cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Fatal("refresh TTL not set")
	}
}

func TestNew_WithTokenTTLs_ZeroAccess(t *testing.T) {
	_, err := newTestAuth(WithTokenTTLs(0, 7*24*time.Hour))
	if err == nil {
		t.Fatal("expected error for zero access TTL")
	}
}

func TestNew_WithTokenTTLs_ZeroRefresh(t *testing.T) {
	_, err := newTestAuth(WithTokenTTLs(5*time.Minute, 0))
	if err == nil {
		t.Fatal("expected error for zero refresh TTL")
	}
}

func TestNew_WithNilUserStore(t *testing.T) {
	_, err := newTestAuth(WithUserStore(nil))
	if err == nil {
		t.Fatal("expected error for nil user store")
	}
}

func TestNew_WithNilSessionStore(t *testing.T) {
	_, err := newTestAuth(WithSessionStore(nil))
	if err == nil {
		t.Fatal("expected error for nil session store")
	}
}

func TestNew_WithRequire2FA(t *testing.T) {
	a, err := newTestAuth(WithRequire2FA(true))
	if err != nil {
		t.Fatalf("New with require 2FA: %v", err)
	}
	if !a.service.cfg.Require2FA {
		t.Fatal("require 2FA not set")
	}
}

func TestNew_WithLogger(t *testing.T) {
	logged := false
	a, err := newTestAuth(WithLogger(func(format string, args ...any) { logged = true }))
	if err != nil {
		t.Fatalf("New with logger: %v", err)
	}
	a.service.logf("test")
	if !logged {
		t.Fatal("logger not called")
	}
}

func TestNew_WithTokenClaimsBuilder(t *testing.T) {
	a, err := newTestAuth(WithTokenClaimsBuilder(func(ctx context.Context, user User) (map[string]any, error) {
		return map[string]any{"x": 1}, nil
	}))
	if err != nil {
		t.Fatalf("New with claims builder: %v", err)
	}
	if a.service.cfg.BuildTokenClaims == nil {
		t.Fatal("BuildTokenClaims not set")
	}
}

func TestNew_NilOptionSkipped(t *testing.T) {
	_, err := newTestAuth(nil)
	if err != nil {
		t.Fatalf("nil option should be skipped, got: %v", err)
	}
}

func TestNew_WithMetadataProvider(t *testing.T) {
	ms := NewMemoryMetadataStore()
	a, err := newTestAuth(WithMetadataProvider(ms))
	if err != nil {
		t.Fatalf("New with metadata provider: %v", err)
	}
	if a.service.metadata == nil {
		t.Fatal("metadata store not set")
	}
}

func TestNew_WithRBACProvider(t *testing.T) {
	rs := NewMemoryRolesPermissionsStore()
	a, err := newTestAuth(WithRBACProvider(rs))
	if err != nil {
		t.Fatalf("New with RBAC provider: %v", err)
	}
	if a.service.rbac == nil {
		t.Fatal("RBAC store not set")
	}
}

func TestNew_WithTenantProvider(t *testing.T) {
	ts := NewMemoryTenantStore()
	a, err := newTestAuth(WithTenantProvider(ts))
	if err != nil {
		t.Fatalf("New with tenant provider: %v", err)
	}
	if a.service.tenants == nil {
		t.Fatal("tenant store not set")
	}
}

func TestNew_WithTokenClaimsBuilder_ErrorOnRegister(t *testing.T) {
	buildErr := errors.New("claims build error")
	a, err := newTestAuth(WithTokenClaimsBuilder(func(ctx context.Context, user User) (map[string]any, error) {
		return nil, buildErr
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	_, _, err = a.Register(ctx, RegisterInput{Email: "claimserr@example.com", Password: "password1", TenantID: "t1"})
	if err == nil {
		t.Fatal("expected error when claims builder fails")
	}
}

func TestAuth_Register_Delegates(t *testing.T) {
	a, _ := newTestAuth()
	ctx := context.Background()
	user, tokens, err := a.Register(ctx, RegisterInput{Email: "auth@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.Email != "auth@example.com" {
		t.Fatalf("unexpected email: %s", user.Email)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}
}

func TestAuth_Login_Delegates(t *testing.T) {
	a, _ := newTestAuth()
	ctx := context.Background()
	_, _, _ = a.Register(ctx, RegisterInput{Email: "login@example.com", Password: "password1", TenantID: "t1"})
	_, tokens, err := a.Login(ctx, LoginInput{Email: "login@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected access token")
	}
}

func TestAuth_Refresh_Delegates(t *testing.T) {
	a, _ := newTestAuth()
	ctx := context.Background()
	_, tokens, _ := a.Register(ctx, RegisterInput{Email: "refresh@example.com", Password: "password1", TenantID: "t1"})
	newTokens, err := a.Refresh(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if newTokens.AccessToken == "" {
		t.Fatal("expected new access token")
	}
}

func TestAuth_Logout_Delegates(t *testing.T) {
	a, _ := newTestAuth()
	ctx := context.Background()
	_, tokens, _ := a.Register(ctx, RegisterInput{Email: "logout@example.com", Password: "password1", TenantID: "t1"})
	if err := a.Logout(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := a.Refresh(ctx, tokens.RefreshToken); err == nil {
		t.Fatal("expected error refreshing after logout")
	}
}

func TestAuth_Me_Delegates(t *testing.T) {
	a, _ := newTestAuth()
	ctx := context.Background()
	user, tokens, _ := a.Register(ctx, RegisterInput{Email: "me@example.com", Password: "password1", TenantID: "t1"})
	me, err := a.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.ID != user.ID {
		t.Fatalf("unexpected user: %s", me.ID)
	}
}

func TestAuth_WithCustomUserStore(t *testing.T) {
	users := NewMemoryUserStore()
	a, err := newTestAuth(WithUserStore(users))
	if err != nil {
		t.Fatalf("New with user store: %v", err)
	}
	ctx := context.Background()
	_, _, err = a.Register(ctx, RegisterInput{Email: "custom@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestAuth_WithCustomSessionStore(t *testing.T) {
	sessions := NewMemorySessionStore()
	a, err := newTestAuth(WithSessionStore(sessions))
	if err != nil {
		t.Fatalf("New with session store: %v", err)
	}
	ctx := context.Background()
	_, tokens, _ := a.Register(ctx, RegisterInput{Email: "sessstore@example.com", Password: "password1", TenantID: "t1"})
	if _, err := a.Refresh(ctx, tokens.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}
