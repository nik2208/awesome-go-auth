package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestMeIncludesMetadataRolesTenantsAndCustomClaims(t *testing.T) {
	ctx := context.Background()
	metadataStore := NewMemoryMetadataStore()
	rbacStore := NewMemoryRolesPermissionsStore()
	tenantStore := NewMemoryTenantStore()
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.BuildTokenClaims = func(_ context.Context, user User) (map[string]any, error) {
		return map[string]any{"plan": "pro", "loginProvider": "local", "subjectEmail": user.Email}, nil
	}

	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(), WithMetadataStore(metadataStore), WithRolesPermissionsStore(rbacStore), WithTenantStore(tenantStore))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "claims@example.com", Password: "password1", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.UpdateMetadata(ctx, user.ID, map[string]any{"theme": "dark", "lang": "it"}); err != nil {
		t.Fatalf("update metadata: %v", err)
	}
	if err := svc.CreateRole(ctx, "editor", []string{"posts:read", "posts:write"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := svc.AssignRole(ctx, user.ID, "editor", user.TenantID); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	tenant, err := svc.CreateTenant(ctx, "Acme", map[string]any{"region": "eu"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := svc.AddUserToTenant(ctx, user.ID, tenant.ID); err != nil {
		t.Fatalf("add user to tenant: %v", err)
	}

	me, err := svc.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.Metadata["theme"] != "dark" || len(me.Roles) != 1 || me.Roles[0] != "editor" {
		t.Fatalf("unexpected enriched profile: %+v", me)
	}
	if len(me.Permissions) != 2 || len(me.Tenants) != 1 || me.Tenants[0].ID != tenant.ID {
		t.Fatalf("unexpected permissions/tenants in profile: %+v", me)
	}
	if me.CustomClaims["plan"] != "pro" || me.CustomClaims["subjectEmail"] != user.Email {
		t.Fatalf("unexpected custom claims in profile: %+v", me.CustomClaims)
	}

	allowed, err := svc.UserHasPermission(ctx, user.ID, "posts:write", user.TenantID)
	if err != nil {
		t.Fatalf("has permission: %v", err)
	}
	if !allowed {
		t.Fatal("expected permission to be granted")
	}

	payload, _, err := splitToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("split token: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal token claims: %v", err)
	}
	if claims["plan"] != "pro" || claims["loginProvider"] != "local" {
		t.Fatalf("custom claims missing from token payload: %+v", claims)
	}
}

type failingMetadataStore struct{}

func (f failingMetadataStore) GetMetadata(context.Context, string) (map[string]any, error) {
	return nil, errors.New("boom")
}

func (f failingMetadataStore) UpdateMetadata(context.Context, string, map[string]any) error {
	return errors.New("boom")
}

func (f failingMetadataStore) ClearMetadata(context.Context, string) error {
	return errors.New("boom")
}

func TestMeSkipsOptionalEnrichmentFailures(t *testing.T) {
	ctx := context.Background()
	logged := false
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.Logger = func(format string, args ...any) {
		logged = true
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(), WithMetadataStore(failingMetadataStore{}))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	user, tokens, err := svc.Register(ctx, RegisterInput{Email: "skip@example.com", Password: "password1", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	me, err := svc.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("me should succeed even if optional enrichment fails: %v", err)
	}
	if me.ID != user.ID {
		t.Fatalf("unexpected user returned: %+v", me)
	}
	if !logged {
		t.Fatal("expected optional enrichment failure to be logged via configured logger")
	}
}
