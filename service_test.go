package auth

import (
	"context"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	cfg := DefaultConfig("01234567890123456789012345678901")
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestRegisterLoginMeAndRefresh(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, tokens, err := svc.Register(ctx, RegisterInput{
		Email:    "Test@Example.com",
		Password: "supersecure",
		TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Fatalf("email not normalized: %s", user.Email)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("tokens should be issued")
	}

	me, err := svc.Me(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.ID != user.ID {
		t.Fatalf("unexpected me user id: %s", me.ID)
	}

	_, loginTokens, err := svc.Login(ctx, LoginInput{
		Email:    "test@example.com",
		Password: "supersecure",
		TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if loginTokens.RefreshToken == "" {
		t.Fatal("refresh token should be issued on login")
	}

	refreshed, err := svc.Refresh(ctx, loginTokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.RefreshToken == loginTokens.RefreshToken {
		t.Fatal("refresh token must rotate")
	}

	if err := svc.Logout(ctx, refreshed.RefreshToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Refresh(ctx, refreshed.RefreshToken); err == nil {
		t.Fatal("expected refresh to fail after logout")
	}
}

func TestDuplicateRegisterFails(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	_, _, err := svc.Register(ctx, RegisterInput{Email: "a@b.c", Password: "password1", TenantID: "t"})
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	_, _, err = svc.Register(ctx, RegisterInput{Email: "a@b.c", Password: "password1", TenantID: "t"})
	if err != ErrUserExists {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
}
