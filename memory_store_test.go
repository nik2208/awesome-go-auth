package auth

import (
	"context"
	"testing"
	"time"
)

func TestMemorySessionStore_ListRevokeAndCleanup(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Now()

	_, _ = store.CreateSession(ctx, Session{ID: "s1", UserID: "u1", TenantID: "t1", RefreshTokenHash: "h1", ExpiresAt: now.Add(1 * time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s2", UserID: "u1", TenantID: "t2", RefreshTokenHash: "h2", ExpiresAt: now.Add(1 * time.Hour)})
	_, _ = store.CreateSession(ctx, Session{ID: "s3", UserID: "u2", TenantID: "t1", RefreshTokenHash: "h3", ExpiresAt: now.Add(-1 * time.Hour)})

	sessions, err := store.ListSessionsForUser(ctx, "u1", "t1")
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Fatalf("unexpected filtered sessions: %+v", sessions)
	}

	if err := store.RevokeSessionByID(ctx, "s1"); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	revoked, err := store.GetSessionByRefreshTokenHash(ctx, "h1")
	if err != nil {
		t.Fatalf("get revoked session: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("revoked session should have RevokedAt")
	}
	if err := store.RevokeSessionByID(ctx, "missing"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	deleted, err := store.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("cleanup expired sessions: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted session, got %d", deleted)
	}
	if _, err := store.GetSessionByRefreshTokenHash(ctx, "h3"); err != ErrSessionNotFound {
		t.Fatalf("expected expired session removed, got %v", err)
	}
}
