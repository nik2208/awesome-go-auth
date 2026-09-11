package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── MemoryUserStore ─────────────────────────────────────────────────────────

func TestMemoryUserStore_CreateAndGetByID(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	user := User{ID: "u001", Email: "alice@example.com", TenantID: "t1"}
	created, err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID != "u001" {
		t.Fatalf("unexpected ID: %s", created.ID)
	}
	found, err := store.GetUserByID(ctx, "u001", "t1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if found.Email != "alice@example.com" {
		t.Fatalf("unexpected email: %s", found.Email)
	}
}

// LoginProvider is stored with the rest of the row: an OAuth-created account
// must still say which provider created it when it is read back, by id and by
// email alike.
func TestMemoryUserStore_PersistsLoginProvider(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, User{ID: "u003", Email: "oauth@example.com", TenantID: "t1", LoginProvider: "github"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	byID, err := store.GetUserByID(ctx, "u003", "t1")
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.LoginProvider != "github" {
		t.Fatalf("LoginProvider by id = %q, want %q", byID.LoginProvider, "github")
	}
	byEmail, err := store.GetUserByEmail(ctx, "oauth@example.com", "t1")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if byEmail.LoginProvider != "github" {
		t.Fatalf("LoginProvider by email = %q, want %q", byEmail.LoginProvider, "github")
	}
}

func TestMemoryUserStore_CreateAndGetByEmail(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u002", Email: "bob@example.com", TenantID: "t1"})
	found, err := store.GetUserByEmail(ctx, "bob@example.com", "t1")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if found.ID != "u002" {
		t.Fatalf("unexpected ID: %s", found.ID)
	}
}

func TestMemoryUserStore_DuplicateEmail(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "dup@example.com", TenantID: "t1"})
	_, err := store.CreateUser(ctx, User{ID: "u2", Email: "dup@example.com", TenantID: "t1"})
	if err != ErrUserExists {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
}

func TestMemoryUserStore_GetUserByID_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByID(context.Background(), "nonexistent", "t1")
	if err == nil {
		t.Fatalf("expected error for not-found user, got nil")
	}
}

func TestMemoryUserStore_GetUserByEmail_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByEmail(context.Background(), "nobody@example.com", "t1")
	if err == nil {
		t.Fatalf("expected error for not-found user, got nil")
	}
}

func TestMemoryUserStore_EmailIsolatedByTenant(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "shared@example.com", TenantID: "t1"})
	// Same email in different tenant should succeed
	_, err := store.CreateUser(ctx, User{ID: "u2", Email: "shared@example.com", TenantID: "t2"})
	if err != nil {
		t.Fatalf("same email in different tenant should be allowed: %v", err)
	}
}

func TestMemoryUserStore_UpdatePassword(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "pw@example.com", TenantID: "t1", PasswordHash: "oldhash"})
	if err := store.UpdatePassword(ctx, "u1", "t1", "newhash"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	u, _ := store.GetUserByID(ctx, "u1", "t1")
	if u.PasswordHash != "newhash" {
		t.Fatalf("expected updated hash, got %s", u.PasswordHash)
	}
}

func TestMemoryUserStore_UpdatePassword_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	err := store.UpdatePassword(context.Background(), "nonexistent", "t1", "hash")
	if err == nil {
		t.Fatalf("expected error for not-found user, got nil")
	}
}

func TestMemoryUserStore_ResetToken_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "reset@example.com", TenantID: "t1"})
	expiry := time.Now().Add(1 * time.Hour)
	if err := store.UpdateResetToken(ctx, "u1", "t1", "resethash123", expiry); err != nil {
		t.Fatalf("UpdateResetToken: %v", err)
	}
	found, err := store.GetUserByResetTokenHash(ctx, "resethash123")
	if err != nil {
		t.Fatalf("GetUserByResetTokenHash: %v", err)
	}
	if found.ID != "u1" {
		t.Fatalf("unexpected user: %s", found.ID)
	}
	if err := store.ClearResetToken(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ClearResetToken: %v", err)
	}
	_, err = store.GetUserByResetTokenHash(ctx, "resethash123")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after clear, got %v", err)
	}
}

func TestMemoryUserStore_GetUserByResetTokenHash_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByResetTokenHash(context.Background(), "nosuchtoken")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMemoryUserStore_MagicLink_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "magic@example.com", TenantID: "t1"})
	expiry := time.Now().Add(15 * time.Minute)
	if err := store.UpdateMagicLinkToken(ctx, "u1", "t1", "magichash", expiry); err != nil {
		t.Fatalf("UpdateMagicLinkToken: %v", err)
	}
	found, err := store.GetUserByMagicLinkTokenHash(ctx, "magichash")
	if err != nil {
		t.Fatalf("GetUserByMagicLinkTokenHash: %v", err)
	}
	if found.ID != "u1" {
		t.Fatalf("unexpected user: %s", found.ID)
	}
	if err := store.ClearMagicLinkToken(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ClearMagicLinkToken: %v", err)
	}
	_, err = store.GetUserByMagicLinkTokenHash(ctx, "magichash")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after clear, got %v", err)
	}
}

func TestMemoryUserStore_MagicLink_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByMagicLinkTokenHash(context.Background(), "badtoken")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMemoryUserStore_SMSCode_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "sms@example.com", TenantID: "t1"})
	expiry := time.Now().Add(5 * time.Minute)
	if err := store.UpdateSMSCode(ctx, "u1", "t1", "smshash", expiry); err != nil {
		t.Fatalf("UpdateSMSCode: %v", err)
	}
	found, err := store.GetUserBySMSCodeHash(ctx, "u1", "t1", "smshash")
	if err != nil {
		t.Fatalf("GetUserBySMSCodeHash: %v", err)
	}
	if found.ID != "u1" {
		t.Fatalf("unexpected user: %s", found.ID)
	}
	if err := store.ClearSMSCode(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ClearSMSCode: %v", err)
	}
	_, err = store.GetUserBySMSCodeHash(ctx, "u1", "t1", "smshash")
	if err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode after clear, got %v", err)
	}
}

func TestMemoryUserStore_SMSCode_WrongCode(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "sms2@example.com", TenantID: "t1"})
	expiry := time.Now().Add(5 * time.Minute)
	_ = store.UpdateSMSCode(ctx, "u1", "t1", "correcthash", expiry)
	_, err := store.GetUserBySMSCodeHash(ctx, "u1", "t1", "wronghash")
	if err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for wrong hash, got %v", err)
	}
}

func TestMemoryUserStore_TOTP_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "totp@example.com", TenantID: "t1"})
	if err := store.UpdateTOTPSecret(ctx, "u1", "t1", "TOTPSECRET", true); err != nil {
		t.Fatalf("UpdateTOTPSecret: %v", err)
	}
	u, _ := store.GetUserByID(ctx, "u1", "t1")
	if !u.IsTOTPEnabled {
		t.Fatal("TOTP should be enabled")
	}
	if u.TOTPSecret != "TOTPSECRET" {
		t.Fatalf("unexpected TOTP secret: %s", u.TOTPSecret)
	}
	// Disable TOTP
	if err := store.UpdateTOTPSecret(ctx, "u1", "t1", "", false); err != nil {
		t.Fatalf("UpdateTOTPSecret disable: %v", err)
	}
	u, _ = store.GetUserByID(ctx, "u1", "t1")
	if u.IsTOTPEnabled {
		t.Fatal("TOTP should be disabled after clearing")
	}
}

func TestMemoryUserStore_EmailVerification_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "verify@example.com", TenantID: "t1", IsEmailVerified: false})
	expiry := time.Now().Add(24 * time.Hour)
	if err := store.UpdateEmailVerificationToken(ctx, "u1", "t1", "verhash", expiry); err != nil {
		t.Fatalf("UpdateEmailVerificationToken: %v", err)
	}
	found, err := store.GetUserByEmailVerificationTokenHash(ctx, "verhash")
	if err != nil {
		t.Fatalf("GetUserByEmailVerificationTokenHash: %v", err)
	}
	if found.ID != "u1" {
		t.Fatalf("unexpected user: %s", found.ID)
	}
	if err := store.MarkEmailVerified(ctx, "u1", "t1", true); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	u, _ := store.GetUserByID(ctx, "u1", "t1")
	if !u.IsEmailVerified {
		t.Fatal("email should be verified")
	}
	if err := store.ClearEmailVerificationToken(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ClearEmailVerificationToken: %v", err)
	}
	_, err = store.GetUserByEmailVerificationTokenHash(ctx, "verhash")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after clear, got %v", err)
	}
}

func TestMemoryUserStore_EmailVerification_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByEmailVerificationTokenHash(context.Background(), "nope")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMemoryUserStore_EmailChange_Flow(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "old@example.com", TenantID: "t1"})
	expiry := time.Now().Add(24 * time.Hour)
	if err := store.UpdateEmailChangeToken(ctx, "u1", "t1", "new@example.com", "changehash", expiry); err != nil {
		t.Fatalf("UpdateEmailChangeToken: %v", err)
	}
	found, err := store.GetUserByEmailChangeTokenHash(ctx, "changehash")
	if err != nil {
		t.Fatalf("GetUserByEmailChangeTokenHash: %v", err)
	}
	if found.PendingEmail != "new@example.com" {
		t.Fatalf("unexpected pending email: %s", found.PendingEmail)
	}
	if err := store.ApplyEmailChange(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ApplyEmailChange: %v", err)
	}
	u, _ := store.GetUserByID(ctx, "u1", "t1")
	if u.Email != "new@example.com" {
		t.Fatalf("email should be changed, got %s", u.Email)
	}
	// After applying, can look up by new email
	_, err = store.GetUserByEmail(ctx, "new@example.com", "t1")
	if err != nil {
		t.Fatalf("should find user by new email: %v", err)
	}
	// Old email should no longer work
	_, err = store.GetUserByEmail(ctx, "old@example.com", "t1")
	if err == nil {
		t.Fatalf("expected error for old email after change, got nil")
	}
}

func TestMemoryUserStore_EmailChange_NotFound(t *testing.T) {
	store := NewMemoryUserStore()
	_, err := store.GetUserByEmailChangeTokenHash(context.Background(), "notoken")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestMemoryUserStore_ClearEmailChangeToken(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, User{ID: "u1", Email: "clr@example.com", TenantID: "t1"})
	expiry := time.Now().Add(1 * time.Hour)
	_ = store.UpdateEmailChangeToken(ctx, "u1", "t1", "new@example.com", "clrhash", expiry)
	if err := store.ClearEmailChangeToken(ctx, "u1", "t1"); err != nil {
		t.Fatalf("ClearEmailChangeToken: %v", err)
	}
	_, err := store.GetUserByEmailChangeTokenHash(ctx, "clrhash")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after clear, got %v", err)
	}
}

// ─── MemorySessionStore ───────────────────────────────────────────────────────

func TestMemorySessionStore_CreateAndGet(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	session := Session{
		ID:               "ses_001",
		UserID:           "u1",
		TenantID:         "t1",
		RefreshTokenHash: "rhash001",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		CreatedAt:        time.Now(),
	}
	created, err := store.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created.ID != "ses_001" {
		t.Fatalf("unexpected ID: %s", created.ID)
	}
	found, err := store.GetSessionByRefreshTokenHash(ctx, "rhash001")
	if err != nil {
		t.Fatalf("GetSessionByRefreshTokenHash: %v", err)
	}
	if found.UserID != "u1" {
		t.Fatalf("unexpected user ID: %s", found.UserID)
	}
}

func TestMemorySessionStore_GetByHash_NotFound(t *testing.T) {
	store := NewMemorySessionStore()
	_, err := store.GetSessionByRefreshTokenHash(context.Background(), "nosuchtoken")
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemorySessionStore_UpdateSession(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	session := Session{
		ID:               "ses_002",
		UserID:           "u1",
		TenantID:         "t1",
		RefreshTokenHash: "rhash002",
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour),
		CreatedAt:        time.Now(),
	}
	_, _ = store.CreateSession(ctx, session)
	session.RefreshTokenHash = "rhash002updated"
	if err := store.UpdateSession(ctx, session); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	found, err := store.GetSessionByRefreshTokenHash(ctx, "rhash002updated")
	if err != nil {
		t.Fatalf("GetSessionByRefreshTokenHash after update: %v", err)
	}
	if found.ID != "ses_002" {
		t.Fatalf("unexpected session ID: %s", found.ID)
	}
}

func TestMemorySessionStore_ListSessionsForUser(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	for i, hash := range []string{"h1", "h2", "h3"} {
		uid := "u1"
		if i == 2 {
			uid = "u2"
		}
		_, _ = store.CreateSession(ctx, Session{
			ID: "s" + hash, UserID: uid, TenantID: "t1",
			RefreshTokenHash: hash, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		})
	}
	sessions, err := store.ListSessionsForUser(ctx, "u1", "t1")
	if err != nil {
		t.Fatalf("ListSessionsForUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions for u1, got %d", len(sessions))
	}
}

func TestMemorySessionStore_RevokeByID(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	_, _ = store.CreateSession(ctx, Session{
		ID: "rev_ses", UserID: "u1", TenantID: "t1",
		RefreshTokenHash: "revhash", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err := store.RevokeSessionByID(ctx, "rev_ses"); err != nil {
		t.Fatalf("RevokeSessionByID: %v", err)
	}
	// After revoke the session is marked with RevokedAt but still exists in store
	found, err := store.GetSessionByRefreshTokenHash(ctx, "revhash")
	if err != nil {
		t.Fatalf("session should still be retrievable (marked revoked): %v", err)
	}
	if found.RevokedAt == nil {
		t.Fatal("RevokedAt should be set after revocation")
	}
}

func TestMemorySessionStore_DeleteExpiredSessions(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)
	_, _ = store.CreateSession(ctx, Session{
		ID: "exp1", UserID: "u1", TenantID: "t1",
		RefreshTokenHash: "exph1", ExpiresAt: past, CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	_, _ = store.CreateSession(ctx, Session{
		ID: "active1", UserID: "u1", TenantID: "t1",
		RefreshTokenHash: "activeh1", ExpiresAt: future, CreatedAt: time.Now(),
	})
	n, err := store.DeleteExpiredSessions(ctx, time.Now())
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}
	_, err = store.GetSessionByRefreshTokenHash(ctx, "exph1")
	if err != ErrSessionNotFound {
		t.Fatalf("expired session should be gone, got %v", err)
	}
	_, err = store.GetSessionByRefreshTokenHash(ctx, "activeh1")
	if err != nil {
		t.Fatalf("active session should remain: %v", err)
	}
}

// ─── OAuthService ─────────────────────────────────────────────────────────────

func TestOAuthService_AuthorizeURL_ValidProvider(t *testing.T) {
	svc := NewOAuthService(OAuthProvider{
		Name:     "mock",
		ClientID: "client123",
		AuthURL:  "https://auth.example.com/authorize",
		Scopes:   []string{"openid", "profile"},
	})
	u, err := svc.AuthorizeURL("mock", "state-token-xyz")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	if !strings.Contains(u, "client_id=client123") {
		t.Fatalf("URL should contain client_id: %s", u)
	}
	if !strings.Contains(u, "state=state-token-xyz") {
		t.Fatalf("URL should contain state: %s", u)
	}
	if !strings.Contains(u, "response_type=code") {
		t.Fatalf("URL should contain response_type=code: %s", u)
	}
}

func TestOAuthService_AuthorizeURL_UnknownProvider(t *testing.T) {
	svc := NewOAuthService()
	_, err := svc.AuthorizeURL("unknown", "state")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestOAuthService_AuthorizeURL_IncludesScopes(t *testing.T) {
	svc := NewOAuthService(OAuthProvider{
		Name:    "mock",
		AuthURL: "https://auth.example.com/authorize",
		Scopes:  []string{"openid", "email"},
	})
	u, err := svc.AuthorizeURL("mock", "s")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	if !strings.Contains(u, "scope=") {
		t.Fatalf("URL should contain scope: %s", u)
	}
}

func TestGoogleProvider_Config(t *testing.T) {
	p := GoogleProvider("gid", "gsecret", "https://example.com/callback")
	if p.Name != "google" {
		t.Fatalf("unexpected name: %s", p.Name)
	}
	if p.ClientID != "gid" {
		t.Fatalf("unexpected client ID: %s", p.ClientID)
	}
	if p.AuthURL == "" || p.TokenURL == "" || p.UserInfoURL == "" {
		t.Fatal("google provider should have all URLs set")
	}
	if len(p.Scopes) == 0 {
		t.Fatal("google provider should have scopes")
	}
}

func TestGitHubProvider_Config(t *testing.T) {
	p := GitHubProvider("ghid", "ghsecret", "https://example.com/callback")
	if p.Name != "github" {
		t.Fatalf("unexpected name: %s", p.Name)
	}
	if p.AuthURL == "" || p.TokenURL == "" {
		t.Fatal("github provider should have all URLs set")
	}
	if p.GitHubEmailsURL != "https://api.github.com/user/emails" {
		t.Fatalf("GitHubEmailsURL = %q, want the reference's endpoint (github.strategy.ts:54)", p.GitHubEmailsURL)
	}
}

// authorizeQuery builds the authorization URL and returns its parsed query.
func authorizeQuery(t *testing.T, svc *OAuthService, provider, state, challenge string) url.Values {
	t.Helper()
	u, err := svc.AuthorizeURLPKCE(provider, state, challenge)
	if err != nil {
		t.Fatalf("AuthorizeURLPKCE: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse %q: %v", u, err)
	}
	return parsed.Query()
}

// The reference's additionalAuthParams (generic-oauth.strategy.ts:63) reach
// the authorization query verbatim (:118).
func TestOAuthService_AuthorizeURL_AdditionalAuthParams(t *testing.T) {
	svc := NewOAuthService(OAuthProvider{
		Name:                 "mock",
		ClientID:             "client123",
		AuthURL:              "https://auth.example.com/authorize?tenant=acme",
		Scopes:               []string{"openid"},
		AdditionalAuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
	})
	q := authorizeQuery(t, svc, "mock", "s", "")
	for key, want := range map[string]string{
		"access_type":   "offline",
		"prompt":        "consent",
		"client_id":     "client123",
		"scope":         "openid",
		"response_type": "code",
		"state":         "s",
		"tenant":        "acme", // the AuthURL's own query survives
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if _, present := q["code_challenge"]; present {
		t.Errorf("code_challenge present without a challenge: %v", q)
	}
}

// Precedence, pinned to the reference's spread order
// (generic-oauth.strategy.ts:113-120): additionalAuthParams is spread AFTER
// client_id, redirect_uri, response_type and scope — so an entry replaces any
// of those four — and BEFORE state, so state always wins. The PKCE pair has no
// counterpart in the reference and is written after the entries too: a
// configuration must not be able to downgrade the code binding.
func TestOAuthService_AuthorizeURL_AdditionalAuthParamsPrecedence(t *testing.T) {
	svc := NewOAuthService(OAuthProvider{
		Name:        "mock",
		ClientID:    "client123",
		RedirectURL: "https://api.example.com/cb",
		AuthURL:     "https://auth.example.com/authorize",
		Scopes:      []string{"openid"},
		AdditionalAuthParams: map[string]string{
			"client_id":             "override-client",
			"redirect_uri":          "https://evil.example.net/cb",
			"response_type":         "token",
			"scope":                 "openid email offline_access",
			"state":                 "forged-state",
			"code_challenge":        "forged-challenge",
			"code_challenge_method": "plain",
		},
	})
	q := authorizeQuery(t, svc, "mock", "real-state", "real-challenge")
	for key, want := range map[string]string{
		// The four the reference lets additionalAuthParams override.
		"client_id":     "override-client",
		"redirect_uri":  "https://evil.example.net/cb",
		"response_type": "token",
		"scope":         "openid email offline_access",
		// state is spread after the entries in the reference.
		"state": "real-state",
		// PKCE, this port's addition, is likewise not overridable.
		"code_challenge":        "real-challenge",
		"code_challenge_method": "S256",
	} {
		if got := q[key]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want exactly [%q]", key, got, want)
		}
	}
}

// google.strategy.ts:24-31 sends access_type=offline and nothing else beyond
// the standard parameters — no prompt.
func TestGoogleProvider_AuthorizeURL_AccessTypeOffline(t *testing.T) {
	svc := NewOAuthService(GoogleProvider("gid", "gsecret", "https://example.com/callback"))
	q := authorizeQuery(t, svc, "google", "s", "")
	if got := q.Get("access_type"); got != "offline" {
		t.Fatalf("access_type = %q, want %q", got, "offline")
	}
	if _, present := q["prompt"]; present {
		t.Fatalf("prompt = %q, the reference sends none", q.Get("prompt"))
	}
	if got := q.Get("scope"); got != "openid email profile" {
		t.Fatalf("scope = %q, want %q (google.strategy.ts:28)", got, "openid email profile")
	}
}

// fakeUserInfoServer serves a token endpoint that always succeeds and a
// userinfo endpoint answering the given JSON. It records what reached the
// optional /user/emails endpoint so the GitHub fallback can be asserted.
type fakeUserInfoServer struct {
	*httptest.Server
	mu           sync.Mutex
	emailsCalls  int
	emailsAuth   string
	emailsAccept string
}

func newFakeUserInfoServer(t *testing.T, userinfo, emails string, emailsStatus int) *fakeUserInfoServer {
	t.Helper()
	f := &fakeUserInfoServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"provider-access-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userinfo))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.emailsCalls++
		f.emailsAuth = r.Header.Get("Authorization")
		f.emailsAccept = r.Header.Get("Accept")
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(emailsStatus)
		_, _ = w.Write([]byte(emails))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeUserInfoServer) provider(name string) OAuthProvider {
	return OAuthProvider{
		Name:         name,
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "https://api.example.com/cb",
		AuthURL:      "https://provider.example.com/authorize",
		TokenURL:     f.URL + "/token",
		UserInfoURL:  f.URL + "/user",
	}
}

func boolPtr(b bool) *bool { return &b }

func describeBool(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

// email_verified maps onto EmailVerified as the reference's `raw.email_verified
// as boolean | undefined` does (generic-oauth.strategy.ts:157; Google
// google.strategy.ts:58): a boolean is taken, absence is nil, and a value that
// is not a boolean is not coerced.
func TestOAuthService_ExchangeCode_EmailVerified(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider string
		userinfo string
		want     *bool
	}{
		{"generic true", "acme", `{"id":"1","email":"a@example.com","email_verified":true}`, boolPtr(true)},
		{"generic false", "acme", `{"id":"1","email":"a@example.com","email_verified":false}`, boolPtr(false)},
		{"generic absent", "acme", `{"id":"1","email":"a@example.com"}`, nil},
		{"generic null", "acme", `{"id":"1","email":"a@example.com","email_verified":null}`, nil},
		{"generic string is not coerced", "acme", `{"id":"1","email":"a@example.com","email_verified":"true"}`, nil},
		{"google true", "google", `{"sub":"g1","email":"g@example.com","email_verified":true}`, boolPtr(true)},
		{"google false", "google", `{"sub":"g1","email":"g@example.com","email_verified":false}`, boolPtr(false)},
		{"google absent", "google", `{"sub":"g1","email":"g@example.com"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeUserInfoServer(t, tc.userinfo, "[]", http.StatusOK)
			svc := NewOAuthService(srv.provider(tc.provider))
			info, err := svc.ExchangeCode(context.Background(), tc.provider, "code")
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}
			if describeBool(info.EmailVerified) != describeBool(tc.want) {
				t.Fatalf("EmailVerified = %s, want %s", describeBool(info.EmailVerified), describeBool(tc.want))
			}
		})
	}
}

// The default subject mapping is the reference's String(raw.id ?? raw.sub ?? "")
// (generic-oauth.strategy.ts:155): id first, then sub. user_id is this port's
// extra last resort, and a JSON number renders without a decimal point.
func TestOAuthService_ExchangeCode_SubjectIDPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		userinfo string
		want     string
	}{
		{"id wins over sub", `{"id":"the-id","sub":"the-sub","user_id":"the-user-id"}`, "the-id"},
		{"sub when id is absent", `{"sub":"the-sub","user_id":"the-user-id"}`, "the-sub"},
		{"user_id as the last resort", `{"user_id":"the-user-id"}`, "the-user-id"},
		{"a numeric id is stringified", `{"id":12345,"sub":"the-sub"}`, "12345"},
		{"an empty id falls through to sub", `{"id":"","sub":"the-sub"}`, "the-sub"},
		{"a non-scalar id falls through", `{"id":{"nested":true},"sub":"the-sub"}`, "the-sub"},
		{"nothing usable", `{"email":"x@example.com"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeUserInfoServer(t, tc.userinfo, "[]", http.StatusOK)
			svc := NewOAuthService(srv.provider("acme"))
			info, err := svc.ExchangeCode(context.Background(), "acme", "code")
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}
			if info.ProviderID != tc.want {
				t.Fatalf("ProviderID = %q, want %q", info.ProviderID, tc.want)
			}
		})
	}
}

// github.strategy.ts:59-69: a profile with no email is completed from
// /user/emails, sent with `Authorization: token <access_token>` and the v3
// Accept header (:55), choosing the primary AND verified entry, else the first
// one (:64-67); emailVerified is that entry's verified flag. When the profile
// has an email the endpoint's answer is not consulted, and a failing endpoint
// leaves the email empty rather than failing the exchange (:62).
func TestOAuthService_ExchangeCode_GitHubEmailFallback(t *testing.T) {
	const twoEmails = `[{"email":"secondary@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`
	for _, tc := range []struct {
		name         string
		userinfo     string
		emails       string
		emailsStatus int
		wantEmail    string
		wantVerified *bool
		wantCalls    int
	}{
		{
			name:         "picks the primary verified entry",
			userinfo:     `{"id":42,"login":"octo","avatar_url":"https://a/octo.png"}`,
			emails:       twoEmails,
			emailsStatus: http.StatusOK,
			wantEmail:    "primary@example.com",
			wantVerified: boolPtr(true),
			wantCalls:    1,
		},
		{
			name:         "falls back to the first entry",
			userinfo:     `{"id":42,"login":"octo"}`,
			emails:       `[{"email":"first@example.com","primary":false,"verified":false},{"email":"unverified-primary@example.com","primary":true,"verified":false}]`,
			emailsStatus: http.StatusOK,
			wantEmail:    "first@example.com",
			wantVerified: boolPtr(false),
			wantCalls:    1,
		},
		{
			name:         "a profile email skips the endpoint",
			userinfo:     `{"id":42,"login":"octo","email":"public@example.com"}`,
			emails:       twoEmails,
			emailsStatus: http.StatusOK,
			wantEmail:    "public@example.com",
			wantVerified: nil,
			wantCalls:    0,
		},
		{
			name:         "a failing endpoint leaves the email empty",
			userinfo:     `{"id":42,"login":"octo"}`,
			emails:       `{"message":"Requires authentication"}`,
			emailsStatus: http.StatusUnauthorized,
			wantEmail:    "",
			wantVerified: nil,
			wantCalls:    1,
		},
		{
			name:         "an empty list leaves the email empty",
			userinfo:     `{"id":42,"login":"octo"}`,
			emails:       `[]`,
			emailsStatus: http.StatusOK,
			wantEmail:    "",
			wantVerified: nil,
			wantCalls:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeUserInfoServer(t, tc.userinfo, tc.emails, tc.emailsStatus)
			// GitHubEmailsURL is left empty on purpose: the endpoint derives from
			// UserInfoURL, which is how the preset's real values line up too.
			svc := NewOAuthService(srv.provider("github"))
			info, err := svc.ExchangeCode(context.Background(), "github", "code")
			if err != nil {
				t.Fatalf("ExchangeCode: %v", err)
			}
			if info.ProviderID != "42" {
				t.Errorf("ProviderID = %q, want %q (String(user.id))", info.ProviderID, "42")
			}
			if info.Name != "octo" {
				t.Errorf("Name = %q, want the login %q when name is absent", info.Name, "octo")
			}
			if info.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", info.Email, tc.wantEmail)
			}
			if describeBool(info.EmailVerified) != describeBool(tc.wantVerified) {
				t.Errorf("EmailVerified = %s, want %s", describeBool(info.EmailVerified), describeBool(tc.wantVerified))
			}
			srv.mu.Lock()
			defer srv.mu.Unlock()
			if srv.emailsCalls != tc.wantCalls {
				t.Fatalf("/user/emails was called %d times, want %d", srv.emailsCalls, tc.wantCalls)
			}
			if tc.wantCalls > 0 {
				if srv.emailsAuth != "token provider-access-token" {
					t.Errorf("Authorization = %q, want %q (github.strategy.ts:55)", srv.emailsAuth, "token provider-access-token")
				}
				if srv.emailsAccept != "application/vnd.github.v3+json" {
					t.Errorf("Accept = %q, want %q", srv.emailsAccept, "application/vnd.github.v3+json")
				}
			}
		})
	}

	t.Run("GitHubEmailsURL overrides the derived endpoint", func(t *testing.T) {
		srv := newFakeUserInfoServer(t, `{"id":42,"login":"octo"}`, twoEmails, http.StatusOK)
		other := newFakeUserInfoServer(t, `{}`, `[{"email":"elsewhere@example.com","primary":true,"verified":true}]`, http.StatusOK)
		p := srv.provider("github")
		p.GitHubEmailsURL = other.URL + "/user/emails"
		svc := NewOAuthService(p)
		info, err := svc.ExchangeCode(context.Background(), "github", "code")
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if info.Email != "elsewhere@example.com" {
			t.Fatalf("Email = %q, want the override endpoint's %q", info.Email, "elsewhere@example.com")
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.emailsCalls != 0 {
			t.Fatalf("the derived endpoint was still called %d times", srv.emailsCalls)
		}
	})

	// The reference prefers the display name and falls back to the login
	// (github.strategy.ts:69).
	t.Run("name wins over login", func(t *testing.T) {
		srv := newFakeUserInfoServer(t, `{"id":42,"login":"octo","name":"Octo Cat","email":"o@example.com"}`, "[]", http.StatusOK)
		svc := NewOAuthService(srv.provider("github"))
		info, err := svc.ExchangeCode(context.Background(), "github", "code")
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if info.Name != "Octo Cat" {
			t.Fatalf("Name = %q, want %q", info.Name, "Octo Cat")
		}
	})
}

// ─── MemoryLinkedAccounts ─────────────────────────────────────────────────────

func TestMemoryLinkedAccounts_SaveAndFind(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	ctx := context.Background()
	link := OAuthLinkedAccount{
		ID:         "link_001",
		UserID:     "u1",
		Provider:   "google",
		ProviderID: "g123",
		CreatedAt:  time.Now(),
	}
	if err := store.Save(ctx, link); err != nil {
		t.Fatalf("Save: %v", err)
	}
	found, err := store.FindByProvider(ctx, "google", "g123")
	if err != nil {
		t.Fatalf("FindByProvider: %v", err)
	}
	if found.UserID != "u1" {
		t.Fatalf("unexpected user ID: %s", found.UserID)
	}
}

func TestMemoryLinkedAccounts_FindByProvider_NotFound(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	_, err := store.FindByProvider(context.Background(), "google", "nobody")
	if err == nil {
		t.Fatal("expected error for unknown provider account")
	}
}

func TestMemoryLinkedAccounts_ListForUser(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	ctx := context.Background()
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l1", UserID: "u1", Provider: "google", ProviderID: "g1"})
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l2", UserID: "u1", Provider: "github", ProviderID: "gh1"})
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l3", UserID: "u2", Provider: "google", ProviderID: "g2"})
	links, err := store.ListForUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links for u1, got %d", len(links))
	}
}

func TestMemoryLinkedAccounts_ListForUser_Empty(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	links, err := store.ListForUser(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("expected empty list, got %d", len(links))
	}
}

func TestMemoryLinkedAccounts_Delete(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	ctx := context.Background()
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l1", UserID: "u1", Provider: "google", ProviderID: "g1"})
	if err := store.Delete(ctx, "l1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := store.FindByProvider(ctx, "google", "g1")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestMemoryLinkedAccounts_DuplicateSave_Overwrites(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	ctx := context.Background()
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l1", UserID: "u1", Provider: "google", ProviderID: "g1"})
	// Overwrite with updated link
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "l1", UserID: "u2", Provider: "google", ProviderID: "g1"})
	found, err := store.FindByProvider(ctx, "google", "g1")
	if err != nil {
		t.Fatalf("FindByProvider: %v", err)
	}
	if found.UserID != "u2" {
		t.Fatalf("expected overwritten user, got %s", found.UserID)
	}
}

func TestMemoryLinkedAccounts_MultipleProviders(t *testing.T) {
	store := NewMemoryLinkedAccounts()
	ctx := context.Background()
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "la", UserID: "u1", Provider: "google", ProviderID: "ga"})
	_ = store.Save(ctx, OAuthLinkedAccount{ID: "lb", UserID: "u1", Provider: "github", ProviderID: "gb"})
	google, _ := store.FindByProvider(ctx, "google", "ga")
	github, _ := store.FindByProvider(ctx, "github", "gb")
	if google.Provider != "google" || github.Provider != "github" {
		t.Fatal("each provider should resolve independently")
	}
}
