package auth

import (
	"context"
	"time"
)

// UserStore persists and resolves users.
type UserStore interface {
	CreateUser(ctx context.Context, user User) (User, error)
	GetUserByEmail(ctx context.Context, email, tenantID string) (User, error)
	GetUserByID(ctx context.Context, id, tenantID string) (User, error)
}

// SessionStore persists refresh-token sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) (Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (Session, error)
	UpdateSession(ctx context.Context, session Session) error
}

// UserPasswordStore adds password lifecycle methods.
type UserPasswordStore interface {
	UpdatePassword(ctx context.Context, userID, tenantID, passwordHash string) error
	UpdateResetToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByResetTokenHash(ctx context.Context, tokenHash string) (User, error)
	ClearResetToken(ctx context.Context, userID, tenantID string) error
}

// MagicLinkStore persists magic link state.
type MagicLinkStore interface {
	UpdateMagicLinkToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByMagicLinkTokenHash(ctx context.Context, tokenHash string) (User, error)
	ClearMagicLinkToken(ctx context.Context, userID, tenantID string) error
}

// SMSStore persists sms code state.
type SMSStore interface {
	UpdateSMSCode(ctx context.Context, userID, tenantID, codeHash string, expiry time.Time) error
	GetUserBySMSCodeHash(ctx context.Context, userID, tenantID, codeHash string) (User, error)
	ClearSMSCode(ctx context.Context, userID, tenantID string) error
}

// TOTPStore persists authenticator setup.
type TOTPStore interface {
	UpdateTOTPSecret(ctx context.Context, userID, tenantID, secret string, enabled bool) error
}

// EmailVerificationStore persists verification flow.
type EmailVerificationStore interface {
	UpdateEmailVerificationToken(ctx context.Context, userID, tenantID, tokenHash string, expiry time.Time) error
	GetUserByEmailVerificationTokenHash(ctx context.Context, tokenHash string) (User, error)
	MarkEmailVerified(ctx context.Context, userID, tenantID string, verified bool) error
	ClearEmailVerificationToken(ctx context.Context, userID, tenantID string) error
}

// EmailChangeStore persists pending email change flow.
type EmailChangeStore interface {
	UpdateEmailChangeToken(ctx context.Context, userID, tenantID, pendingEmail, tokenHash string, expiry time.Time) error
	GetUserByEmailChangeTokenHash(ctx context.Context, tokenHash string) (User, error)
	ApplyEmailChange(ctx context.Context, userID, tenantID string) error
	ClearEmailChangeToken(ctx context.Context, userID, tenantID string) error
}

// SessionAdminStore exposes session listing and cleanup primitives.
type SessionAdminStore interface {
	ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]Session, error)
	RevokeSessionByID(ctx context.Context, sessionID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}
