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

// UserAccountStore adds account lifecycle operations.
type UserAccountStore interface {
	UpdateProfile(ctx context.Context, userID, tenantID, firstName, lastName string) (User, error)
	DeleteUser(ctx context.Context, userID, tenantID string) error
}

// SessionStore persists refresh-token sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) (Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (Session, error)
	UpdateSession(ctx context.Context, session Session) error
}

// SessionLookupStore resolves sessions by session ID.
type SessionLookupStore interface {
	GetSessionByID(ctx context.Context, sessionID string) (Session, error)
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

// UserMetadataStore manages arbitrary key/value user metadata.
type UserMetadataStore interface {
	GetMetadata(ctx context.Context, userID string) (map[string]any, error)
	UpdateMetadata(ctx context.Context, userID string, metadata map[string]any) error
	ClearMetadata(ctx context.Context, userID string) error
}

// RolesPermissionsStore manages RBAC assignments and permissions.
type RolesPermissionsStore interface {
	AddRoleToUser(ctx context.Context, userID, role string, tenantID string) error
	RemoveRoleFromUser(ctx context.Context, userID, role string, tenantID string) error
	GetRolesForUser(ctx context.Context, userID, tenantID string) ([]string, error)
	CreateRole(ctx context.Context, role string, permissions []string) error
	DeleteRole(ctx context.Context, role string) error
	AddPermissionToRole(ctx context.Context, role, permission string) error
	RemovePermissionFromRole(ctx context.Context, role, permission string) error
	GetPermissionsForRole(ctx context.Context, role string) ([]string, error)
	GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error)
	UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error)
}

// AuthCode is one OIDC authorization code as the IDP stores it between
// /authorize and /token. CodeHash is hashToken of the value the client was
// given; the clear-text code is never persisted. RedirectURI is the canonical
// entry from IDPClient.RedirectURIs that the authorization request matched.
// CodeChallenge, CodeChallengeMethod and Scope are recorded from the
// authorization request as plain data: this package does not verify them yet,
// but carrying them now means a store written today needs no schema change
// when /token starts to.
type AuthCode struct {
	CodeHash            string
	UserID              string
	TenantID            string
	ClientID            string
	Nonce               string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	ExpiresAt           time.Time
}

// AuthCodeStore persists OIDC authorization codes for the IDP.
//
// Design note. The IDP endpoints are net-new relative to the TypeScript
// reference, which ships no authorization server, so there is no wire contract
// to cite; the shape below is chosen for the runtimes this library targets.
//
//   - The store is keyed by hashToken(code), never by the code itself. The
//     client carries a 24-byte random token in the redirect; the store sees
//     only its SHA-256, so a dump of the backing table cannot be redeemed at
//     /token. This matches how refresh tokens, reset tokens and magic links
//     are already held.
//   - ConsumeCode is the only read and it is destructive: it returns a record
//     exactly once and answers ErrInvalidCode for every later call with the
//     same hash, including concurrent ones. That is the single-use guarantee
//     /token relies on. It used to come from a process-local map, which holds
//     only while /authorize and /token run in the same process; a serverless
//     or multi-instance deployment must supply a shared implementation via
//     IDPConfig.Codes, and its ConsumeCode must be atomic (a conditional
//     delete, a row lock, or a DEL-and-check pipeline, not a read followed by a
//     delete).
//   - An expired record is absent: ConsumeCode returns ErrInvalidCode for it
//     and is free to delete it. Implementations may also sweep expired rows on
//     SaveCode or on a schedule. The handler re-checks ExpiresAt regardless.
//   - SaveCode overwrites an existing record with the same CodeHash. The codes
//     are random, so in practice this never happens; the rule exists so an
//     implementation need not detect the collision.
//   - Errors other than ErrInvalidCode are surfaced by /authorize and /token as
//     plain 500s; the store is not expected to map them.
type AuthCodeStore interface {
	SaveCode(ctx context.Context, code AuthCode) error
	ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error)
}

// TenantStore manages tenants and user memberships.
type TenantStore interface {
	CreateTenant(ctx context.Context, tenant Tenant) (Tenant, error)
	GetTenantByID(ctx context.Context, id string) (Tenant, error)
	GetAllTenants(ctx context.Context) ([]Tenant, error)
	UpdateTenant(ctx context.Context, id string, update Tenant) error
	DeleteTenant(ctx context.Context, id string) error
	AssociateUserWithTenant(ctx context.Context, userID, tenantID string) error
	DisassociateUserFromTenant(ctx context.Context, userID, tenantID string) error
	GetTenantsForUser(ctx context.Context, userID string) ([]Tenant, error)
	GetUsersForTenant(ctx context.Context, tenantID string) ([]string, error)
}
