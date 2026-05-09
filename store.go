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
