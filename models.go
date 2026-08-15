package auth

import "time"

// User is the canonical identity model.
type User struct {
	ID                           string
	Email                        string
	PasswordHash                 string
	TenantID                     string
	PhoneNumber                  string
	FirstName                    string
	LastName                     string
	Role                         string
	IsEmailVerified              bool
	Require2FA                   bool
	IsTOTPEnabled                bool
	TOTPSecret                   string
	ResetTokenHash               string
	ResetTokenExpiresAt          *time.Time
	MagicLinkTokenHash           string
	MagicLinkTokenExpiresAt      *time.Time
	SMSCodeHash                  string
	SMSCodeExpiresAt             *time.Time
	EmailVerificationTokenHash   string
	EmailVerificationTokenExpiry *time.Time
	PendingEmail                 string
	EmailChangeTokenHash         string
	EmailChangeTokenExpiry       *time.Time
	Metadata                     map[string]any
	Roles                        []string
	Permissions                  []string
	Tenants                      []Tenant
	CustomClaims                 map[string]any
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
}

// Tenant represents an isolated workspace or organization.
type Tenant struct {
	ID        string
	Name      string
	IsActive  bool
	Config    map[string]any
	CreatedAt time.Time
}

// PublicUser is the response-safe projection of User. It is the only user shape
// adapters may serialise: credential material (password hash, TOTP secret,
// one-time token hashes and the pending email change) is deliberately absent.
type PublicUser struct {
	// Sub is the identifier under the name the reference uses and the shipped
	// clients require. Both cast it non-nullably — awesome-node-auth-flutter
	// does `json['sub'] as String` (auth_user.dart:76) and ng-awesome-node-auth
	// declares `sub: string` (auth.service.ts:10) — so omitting it does not
	// degrade a client, it throws inside one. It duplicates ID rather than
	// replacing it because `id` shipped in 0.2.0 and both clients read that as
	// optional, so emitting both breaks nobody.
	Sub   string `json:"sub"`
	ID    string `json:"id"`
	Email string `json:"email"`
	// Role is the reference's single-role field, distinct from Roles. Omitted
	// when empty, which it always is until something writes it.
	Role            string         `json:"role,omitempty"`
	TenantID        string         `json:"tenantId,omitempty"`
	FirstName       string         `json:"firstName,omitempty"`
	LastName        string         `json:"lastName,omitempty"`
	PhoneNumber     string         `json:"phoneNumber,omitempty"`
	IsEmailVerified bool           `json:"isEmailVerified"`
	IsTOTPEnabled   bool           `json:"isTotpEnabled"`
	Roles           []string       `json:"roles,omitempty"`
	Permissions     []string       `json:"permissions,omitempty"`
	Tenants         []PublicTenant `json:"tenants,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CustomClaims    map[string]any `json:"customClaims,omitempty"`
	CreatedAt       time.Time      `json:"createdAt"`
}

// PublicTenant is the response-safe projection of Tenant. The tenant Config
// blob is server-side configuration and is never serialised.
type PublicTenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
}

// NewPublicUser projects a User onto its response-safe representation.
func NewPublicUser(user User) PublicUser {
	public := PublicUser{
		Sub:             user.ID,
		ID:              user.ID,
		Email:           user.Email,
		Role:            user.Role,
		TenantID:        user.TenantID,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		PhoneNumber:     user.PhoneNumber,
		IsEmailVerified: user.IsEmailVerified,
		IsTOTPEnabled:   user.IsTOTPEnabled,
		Roles:           user.Roles,
		Permissions:     user.Permissions,
		Metadata:        user.Metadata,
		CustomClaims:    user.CustomClaims,
		CreatedAt:       user.CreatedAt,
	}
	if len(user.Tenants) > 0 {
		public.Tenants = make([]PublicTenant, 0, len(user.Tenants))
		for _, tenant := range user.Tenants {
			public.Tenants = append(public.Tenants, PublicTenant{
				ID:        tenant.ID,
				Name:      tenant.Name,
				IsActive:  tenant.IsActive,
				CreatedAt: tenant.CreatedAt,
			})
		}
	}
	return public
}

// Session stores refresh-token bound session metadata.
type Session struct {
	ID               string
	UserID           string
	TenantID         string
	RefreshTokenHash string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
}

// AuthTokens are the issued access/refresh pair.
type AuthTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
}

// RegisterInput is the payload to create a user and initial session.
type RegisterInput struct {
	Email    string
	Password string
	TenantID string
}

// LoginInput is the payload used for user authentication.
type LoginInput struct {
	Email    string
	Password string
	TenantID string
}

type ForgotPasswordInput struct {
	Email    string
	TenantID string
}

type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

type MagicLinkSendInput struct {
	Email    string
	TenantID string
}

type MagicLinkVerifyInput struct {
	Token string
}

type SMSCodeSendInput struct {
	UserID   string
	Email    string
	TenantID string
}

type SMSCodeVerifyInput struct {
	UserID   string
	Email    string
	TenantID string
	Code     string
}

type ChangePasswordInput struct {
	UserID          string
	TenantID        string
	CurrentPassword string
	NewPassword     string
}

type EmailVerificationInput struct {
	UserID   string
	TenantID string
}

type VerifyEmailInput struct {
	Token string
}

type ChangeEmailRequestInput struct {
	UserID   string
	TenantID string
	NewEmail string
}

type ConfirmEmailChangeInput struct {
	Token string
}

// UpdateProfileInput is the payload behind PATCH /profile. FirstName and
// LastName are pointers because the route is a *partial* update: the reference
// types the body { firstName?: string | null, lastName?: string | null } and
// passes it through verbatim, so a key the caller omitted arrives at the store as
// undefined and leaves the stored column alone (wire-contract §3.5,
// user-store.interface.ts:136).
//
// nil therefore means "not submitted, leave as it is" and a pointer to "" means
// "clear it" — the distinction a plain string cannot carry, and without which
// sending only firstName silently erases the stored lastName.
type UpdateProfileInput struct {
	UserID    string
	TenantID  string
	FirstName *string
	LastName  *string
}

type DeleteAccountInput struct {
	UserID   string
	TenantID string
}
