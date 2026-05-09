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
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
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
