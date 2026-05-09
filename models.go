package auth

import "time"

// User is the canonical identity model.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	TenantID     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
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
