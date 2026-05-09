package auth

import "errors"

var (
	ErrInvalidCredentials  = errors.New("auth: invalid credentials")
	ErrUserExists          = errors.New("auth: user already exists")
	ErrInvalidToken        = errors.New("auth: invalid token")
	ErrSessionNotFound     = errors.New("auth: session not found")
	ErrSessionRevoked      = errors.New("auth: session revoked")
	ErrWeakPassword        = errors.New("auth: password is too weak")
	ErrFeatureNotSupported = errors.New("auth: feature not supported by configured stores")
	ErrEmailNotVerified    = errors.New("auth: email not verified")
	ErrInvalidCode         = errors.New("auth: invalid code")
	ErrTwoFactorRequired   = errors.New("auth: two-factor authentication required")
	ErrAlreadyExists       = errors.New("auth: resource already exists")
)
