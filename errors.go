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
	ErrTenantNotFound      = errors.New("auth: tenant not found")
	ErrRoleNotFound        = errors.New("auth: role not found")

	// ErrEmailNotConfigured and ErrSMSNotConfigured mean the deployment has no
	// way to deliver the credential a send route just asked for. They are
	// deliberately not ErrFeatureNotSupported: that one says the configured
	// store cannot hold the column, and it is already on the wire as
	// NOT_IMPLEMENTED on these same routes. See delivery.go.
	ErrEmailNotConfigured = errors.New("auth: email delivery is not configured")
	ErrSMSNotConfigured   = errors.New("auth: sms delivery is not configured")
)
