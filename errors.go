package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrUserExists         = errors.New("auth: user already exists")
	ErrInvalidToken       = errors.New("auth: invalid token")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrSessionRevoked     = errors.New("auth: session revoked")
	ErrWeakPassword       = errors.New("auth: password is too weak")
)
