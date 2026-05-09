package auth

import (
	"errors"
	"time"
)

// Config contains security and token settings for the auth service.
type Config struct {
	Secret               string
	Issuer               string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	ClockSkew            time.Duration
	MinPasswordLen       int
	ResetTokenTTL        time.Duration
	MagicLinkTTL         time.Duration
	SMSCodeTTL           time.Duration
	EmailVerificationTTL time.Duration
	EmailChangeTTL       time.Duration
	TempTokenTTL         time.Duration
	Require2FA           bool
}

// DefaultConfig returns secure defaults for development and production bootstrap.
func DefaultConfig(secret string) Config {
	return Config{
		Secret:               secret,
		Issuer:               "awesome-go-auth",
		AccessTokenTTL:       15 * time.Minute,
		RefreshTokenTTL:      30 * 24 * time.Hour,
		ClockSkew:            30 * time.Second,
		MinPasswordLen:       8,
		ResetTokenTTL:        1 * time.Hour,
		MagicLinkTTL:         15 * time.Minute,
		SMSCodeTTL:           10 * time.Minute,
		EmailVerificationTTL: 24 * time.Hour,
		EmailChangeTTL:       1 * time.Hour,
		TempTokenTTL:         5 * time.Minute,
	}
}

func (c Config) validate() error {
	if len(c.Secret) < 32 {
		return errors.New("auth: secret must be at least 32 chars")
	}
	if c.AccessTokenTTL <= 0 {
		return errors.New("auth: access token ttl must be > 0")
	}
	if c.RefreshTokenTTL <= 0 {
		return errors.New("auth: refresh token ttl must be > 0")
	}
	if c.MinPasswordLen < 8 {
		return errors.New("auth: min password len must be >= 8")
	}
	if c.ResetTokenTTL <= 0 || c.MagicLinkTTL <= 0 || c.SMSCodeTTL <= 0 {
		return errors.New("auth: reset token, magic link, and sms code ttl must be > 0")
	}
	if c.EmailVerificationTTL <= 0 || c.EmailChangeTTL <= 0 || c.TempTokenTTL <= 0 {
		return errors.New("auth: email and temp token ttl must be > 0")
	}
	return nil
}
