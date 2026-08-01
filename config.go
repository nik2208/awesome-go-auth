package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	SessionCheckOnAllCalls = "allcalls"
	SessionCheckOnRefresh  = "refresh"
	SessionCheckOnNone     = "none"
)

// Email verification modes accepted by Config.EmailVerificationMode.
//
//	none   : verification is never required; Register marks the address verified.
//	lazy   : Register leaves the address unverified but login is still allowed.
//	strict : Register leaves the address unverified and login is refused until
//	         the address is confirmed.
const (
	EmailVerificationModeNone   = "none"
	EmailVerificationModeLazy   = "lazy"
	EmailVerificationModeStrict = "strict"
)

// Config contains security and token settings for the auth service.
type Config struct {
	Secret                string
	Issuer                string
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	SessionCheckOn        string
	ClockSkew             time.Duration
	MinPasswordLen        int
	ResetTokenTTL         time.Duration
	MagicLinkTTL          time.Duration
	SMSCodeTTL            time.Duration
	EmailVerificationTTL  time.Duration
	EmailVerificationMode string
	EmailChangeTTL        time.Duration
	TempTokenTTL          time.Duration
	Require2FA            bool
	BuildTokenClaims      func(ctx context.Context, user User) (map[string]any, error)
	Logger                func(format string, args ...any)
}

// DefaultConfig returns secure defaults for development and production bootstrap.
func DefaultConfig(secret string) Config {
	return Config{
		Secret:                secret,
		Issuer:                "awesome-go-auth",
		AccessTokenTTL:        15 * time.Minute,
		RefreshTokenTTL:       30 * 24 * time.Hour,
		SessionCheckOn:        SessionCheckOnRefresh,
		ClockSkew:             30 * time.Second,
		MinPasswordLen:        8,
		ResetTokenTTL:         1 * time.Hour,
		MagicLinkTTL:          15 * time.Minute,
		SMSCodeTTL:            10 * time.Minute,
		EmailVerificationTTL:  24 * time.Hour,
		EmailVerificationMode: EmailVerificationModeNone,
		EmailChangeTTL:        1 * time.Hour,
		TempTokenTTL:          5 * time.Minute,
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
	switch strings.ToLower(strings.TrimSpace(c.SessionCheckOn)) {
	case "", SessionCheckOnAllCalls, SessionCheckOnRefresh, SessionCheckOnNone:
	default:
		return errors.New("auth: session check mode must be one of allcalls|refresh|none")
	}
	switch strings.ToLower(strings.TrimSpace(c.EmailVerificationMode)) {
	case "", EmailVerificationModeNone, EmailVerificationModeLazy, EmailVerificationModeStrict:
	default:
		return errors.New("auth: email verification mode must be one of none|lazy|strict")
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
