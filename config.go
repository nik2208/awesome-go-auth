package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCheckOnAllCalls = "allcalls"
	SessionCheckOnRefresh  = "refresh"
	SessionCheckOnNone     = "none"
)

// Email verification modes accepted by Config.EmailVerificationMode.
//
//	none   : Register marks the address verified, so verification never comes up
//	         on the self-registration path. An address left unverified by some
//	         other route (admin provisioning, a data import, a custom UserStore
//	         whose column defaults to false) is still refused at login. This is
//	         the default and is exactly how the service behaved before the mode
//	         existed.
//	lazy   : Register leaves the address unverified and login is allowed anyway.
//	         This is the only mode in which an unverified address may log in.
//	strict : Register leaves the address unverified and login is refused until
//	         the address is confirmed.
const (
	EmailVerificationModeNone   = "none"
	EmailVerificationModeLazy   = "lazy"
	EmailVerificationModeStrict = "strict"
)

// Config contains security and token settings for the auth service.
type Config struct {
	Secret          string
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SessionCheckOn  string
	ClockSkew       time.Duration
	MinPasswordLen  int
	// BcryptCost is the bcrypt cost used for every password hash the library
	// writes. It is this port's spelling of the reference's
	// AuthConfig.bcryptSaltRounds; "cost" is what x/crypto/bcrypt calls the
	// parameter, and what bcrypt.DefaultCost, MinCost and MaxCost name.
	//
	// Zero means unset, and unset means bcrypt.DefaultCost — never
	// bcrypt.MinCost. A Config that was never told a cost must not silently get
	// the weakest one. Any other value must lie in
	// [bcrypt.MinCost, bcrypt.MaxCost]; validate rejects the rest.
	BcryptCost            int
	ResetTokenTTL         time.Duration
	MagicLinkTTL          time.Duration
	SMSCodeTTL            time.Duration
	EmailVerificationTTL  time.Duration
	EmailVerificationMode string
	EmailChangeTTL        time.Duration
	TempTokenTTL          time.Duration
	Require2FA            bool
	BuildTokenClaims      func(ctx context.Context, user User) (map[string]any, error)
	// SendMagicLink and SendSMSCode are the delivery seam. Both are optional to
	// construct a service with and required to use the route that needs them:
	// leaving one nil is what makes POST <prefix>/magic-link/send answer 500
	// EMAIL_NOT_CONFIGURED and POST <prefix>/sms/send answer 500
	// SMS_NOT_CONFIGURED. See delivery.go for why they live here.
	SendMagicLink MagicLinkSender
	SendSMSCode   SMSCodeSender
	Logger        func(format string, args ...any)
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
		BcryptCost:            bcrypt.DefaultCost,
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
	if c.BcryptCost != 0 && (c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost) {
		return fmt.Errorf("auth: bcrypt cost must be between %d and %d, or 0 for the default (%d)", bcrypt.MinCost, bcrypt.MaxCost, bcrypt.DefaultCost)
	}
	if c.ResetTokenTTL <= 0 || c.MagicLinkTTL <= 0 || c.SMSCodeTTL <= 0 {
		return errors.New("auth: reset token, magic link, and sms code ttl must be > 0")
	}
	if c.EmailVerificationTTL <= 0 || c.EmailChangeTTL <= 0 || c.TempTokenTTL <= 0 {
		return errors.New("auth: email and temp token ttl must be > 0")
	}
	return nil
}
