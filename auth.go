package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Auth is the top-level entrypoint configured with functional options.
type Auth struct {
	service *Service
	// oauth is nil unless WithOAuth was supplied; see oauth_wire.go.
	oauth *OAuthWiring
}

// Option configures Auth initialization.
type Option func(*authBuilder) error

type authBuilder struct {
	cfg      Config
	users    UserStore
	sessions SessionStore
	svcOpts  []ServiceOption
	oauth    *OAuthWiring
}

// New creates a configured Auth instance from the package defaults.
func New(opts ...Option) (*Auth, error) {
	return NewWithConfig(DefaultConfig("01234567890123456789012345678901"), opts...)
}

// NewWithConfig creates a configured Auth instance from a pre-populated Config,
// with any Options applied in order on top of it.
//
// New builds its Config internally and the exported Option set has always been
// narrower than Config, so fields with no matching Option — the individual TTLs,
// EmailVerificationMode, and until now BcryptCost — were unreachable from
// outside the package (#25). Accepting the struct closes that whole class of gap
// at once and cannot drift as Config grows, which one-Option-per-field would.
// The Options remain as sugar and still compose with a supplied Config.
//
// cfg is validated by NewService exactly as New's is; a hand-built Config that
// omits, say, the TTLs is rejected rather than silently defaulted.
func NewWithConfig(cfg Config, opts ...Option) (*Auth, error) {
	b := &authBuilder{cfg: cfg}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(b); err != nil {
			return nil, err
		}
	}
	if b.users == nil {
		b.users = NewMemoryUserStore()
	}
	if b.sessions == nil {
		b.sessions = NewMemorySessionStore()
	}
	svc, err := NewService(b.cfg, b.users, b.sessions, b.svcOpts...)
	if err != nil {
		return nil, err
	}
	return &Auth{service: svc, oauth: b.oauth}, nil
}

// Service exposes the configured core service.
func (a *Auth) Service() *Service { return a.service }

// WithSecret configures the JWT signing secret.
func WithSecret(secret string) Option {
	return func(b *authBuilder) error {
		b.cfg.Secret = secret
		return nil
	}
}

// WithIssuer configures token issuer.
func WithIssuer(issuer string) Option {
	return func(b *authBuilder) error {
		b.cfg.Issuer = issuer
		return nil
	}
}

// WithTokenTTLs configures access and refresh TTL.
func WithTokenTTLs(access, refresh time.Duration) Option {
	return func(b *authBuilder) error {
		if access <= 0 || refresh <= 0 {
			return errors.New("auth: ttl must be > 0")
		}
		b.cfg.AccessTokenTTL = access
		b.cfg.RefreshTokenTTL = refresh
		return nil
	}
}

// WithBcryptCost sets the bcrypt cost used for every password hash the library
// writes. See Config.BcryptCost.
//
// Unlike the zero value of Config.BcryptCost, which means "unset" and resolves
// to bcrypt.DefaultCost, calling this Option with 0 is an error: an explicit
// setter reached with an unset value is a caller mistake, not a request for the
// default. Omit the Option to get the default.
func WithBcryptCost(cost int) Option {
	return func(b *authBuilder) error {
		if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
			// The remedy has to be in the message. An operator who reaches this
			// with an unparsed or unset value sees only a rejected range, and
			// the cheapest way out of a rejected range is to pass MinCost —
			// which is the one outcome this whole change exists to prevent.
			return fmt.Errorf("auth: bcrypt cost must be between %d and %d; omit WithBcryptCost to get the default (%d)", bcrypt.MinCost, bcrypt.MaxCost, bcrypt.DefaultCost)
		}
		b.cfg.BcryptCost = cost
		return nil
	}
}

// WithUserStore sets a custom UserStore implementation.
func WithUserStore(store UserStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: user store is required")
		}
		b.users = store
		return nil
	}
}

// WithSessionStore sets a custom SessionStore implementation.
func WithSessionStore(store SessionStore) Option {
	return func(b *authBuilder) error {
		if store == nil {
			return errors.New("auth: session store is required")
		}
		b.sessions = store
		return nil
	}
}

// WithMetadataProvider wires optional metadata support.
func WithMetadataProvider(store UserMetadataStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithMetadataStore(store))
		return nil
	}
}

// WithRBACProvider wires optional role/permission support.
func WithRBACProvider(store RolesPermissionsStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithRolesPermissionsStore(store))
		return nil
	}
}

// WithTenantProvider wires optional tenant support.
func WithTenantProvider(store TenantStore) Option {
	return func(b *authBuilder) error {
		b.svcOpts = append(b.svcOpts, WithTenantStore(store))
		return nil
	}
}

// WithRequire2FA enables mandatory second-factor login checks.
func WithRequire2FA(enabled bool) Option {
	return func(b *authBuilder) error {
		b.cfg.Require2FA = enabled
		return nil
	}
}

// WithTokenClaimsBuilder customizes token claims creation.
func WithTokenClaimsBuilder(fn func(ctx context.Context, user User) (map[string]any, error)) Option {
	return func(b *authBuilder) error {
		b.cfg.BuildTokenClaims = fn
		return nil
	}
}

// WithMagicLinkSender wires magic-link delivery. Without it POST
// <prefix>/magic-link/send answers 500 EMAIL_NOT_CONFIGURED, because the route
// cannot put the link in its response body.
//
// Pass a callback to send the mail yourself, or MagicLinkMailer.Send to use the
// built-in templates over a MailerTransport.
func WithMagicLinkSender(sender MagicLinkSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: magic link sender is required")
		}
		b.cfg.SendMagicLink = sender
		return nil
	}
}

// WithSMSCodeSender wires SMS delivery. Without it POST <prefix>/sms/send
// answers 500 SMS_NOT_CONFIGURED.
//
// Pass a callback to send the message yourself, or SMSTransportSender over an
// SMSTransport such as HTTPSMSTransport.
func WithSMSCodeSender(sender SMSCodeSender) Option {
	return func(b *authBuilder) error {
		if sender == nil {
			return errors.New("auth: sms code sender is required")
		}
		b.cfg.SendSMSCode = sender
		return nil
	}
}

// WithLogger provides optional library logging callback.
func WithLogger(fn func(format string, args ...any)) Option {
	return func(b *authBuilder) error {
		b.cfg.Logger = fn
		return nil
	}
}

// Register delegates to Service.Register.
func (a *Auth) Register(ctx context.Context, in RegisterInput) (User, AuthTokens, error) {
	return a.service.Register(ctx, in)
}

// Login delegates to Service.Login.
func (a *Auth) Login(ctx context.Context, in LoginInput) (User, AuthTokens, error) {
	return a.service.Login(ctx, in)
}

// Refresh delegates to Service.Refresh.
func (a *Auth) Refresh(ctx context.Context, refreshToken string) (AuthTokens, error) {
	return a.service.Refresh(ctx, refreshToken)
}

// Logout delegates to Service.Logout.
func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	return a.service.Logout(ctx, refreshToken)
}

// Me delegates to Service.Me.
func (a *Auth) Me(ctx context.Context, accessToken string) (User, error) {
	return a.service.Me(ctx, accessToken)
}

// UpdateProfile delegates to Service.UpdateProfile.
func (a *Auth) UpdateProfile(ctx context.Context, in UpdateProfileInput) (User, error) {
	return a.service.UpdateProfile(ctx, in)
}

// DeleteAccount delegates to Service.DeleteAccount.
func (a *Auth) DeleteAccount(ctx context.Context, in DeleteAccountInput) error {
	return a.service.DeleteAccount(ctx, in)
}
