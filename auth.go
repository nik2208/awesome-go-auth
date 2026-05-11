package auth

import (
	"context"
	"errors"
	"time"
)

// Auth is the top-level entrypoint configured with functional options.
type Auth struct {
	service *Service
}

// Option configures Auth initialization.
type Option func(*authBuilder) error

type authBuilder struct {
	cfg      Config
	users    UserStore
	sessions SessionStore
	svcOpts  []ServiceOption
}

// New creates a configured Auth instance.
func New(opts ...Option) (*Auth, error) {
	b := &authBuilder{cfg: DefaultConfig("01234567890123456789012345678901")}
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
	return &Auth{service: svc}, nil
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
