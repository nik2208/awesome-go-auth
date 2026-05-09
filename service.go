package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Service is the main entry point for authentication operations.
type Service struct {
	cfg      Config
	users    UserStore
	sessions SessionStore
	metadata UserMetadataStore
	rbac     RolesPermissionsStore
	tenants  TenantStore
	now      func() time.Time
}

type ServiceOption func(*Service)

func WithMetadataStore(store UserMetadataStore) ServiceOption {
	return func(s *Service) { s.metadata = store }
}

func WithRolesPermissionsStore(store RolesPermissionsStore) ServiceOption {
	return func(s *Service) { s.rbac = store }
}

func WithTenantStore(store TenantStore) ServiceOption {
	return func(s *Service) { s.tenants = store }
}

// NewService builds an auth service with validated configuration.
func NewService(cfg Config, users UserStore, sessions SessionStore, opts ...ServiceOption) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if users == nil || sessions == nil {
		return nil, errors.New("auth: stores are required")
	}
	svc := &Service{
		cfg:      cfg,
		users:    users,
		sessions: sessions,
		now:      time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(svc)
		}
	}
	return svc, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *Service) Register(ctx context.Context, in RegisterInput) (User, AuthTokens, error) {
	var zeroTokens AuthTokens
	in.Email = normalizeEmail(in.Email)
	if len(in.Password) < s.cfg.MinPasswordLen {
		return User{}, zeroTokens, ErrWeakPassword
	}

	if _, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID); err == nil {
		return User{}, zeroTokens, ErrUserExists
	}

	pwHash, err := hashPassword(in.Password)
	if err != nil {
		return User{}, zeroTokens, err
	}
	userID, err := newID("usr")
	if err != nil {
		return User{}, zeroTokens, err
	}
	now := s.now()
	created, err := s.users.CreateUser(ctx, User{
		ID:              userID,
		Email:           in.Email,
		PasswordHash:    pwHash,
		TenantID:        in.TenantID,
		IsEmailVerified: true,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		return User{}, zeroTokens, fmt.Errorf("auth: create user: %w", err)
	}

	tokens, err := s.newSessionTokens(ctx, created)
	if err != nil {
		return User{}, zeroTokens, err
	}
	return created, tokens, nil
}

func (s *Service) Login(ctx context.Context, in LoginInput) (User, AuthTokens, error) {
	var zeroTokens AuthTokens
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil || !verifyPassword(in.Password, user.PasswordHash) {
		return User{}, zeroTokens, ErrInvalidCredentials
	}
	if !user.IsEmailVerified {
		return User{}, zeroTokens, ErrEmailNotVerified
	}
	if s.requiresTwoFactor(user) {
		return User{}, zeroTokens, ErrTwoFactorRequired
	}
	tokens, err := s.newSessionTokens(ctx, user)
	if err != nil {
		return User{}, zeroTokens, err
	}
	return user, tokens, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (AuthTokens, error) {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return AuthTokens{}, err
	}

	tokHash := hashToken(refreshToken)
	session, err := s.sessions.GetSessionByRefreshTokenHash(ctx, tokHash)
	if err != nil {
		return AuthTokens{}, ErrSessionNotFound
	}
	if session.RevokedAt != nil {
		return AuthTokens{}, ErrSessionRevoked
	}
	if s.now().After(session.ExpiresAt.Add(s.cfg.ClockSkew)) {
		return AuthTokens{}, ErrInvalidToken
	}
	if session.ID != claims.Sid || session.UserID != claims.Sub {
		return AuthTokens{}, ErrInvalidToken
	}

	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		return AuthTokens{}, ErrInvalidToken
	}

	newRefresh, refreshExp, err := s.issueToken(user, session.ID, "refresh", s.cfg.RefreshTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	newAccess, _, err := s.issueToken(user, session.ID, "access", s.cfg.AccessTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}

	session.RefreshTokenHash = hashToken(newRefresh)
	session.ExpiresAt = refreshExp
	if err := s.sessions.UpdateSession(ctx, session); err != nil {
		return AuthTokens{}, err
	}
	return AuthTokens{AccessToken: newAccess, RefreshToken: newRefresh, ExpiresIn: s.cfg.AccessTokenTTL}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return err
	}
	tokHash := hashToken(refreshToken)
	session, err := s.sessions.GetSessionByRefreshTokenHash(ctx, tokHash)
	if err != nil {
		return ErrSessionNotFound
	}
	if session.ID != claims.Sid {
		return ErrInvalidToken
	}
	now := s.now()
	session.RevokedAt = &now
	return s.sessions.UpdateSession(ctx, session)
}

func (s *Service) Me(ctx context.Context, accessToken string) (User, error) {
	claims, err := s.parseToken(accessToken, "access")
	if err != nil {
		return User{}, err
	}
	user, err := s.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		return User{}, ErrInvalidToken
	}
	return s.enrichUser(ctx, user)
}

func (s *Service) newSessionTokens(ctx context.Context, user User) (AuthTokens, error) {
	sessionID, err := newID("ses")
	if err != nil {
		return AuthTokens{}, err
	}
	refreshToken, refreshExp, err := s.issueToken(user, sessionID, "refresh", s.cfg.RefreshTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	accessToken, _, err := s.issueToken(user, sessionID, "access", s.cfg.AccessTokenTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	now := s.now()
	_, err = s.sessions.CreateSession(ctx, Session{
		ID:               sessionID,
		UserID:           user.ID,
		TenantID:         user.TenantID,
		RefreshTokenHash: hashToken(refreshToken),
		CreatedAt:        now,
		ExpiresAt:        refreshExp,
	})
	if err != nil {
		return AuthTokens{}, err
	}
	return AuthTokens{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: s.cfg.AccessTokenTTL}, nil
}

func (s *Service) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil {
		return "", nil
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	resetToken, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if err := ps.UpdateResetToken(ctx, user.ID, user.TenantID, hashToken(resetToken), s.now().Add(s.cfg.ResetTokenTTL)); err != nil {
		return "", err
	}
	return resetToken, nil
}

func (s *Service) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if len(in.NewPassword) < s.cfg.MinPasswordLen {
		return ErrWeakPassword
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := ps.GetUserByResetTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.ResetTokenExpiresAt == nil || s.now().After(user.ResetTokenExpiresAt.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	pwHash, err := hashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	if err := ps.UpdatePassword(ctx, user.ID, user.TenantID, pwHash); err != nil {
		return err
	}
	return ps.ClearResetToken(ctx, user.ID, user.TenantID)
}

func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	if len(in.NewPassword) < s.cfg.MinPasswordLen {
		return ErrWeakPassword
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return ErrInvalidCredentials
	}
	if !verifyPassword(in.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}
	ps, ok := s.users.(UserPasswordStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	pwHash, err := hashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	return ps.UpdatePassword(ctx, user.ID, user.TenantID, pwHash)
}

func (s *Service) SendMagicLink(ctx context.Context, in MagicLinkSendInput) (string, error) {
	ms, ok := s.users.(MagicLinkStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	in.Email = normalizeEmail(in.Email)
	user, err := s.users.GetUserByEmail(ctx, in.Email, in.TenantID)
	if err != nil {
		return "", nil
	}
	magicToken, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if err := ms.UpdateMagicLinkToken(ctx, user.ID, user.TenantID, hashToken(magicToken), s.now().Add(s.cfg.MagicLinkTTL)); err != nil {
		return "", err
	}
	return magicToken, nil
}

func (s *Service) VerifyMagicLink(ctx context.Context, in MagicLinkVerifyInput) (User, AuthTokens, error) {
	ms, ok := s.users.(MagicLinkStore)
	if !ok {
		return User{}, AuthTokens{}, ErrFeatureNotSupported
	}
	user, err := ms.GetUserByMagicLinkTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.MagicLinkTokenExpiresAt == nil || s.now().After(user.MagicLinkTokenExpiresAt.Add(s.cfg.ClockSkew)) {
		return User{}, AuthTokens{}, ErrInvalidToken
	}
	if err := ms.ClearMagicLinkToken(ctx, user.ID, user.TenantID); err != nil {
		return User{}, AuthTokens{}, err
	}
	if !user.IsEmailVerified {
		if evs, ok := s.users.(EmailVerificationStore); ok {
			_ = evs.MarkEmailVerified(ctx, user.ID, user.TenantID, true)
		}
		user.IsEmailVerified = true
	}
	tokens, err := s.newSessionTokens(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return user, tokens, nil
}

func (s *Service) SendSMSCode(ctx context.Context, in SMSCodeSendInput) (string, error) {
	ss, ok := s.users.(SMSStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	user, err := s.resolveUser(ctx, in.UserID, in.Email, in.TenantID)
	if err != nil || user.PhoneNumber == "" {
		return "", nil
	}
	code, err := randomNumericCode(6)
	if err != nil {
		return "", err
	}
	if err := ss.UpdateSMSCode(ctx, user.ID, user.TenantID, hashToken(code), s.now().Add(s.cfg.SMSCodeTTL)); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Service) VerifySMSCode(ctx context.Context, in SMSCodeVerifyInput) (User, AuthTokens, error) {
	ss, ok := s.users.(SMSStore)
	if !ok {
		return User{}, AuthTokens{}, ErrFeatureNotSupported
	}
	user, err := s.resolveUser(ctx, in.UserID, in.Email, in.TenantID)
	if err != nil {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	matched, err := ss.GetUserBySMSCodeHash(ctx, user.ID, user.TenantID, hashToken(in.Code))
	if err != nil || matched.SMSCodeExpiresAt == nil || s.now().After(matched.SMSCodeExpiresAt.Add(s.cfg.ClockSkew)) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	if err := ss.ClearSMSCode(ctx, matched.ID, matched.TenantID); err != nil {
		return User{}, AuthTokens{}, err
	}
	tokens, err := s.newSessionTokens(ctx, matched)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return matched, tokens, nil
}

func (s *Service) SendVerificationEmailToken(ctx context.Context, in EmailVerificationInput) (string, error) {
	evs, ok := s.users.(EmailVerificationStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	if user.IsEmailVerified {
		return "", nil
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if err := evs.UpdateEmailVerificationToken(ctx, user.ID, user.TenantID, hashToken(token), s.now().Add(s.cfg.EmailVerificationTTL)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	evs, ok := s.users.(EmailVerificationStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := evs.GetUserByEmailVerificationTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.EmailVerificationTokenExpiry == nil || s.now().After(user.EmailVerificationTokenExpiry.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	if err := evs.MarkEmailVerified(ctx, user.ID, user.TenantID, true); err != nil {
		return err
	}
	return evs.ClearEmailVerificationToken(ctx, user.ID, user.TenantID)
}

func (s *Service) RequestEmailChange(ctx context.Context, in ChangeEmailRequestInput) (string, error) {
	ecs, ok := s.users.(EmailChangeStore)
	if !ok {
		return "", ErrFeatureNotSupported
	}
	in.NewEmail = normalizeEmail(in.NewEmail)
	if _, err := s.users.GetUserByEmail(ctx, in.NewEmail, in.TenantID); err == nil {
		return "", ErrUserExists
	}
	user, err := s.users.GetUserByID(ctx, in.UserID, in.TenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if err := ecs.UpdateEmailChangeToken(ctx, user.ID, user.TenantID, in.NewEmail, hashToken(token), s.now().Add(s.cfg.EmailChangeTTL)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) ConfirmEmailChange(ctx context.Context, in ConfirmEmailChangeInput) error {
	ecs, ok := s.users.(EmailChangeStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	user, err := ecs.GetUserByEmailChangeTokenHash(ctx, hashToken(in.Token))
	if err != nil || user.EmailChangeTokenExpiry == nil || s.now().After(user.EmailChangeTokenExpiry.Add(s.cfg.ClockSkew)) {
		return ErrInvalidToken
	}
	if err := ecs.ApplyEmailChange(ctx, user.ID, user.TenantID); err != nil {
		return err
	}
	return ecs.ClearEmailChangeToken(ctx, user.ID, user.TenantID)
}

func (s *Service) SetupTOTP(ctx context.Context, userID, tenantID string) (string, error) {
	_, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	return generateTOTPSecret()
}

func (s *Service) VerifyTOTPSetup(ctx context.Context, userID, tenantID, secret, code string) error {
	ts, ok := s.users.(TOTPStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	if !validateTOTPCode(secret, code, s.now()) {
		return ErrInvalidCode
	}
	return ts.UpdateTOTPSecret(ctx, userID, tenantID, secret, true)
}

func (s *Service) VerifyTOTP(ctx context.Context, userID, tenantID, code string) (User, AuthTokens, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil || !user.IsTOTPEnabled || user.TOTPSecret == "" {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	if !validateTOTPCode(user.TOTPSecret, code, s.now()) {
		return User{}, AuthTokens{}, ErrInvalidCode
	}
	tokens, err := s.newSessionTokens(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return user, tokens, nil
}

func (s *Service) GetMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if s.metadata == nil {
		return nil, ErrFeatureNotSupported
	}
	return s.metadata.GetMetadata(ctx, userID)
}

func (s *Service) UpdateMetadata(ctx context.Context, userID string, metadata map[string]any) error {
	if s.metadata == nil {
		return ErrFeatureNotSupported
	}
	return s.metadata.UpdateMetadata(ctx, userID, metadata)
}

func (s *Service) CreateRole(ctx context.Context, role string, permissions []string) error {
	if s.rbac == nil {
		return ErrFeatureNotSupported
	}
	return s.rbac.CreateRole(ctx, role, permissions)
}

func (s *Service) AssignRole(ctx context.Context, userID, role, tenantID string) error {
	if s.rbac == nil {
		return ErrFeatureNotSupported
	}
	return s.rbac.AddRoleToUser(ctx, userID, role, tenantID)
}

func (s *Service) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	if s.rbac == nil {
		return false, ErrFeatureNotSupported
	}
	return s.rbac.UserHasPermission(ctx, userID, permission, tenantID)
}

func (s *Service) CreateTenant(ctx context.Context, name string, config map[string]any) (Tenant, error) {
	if s.tenants == nil {
		return Tenant{}, ErrFeatureNotSupported
	}
	id, err := newID("tnt")
	if err != nil {
		return Tenant{}, err
	}
	return s.tenants.CreateTenant(ctx, Tenant{
		ID:        id,
		Name:      name,
		IsActive:  true,
		Config:    config,
		CreatedAt: s.now(),
	})
}

func (s *Service) AddUserToTenant(ctx context.Context, userID, tenantID string) error {
	if s.tenants == nil {
		return ErrFeatureNotSupported
	}
	return s.tenants.AssociateUserWithTenant(ctx, userID, tenantID)
}

func (s *Service) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	ts, ok := s.users.(TOTPStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	return ts.UpdateTOTPSecret(ctx, userID, tenantID, "", false)
}

func (s *Service) ListSessions(ctx context.Context, userID, tenantID string) ([]Session, error) {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return nil, ErrFeatureNotSupported
	}
	return store.ListSessionsForUser(ctx, userID, tenantID)
}

func (s *Service) RevokeSessionByID(ctx context.Context, sessionID string) error {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	return store.RevokeSessionByID(ctx, sessionID)
}

func (s *Service) CleanupExpiredSessions(ctx context.Context) (int, error) {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return 0, ErrFeatureNotSupported
	}
	return store.DeleteExpiredSessions(ctx, s.now())
}

func (s *Service) resolveUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	trimmedUserID := strings.TrimSpace(userID)
	trimmedEmail := strings.TrimSpace(email)
	if trimmedUserID != "" {
		return s.users.GetUserByID(ctx, trimmedUserID, tenantID)
	}
	if trimmedEmail != "" {
		return s.users.GetUserByEmail(ctx, normalizeEmail(trimmedEmail), tenantID)
	}
	return User{}, ErrInvalidCredentials
}

func (s *Service) requiresTwoFactor(user User) bool {
	hasTOTP := user.IsTOTPEnabled && strings.TrimSpace(user.TOTPSecret) != ""
	return s.cfg.Require2FA || user.Require2FA || hasTOTP
}

func (s *Service) enrichUser(ctx context.Context, user User) (User, error) {
	if s.metadata != nil {
		metadata, err := s.metadata.GetMetadata(ctx, user.ID)
		if err != nil {
			s.logf("auth: metadata enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Metadata = metadata
		}
	}
	if s.rbac != nil {
		roles, err := s.rbac.GetRolesForUser(ctx, user.ID, user.TenantID)
		if err != nil {
			s.logf("auth: role enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Roles = roles
			permissions, err := s.rbac.GetPermissionsForUser(ctx, user.ID, user.TenantID)
			if err != nil {
				s.logf("auth: permission enrichment skipped for user %q: %v", user.ID, err)
			} else {
				user.Permissions = permissions
			}
		}
	}
	if s.tenants != nil {
		tenants, err := s.tenants.GetTenantsForUser(ctx, user.ID)
		if err != nil {
			s.logf("auth: tenant enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.Tenants = tenants
		}
	}
	if s.cfg.BuildTokenClaims != nil {
		claims, err := s.cfg.BuildTokenClaims(ctx, user)
		if err != nil {
			s.logf("auth: custom claim enrichment skipped for user %q: %v", user.ID, err)
		} else {
			user.CustomClaims = claims
		}
	}
	return user, nil
}

func (s *Service) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger(format, args...)
	}
}
