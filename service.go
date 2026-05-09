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
	now      func() time.Time
}

// NewService builds an auth service with validated configuration.
func NewService(cfg Config, users UserStore, sessions SessionStore) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if users == nil || sessions == nil {
		return nil, errors.New("auth: stores are required")
	}
	return &Service{
		cfg:      cfg,
		users:    users,
		sessions: sessions,
		now:      time.Now,
	}, nil
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
		ID:           userID,
		Email:        in.Email,
		PasswordHash: pwHash,
		TenantID:     in.TenantID,
		CreatedAt:    now,
		UpdatedAt:    now,
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
	return user, nil
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
