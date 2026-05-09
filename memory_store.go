package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MemoryUserStore is a thread-safe in-memory implementation of UserStore.
type MemoryUserStore struct {
	mu                 sync.RWMutex
	byID               map[string]User
	byEmail            map[string]string
	byResetToken       map[string]string
	byMagicToken       map[string]string
	byVerifyToken      map[string]string
	byEmailChangeToken map[string]string
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:               make(map[string]User),
		byEmail:            make(map[string]string),
		byResetToken:       make(map[string]string),
		byMagicToken:       make(map[string]string),
		byVerifyToken:      make(map[string]string),
		byEmailChangeToken: make(map[string]string),
	}
}

func userEmailKey(email, tenantID string) string {
	return tenantID + ":" + normalizeEmail(email)
}

func (s *MemoryUserStore) CreateUser(_ context.Context, user User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[user.ID]; ok {
		return User{}, ErrUserExists
	}
	key := userEmailKey(user.Email, user.TenantID)
	if _, ok := s.byEmail[key]; ok {
		return User{}, ErrUserExists
	}
	s.byID[user.ID] = user
	s.byEmail[key] = user.ID
	return user, nil
}

func (s *MemoryUserStore) GetUserByEmail(_ context.Context, email, tenantID string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := userEmailKey(email, tenantID)
	id, ok := s.byEmail[key]
	if !ok {
		return User{}, errors.New("user not found")
	}
	u, ok := s.byID[id]
	if !ok {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) GetUserByID(_ context.Context, id, tenantID string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok || u.TenantID != tenantID {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) UpdatePassword(_ context.Context, userID, tenantID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.PasswordHash = passwordHash
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateResetToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.ResetTokenHash != "" {
		delete(s.byResetToken, u.ResetTokenHash)
	}
	u.ResetTokenHash = tokenHash
	u.ResetTokenExpiresAt = &expiry
	s.byResetToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByResetTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byResetToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ClearResetToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.ResetTokenHash != "" {
		delete(s.byResetToken, u.ResetTokenHash)
	}
	u.ResetTokenHash = ""
	u.ResetTokenExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateMagicLinkToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.MagicLinkTokenHash != "" {
		delete(s.byMagicToken, u.MagicLinkTokenHash)
	}
	u.MagicLinkTokenHash = tokenHash
	u.MagicLinkTokenExpiresAt = &expiry
	s.byMagicToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByMagicLinkTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byMagicToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ClearMagicLinkToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.MagicLinkTokenHash != "" {
		delete(s.byMagicToken, u.MagicLinkTokenHash)
	}
	u.MagicLinkTokenHash = ""
	u.MagicLinkTokenExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateSMSCode(_ context.Context, userID, tenantID, codeHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.SMSCodeHash = codeHash
	u.SMSCodeExpiresAt = &expiry
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserBySMSCodeHash(_ context.Context, userID, tenantID, codeHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return User{}, ErrInvalidCode
	}
	if !secureEqual(u.SMSCodeHash, codeHash) {
		return User{}, ErrInvalidCode
	}
	return u, nil
}

func (s *MemoryUserStore) ClearSMSCode(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.SMSCodeHash = ""
	u.SMSCodeExpiresAt = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateTOTPSecret(_ context.Context, userID, tenantID, secret string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.TOTPSecret = secret
	u.IsTOTPEnabled = enabled
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateEmailVerificationToken(_ context.Context, userID, tenantID, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailVerificationTokenHash != "" {
		delete(s.byVerifyToken, u.EmailVerificationTokenHash)
	}
	u.EmailVerificationTokenHash = tokenHash
	u.EmailVerificationTokenExpiry = &expiry
	s.byVerifyToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByEmailVerificationTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byVerifyToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) MarkEmailVerified(_ context.Context, userID, tenantID string, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	u.IsEmailVerified = verified
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) ClearEmailVerificationToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailVerificationTokenHash != "" {
		delete(s.byVerifyToken, u.EmailVerificationTokenHash)
	}
	u.EmailVerificationTokenHash = ""
	u.EmailVerificationTokenExpiry = nil
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) UpdateEmailChangeToken(_ context.Context, userID, tenantID, pendingEmail, tokenHash string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailChangeTokenHash != "" {
		delete(s.byEmailChangeToken, u.EmailChangeTokenHash)
	}
	u.PendingEmail = pendingEmail
	u.EmailChangeTokenHash = tokenHash
	u.EmailChangeTokenExpiry = &expiry
	s.byEmailChangeToken[tokenHash] = userID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) GetUserByEmailChangeTokenHash(_ context.Context, tokenHash string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.byEmailChangeToken[tokenHash]
	if !ok {
		return User{}, ErrInvalidToken
	}
	u, ok := s.byID[uid]
	if !ok {
		return User{}, ErrInvalidToken
	}
	return u, nil
}

func (s *MemoryUserStore) ApplyEmailChange(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	oldKey := userEmailKey(u.Email, u.TenantID)
	newKey := userEmailKey(u.PendingEmail, u.TenantID)
	if _, exists := s.byEmail[newKey]; exists {
		return ErrUserExists
	}
	delete(s.byEmail, oldKey)
	u.Email = normalizeEmail(u.PendingEmail)
	u.PendingEmail = ""
	s.byEmail[newKey] = u.ID
	s.byID[userID] = u
	return nil
}

func (s *MemoryUserStore) ClearEmailChangeToken(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[userID]
	if !ok || u.TenantID != tenantID {
		return errors.New("user not found")
	}
	if u.EmailChangeTokenHash != "" {
		delete(s.byEmailChangeToken, u.EmailChangeTokenHash)
	}
	u.EmailChangeTokenHash = ""
	u.EmailChangeTokenExpiry = nil
	u.PendingEmail = ""
	s.byID[userID] = u
	return nil
}

// MemorySessionStore is a thread-safe in-memory implementation of SessionStore.
type MemorySessionStore struct {
	mu            sync.RWMutex
	byID          map[string]Session
	byTokenHashed map[string]string
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		byID:          make(map[string]Session),
		byTokenHashed: make(map[string]string),
	}
}

func (s *MemorySessionStore) CreateSession(_ context.Context, session Session) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[session.ID] = session
	s.byTokenHashed[session.RefreshTokenHash] = session.ID
	return session, nil
}

func (s *MemorySessionStore) GetSessionByRefreshTokenHash(_ context.Context, tokenHash string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sid, ok := s.byTokenHashed[tokenHash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	session, ok := s.byID[sid]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

func (s *MemorySessionStore) UpdateSession(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[session.ID]
	if !ok {
		return ErrSessionNotFound
	}
	if current.RefreshTokenHash != session.RefreshTokenHash {
		delete(s.byTokenHashed, current.RefreshTokenHash)
		s.byTokenHashed[session.RefreshTokenHash] = session.ID
	}
	s.byID[session.ID] = session
	return nil
}

func (s *MemorySessionStore) ListSessionsForUser(_ context.Context, userID, tenantID string) ([]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Session, 0)
	for _, session := range s.byID {
		if session.UserID == userID && session.TenantID == tenantID {
			out = append(out, session)
		}
	}
	return out, nil
}

func (s *MemorySessionStore) RevokeSessionByID(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byID[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	now := time.Now()
	session.RevokedAt = &now
	s.byID[sessionID] = session
	return nil
}

func (s *MemorySessionStore) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for id, session := range s.byID {
		if now.After(session.ExpiresAt) {
			delete(s.byID, id)
			delete(s.byTokenHashed, session.RefreshTokenHash)
			deleted++
		}
	}
	return deleted, nil
}
