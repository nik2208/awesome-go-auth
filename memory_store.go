package auth

import (
	"context"
	"errors"
	"sync"
)

// MemoryUserStore is a thread-safe in-memory implementation of UserStore.
type MemoryUserStore struct {
	mu      sync.RWMutex
	byID    map[string]User
	byEmail map[string]string
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:    make(map[string]User),
		byEmail: make(map[string]string),
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
