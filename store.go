package auth

import "context"

// UserStore persists and resolves users.
type UserStore interface {
	CreateUser(ctx context.Context, user User) (User, error)
	GetUserByEmail(ctx context.Context, email, tenantID string) (User, error)
	GetUserByID(ctx context.Context, id, tenantID string) (User, error)
}

// SessionStore persists refresh-token sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) (Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (Session, error)
	UpdateSession(ctx context.Context, session Session) error
}
