package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file carries what the session-listing and account-management routes need
// from the core package: the response-safe session projection, the phone-number
// store capability, and the service entry points the adapters call. The HTTP
// conventions themselves stay in wire.go.

// UserPhoneStore adds the phone-number update behind POST /add-phone. It is a
// capability of its own rather than a method on UserAccountStore so that a store
// written against the existing interface keeps compiling; a store that does not
// implement it makes the route answer 501, which is the reference's own
// behaviour when userStore.updatePhoneNumber is absent (auth.router.ts:700-703).
type UserPhoneStore interface {
	UpdatePhoneNumber(ctx context.Context, userID, tenantID, phoneNumber string) (User, error)
}

// AddPhoneInput is the payload behind POST /add-phone. An empty PhoneNumber
// clears the number, as the reference's nullable phoneNumber does.
type AddPhoneInput struct {
	UserID      string
	TenantID    string
	PhoneNumber string
}

// PublicSession is the response-safe projection of Session, and the only session
// shape an adapter may serialise: Session carries the refresh-token hash, which
// is credential material and must never reach a response body.
//
// The field names are the family's: both browser clients read sessionHandle off
// each entry and post it straight back to DELETE /sessions/{handle}.
type PublicSession struct {
	SessionHandle string     `json:"sessionHandle"`
	UserID        string     `json:"userId"`
	TenantID      string     `json:"tenantId,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
}

// NewPublicSession projects a Session onto its response-safe representation.
func NewPublicSession(session Session) PublicSession {
	return PublicSession{
		SessionHandle: session.ID,
		UserID:        session.UserID,
		TenantID:      session.TenantID,
		CreatedAt:     session.CreatedAt,
		ExpiresAt:     session.ExpiresAt,
		RevokedAt:     session.RevokedAt,
	}
}

// NewPublicSessions projects a session list. The result is never nil: a store
// that returns no sessions must serialise as [] and not as null, because a
// client iterating response.sessions breaks on null.
func NewPublicSessions(sessions []Session) []PublicSession {
	out := make([]PublicSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, NewPublicSession(session))
	}
	return out
}

// HTTPErrSessionNotFound is the answer to DELETE /sessions/{handle} for a handle
// that does not exist and for one that belongs to somebody else — deliberately
// the same body, so the route cannot be used to probe for live sessions
// (auth.router.ts:762-767). It is written by the route rather than mapped in
// HTTPErrorFor, because ErrSessionNotFound means "unusable refresh token" (401)
// everywhere else.
var HTTPErrSessionNotFound = HTTPError{Status: http.StatusNotFound, Message: "Session not found"}

// SessionHandleParam normalises the {handle} path parameter.
//
// Two things vary and both have to be absorbed here. One family client
// URI-escapes the handle and the other posts it verbatim, so the value is
// unescaped when it is escaped — the reference decodeURIComponent's it
// unconditionally (auth.router.ts:761). And each router hands the segment over
// differently: net/http and gin decode it, chi and echo do not, so a handler
// that trusted its router would work on two adapters and 404 on the other two.
//
// raw is the router's own path parameter; when a router does not expose one, the
// last path segment is used instead. A handle containing an encoded slash is not
// recoverable in Go — url.Path has already merged it into the path — but the
// handles this package issues are "ses_" plus hex.
func SessionHandleParam(r *http.Request, raw string) string {
	handle := strings.TrimSpace(raw)
	if handle == "" && r != nil && r.URL != nil {
		handle = lastPathSegment(r.URL.Path)
	}
	if decoded, err := url.PathUnescape(handle); err == nil {
		return decoded
	}
	return handle
}

func lastPathSegment(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// UpdatePhoneNumber makes MemoryUserStore satisfy UserPhoneStore. It lives
// beside the interface rather than in memory_store.go so that the capability
// and its in-memory implementation stay in one place.
func (s *MemoryUserStore) UpdatePhoneNumber(_ context.Context, userID, tenantID, phoneNumber string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.byID[userID]
	if !ok || user.TenantID != tenantID {
		return User{}, errors.New("user not found")
	}
	user.PhoneNumber = phoneNumber
	user.UpdatedAt = time.Now()
	s.byID[userID] = user
	return user, nil
}

// UpdatePhoneNumber sets or clears a user's phone number.
func (s *Service) UpdatePhoneNumber(ctx context.Context, in AddPhoneInput) (User, error) {
	phoneStore, ok := s.users.(UserPhoneStore)
	if !ok {
		return User{}, ErrFeatureNotSupported
	}
	updated, err := phoneStore.UpdatePhoneNumber(ctx, in.UserID, in.TenantID, strings.TrimSpace(in.PhoneNumber))
	if err != nil {
		return User{}, fmt.Errorf("auth: update phone number: %w", err)
	}
	return s.enrichUser(ctx, updated)
}

// RevokeUserSession revokes one of a user's own sessions. Ownership is part of
// the lookup rather than a check bolted on afterwards: a handle belonging to
// another user is indistinguishable from one that never existed.
func (s *Service) RevokeUserSession(ctx context.Context, userID, tenantID, sessionID string) error {
	store, ok := s.sessions.(SessionAdminStore)
	if !ok {
		return ErrFeatureNotSupported
	}
	handle := strings.TrimSpace(sessionID)
	if handle == "" {
		return ErrSessionNotFound
	}
	sessions, err := store.ListSessionsForUser(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	for _, session := range sessions {
		if session.ID == handle {
			return store.RevokeSessionByID(ctx, handle)
		}
	}
	return ErrSessionNotFound
}

// ListSessions delegates to Service.ListSessions.
func (a *Auth) ListSessions(ctx context.Context, userID, tenantID string) ([]Session, error) {
	return a.service.ListSessions(ctx, userID, tenantID)
}

// RevokeUserSession delegates to Service.RevokeUserSession.
func (a *Auth) RevokeUserSession(ctx context.Context, userID, tenantID, sessionID string) error {
	return a.service.RevokeUserSession(ctx, userID, tenantID, sessionID)
}

// CleanupExpiredSessions delegates to Service.CleanupExpiredSessions.
func (a *Auth) CleanupExpiredSessions(ctx context.Context) (int, error) {
	return a.service.CleanupExpiredSessions(ctx)
}

// UpdatePhoneNumber delegates to Service.UpdatePhoneNumber.
func (a *Auth) UpdatePhoneNumber(ctx context.Context, in AddPhoneInput) (User, error) {
	return a.service.UpdatePhoneNumber(ctx, in)
}
