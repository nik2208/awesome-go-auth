package nethttp

import (
	"errors"
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The session-listing and account-management routes: GET /sessions,
// DELETE /sessions/{handle}, POST /sessions/cleanup, PATCH /profile,
// POST /add-phone and DELETE /account.
//
// These are the first routes in this port that sit behind the auth middleware
// and change state, so they are also the first on which the CSRF double-submit
// is actually enforceable in cookie mode.

type updateProfileRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type addPhoneRequest struct {
	PhoneNumber string `json:"phoneNumber"`
}

// Sessions handles GET <prefix>/sessions. The list is wrapped in a "sessions"
// key — a client-pinned invariant: both browser clients read response.sessions,
// and a bare array breaks them.
func (a *Adapter) Sessions(w http.ResponseWriter, r *http.Request) {
	user, ok := accountUser(w, r)
	if !ok {
		return
	}
	sessions, err := a.auth.ListSessions(r.Context(), user.ID, user.TenantID)
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"sessions": auth.NewPublicSessions(sessions)})
}

// RevokeSession handles DELETE <prefix>/sessions/{handle}.
func (a *Adapter) RevokeSession(w http.ResponseWriter, r *http.Request) {
	user, ok := accountUser(w, r)
	if !ok {
		return
	}
	handle := auth.SessionHandleParam(r, r.PathValue("handle"))
	if err := a.auth.RevokeUserSession(r.Context(), user.ID, user.TenantID, handle); err != nil {
		writeRevokeError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// CleanupSessions handles POST <prefix>/sessions/cleanup.
//
// It is mounted with no auth gate, because the reference mounts it with none
// (auth.router.ts:733-744): anyone who can reach the router can trigger a
// cleanup. That is reproduced deliberately rather than hardened, since a client
// or a cron job calling it unauthenticated must keep working — see the note in
// the pull request that added this route.
func (a *Adapter) CleanupSessions(w http.ResponseWriter, r *http.Request) {
	deleted, err := a.auth.CleanupExpiredSessions(r.Context())
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, map[string]any{"deleted": deleted})
}

// UpdateProfile handles PATCH <prefix>/profile. The updated user is not echoed
// back: the reference answers {"success": true} and the clients re-read /me.
func (a *Adapter) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user, ok := accountUser(w, r)
	if !ok {
		return
	}
	var req updateProfileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, err := a.auth.UpdateProfile(r.Context(), auth.UpdateProfileInput{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// AddPhone handles POST <prefix>/add-phone. An empty phoneNumber clears the
// number, matching the reference's nullable field.
func (a *Adapter) AddPhone(w http.ResponseWriter, r *http.Request) {
	user, ok := accountUser(w, r)
	if !ok {
		return
	}
	var req addPhoneRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if _, err := a.auth.UpdatePhoneNumber(r.Context(), auth.AddPhoneInput{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		PhoneNumber: req.PhoneNumber,
	}); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// DeleteAccount handles DELETE <prefix>/account. The cookies are cleared on the
// way out even for a bearer caller, as the reference does: a client that has
// just deleted its account must not be left holding live cookies.
func (a *Adapter) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := accountUser(w, r)
	if !ok {
		return
	}
	if err := a.auth.DeleteAccount(r.Context(), auth.DeleteAccountInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	a.cfg.Cookies.ClearAuthCookies(w, a.cfg.CSRF.Enabled)
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// accountUser reads the authenticated user the middleware injected. The
// middleware has already refused every request without one, so reaching the
// error branch means the route was mounted without it.
func accountUser(w http.ResponseWriter, r *http.Request) (auth.User, bool) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return auth.User{}, false
	}
	return user, true
}

// writeRevokeError keeps "not found" and "not yours" indistinguishable.
func writeRevokeError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrSessionNotFound) {
		auth.WriteHTTPError(w, auth.HTTPErrSessionNotFound)
		return
	}
	auth.WriteServiceError(w, err)
}
