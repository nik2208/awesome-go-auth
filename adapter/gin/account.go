package gin

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

// The session-listing and account-management routes. The bodies are written
// through the shared wire helpers so that gin cannot drift from net/http.

func (ad *Adapter) sessions(c *gin.Context) {
	user, ok := accountUser(c)
	if !ok {
		return
	}
	sessions, err := ad.auth.ListSessions(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteJSON(c.Writer, http.StatusOK, map[string]any{"sessions": auth.NewPublicSessions(sessions)})
}

func (ad *Adapter) revokeSession(c *gin.Context) {
	user, ok := accountUser(c)
	if !ok {
		return
	}
	handle := auth.SessionHandleParam(c.Request, c.Param("handle"))
	if err := ad.auth.RevokeUserSession(c.Request.Context(), user.ID, user.TenantID, handle); err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) {
			auth.WriteHTTPError(c.Writer, auth.HTTPErrSessionNotFound)
			return
		}
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

// cleanupSessions is mounted with no auth gate, reproducing the reference
// (auth.router.ts:733-744).
func (ad *Adapter) cleanupSessions(c *gin.Context) {
	deleted, err := ad.auth.CleanupExpiredSessions(c.Request.Context())
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, map[string]any{"deleted": deleted})
}

func (ad *Adapter) updateProfile(c *gin.Context) {
	user, ok := accountUser(c)
	if !ok {
		return
	}
	// Pointers, so an omitted key stays distinguishable from an empty one: the
	// route is a partial update (§3.5). Decoded by the shared core helper rather
	// than by ShouldBindJSON, which reports a bodyless request as io.EOF where the
	// reference answers 200 — the drift that had echo alone answering 200 here.
	var req struct {
		FirstName *string `json:"firstName"`
		LastName  *string `json:"lastName"`
	}
	if err := auth.DecodeOptionalJSONBody(c.Request, &req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	if _, err := ad.auth.UpdateProfile(c.Request.Context(), auth.UpdateProfileInput{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) addPhone(c *gin.Context) {
	user, ok := accountUser(c)
	if !ok {
		return
	}
	var req struct {
		PhoneNumber string `json:"phoneNumber"`
	}
	if err := auth.DecodeOptionalJSONBody(c.Request, &req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	if _, err := ad.auth.UpdatePhoneNumber(c.Request.Context(), auth.AddPhoneInput{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		PhoneNumber: req.PhoneNumber,
	}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) deleteAccount(c *gin.Context) {
	user, ok := accountUser(c)
	if !ok {
		return
	}
	if err := ad.auth.DeleteAccount(c.Request.Context(), auth.DeleteAccountInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	ad.cfg.Cookies.ClearAuthCookies(c.Writer, ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func accountUser(c *gin.Context) (auth.User, bool) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return auth.User{}, false
	}
	return user, true
}
