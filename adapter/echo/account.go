package echo

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
)

// The session-listing and account-management routes. The bodies are written
// through the shared wire helpers so that echo cannot drift from net/http.

func (ad *Adapter) sessions(c echo.Context) error {
	user, ok := accountUser(c)
	if !ok {
		return nil
	}
	sessions, err := ad.auth.ListSessions(c.Request().Context(), user.ID, user.TenantID)
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteJSON(c.Response(), http.StatusOK, map[string]any{"sessions": auth.NewPublicSessions(sessions)})
	return nil
}

func (ad *Adapter) revokeSession(c echo.Context) error {
	user, ok := accountUser(c)
	if !ok {
		return nil
	}
	// Echo hands the path parameter over still percent-encoded, which is exactly
	// why the normalisation lives in the core package.
	handle := auth.SessionHandleParam(c.Request(), c.Param("handle"))
	if err := ad.auth.RevokeUserSession(c.Request().Context(), user.ID, user.TenantID, handle); err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) {
			auth.WriteHTTPError(c.Response(), auth.HTTPErrSessionNotFound)
			return nil
		}
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

// cleanupSessions is mounted with no auth gate, reproducing the reference
// (auth.router.ts:733-744).
func (ad *Adapter) cleanupSessions(c echo.Context) error {
	deleted, err := ad.auth.CleanupExpiredSessions(c.Request().Context())
	if err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, map[string]any{"deleted": deleted})
	return nil
}

func (ad *Adapter) updateProfile(c echo.Context) error {
	user, ok := accountUser(c)
	if !ok {
		return nil
	}
	var req struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	if err := c.Bind(&req); err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrInvalidBody)
		return nil
	}
	if _, err := ad.auth.UpdateProfile(c.Request().Context(), auth.UpdateProfileInput{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) addPhone(c echo.Context) error {
	user, ok := accountUser(c)
	if !ok {
		return nil
	}
	var req struct {
		PhoneNumber string `json:"phoneNumber"`
	}
	if err := c.Bind(&req); err != nil {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrInvalidBody)
		return nil
	}
	if _, err := ad.auth.UpdatePhoneNumber(c.Request().Context(), auth.AddPhoneInput{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		PhoneNumber: req.PhoneNumber,
	}); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func (ad *Adapter) deleteAccount(c echo.Context) error {
	user, ok := accountUser(c)
	if !ok {
		return nil
	}
	if err := ad.auth.DeleteAccount(c.Request().Context(), auth.DeleteAccountInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(c.Response(), err)
		return nil
	}
	ad.cfg.Cookies.ClearAuthCookies(c.Response(), ad.cfg.CSRF.Enabled)
	auth.WriteSuccess(c.Response(), http.StatusOK, nil)
	return nil
}

func accountUser(c echo.Context) (auth.User, bool) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Response(), auth.HTTPErrNoAccessToken)
		return auth.User{}, false
	}
	return user, true
}
