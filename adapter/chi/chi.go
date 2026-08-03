package chi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// Middleware returns a Chi-compatible auth middleware.
func Middleware(a *auth.Auth) func(http.Handler) http.Handler {
	return nethttpadapter.Middleware(a)
}

// Mount mounts auth routes onto a Chi router.
func Mount(r chi.Router, a *auth.Auth) {
	MountWithConfig(r, a, auth.DefaultHTTPConfig())
}

// MountWithConfig mounts auth routes using the supplied wire conventions.
func MountWithConfig(r chi.Router, a *auth.Auth, cfg auth.HTTPConfig) {
	h := nethttpadapter.NewWithConfig(a, cfg)
	resolved := h.Config()
	prefix := resolved.Prefix()
	csrf := auth.CSRFMiddleware(resolved)

	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/register", h.Register)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/login", h.Login)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/refresh", h.Refresh)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/logout", h.Logout)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodGet, prefix+"/me", h.Me)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodGet, prefix+"/sessions", h.Sessions)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/sessions/{handle}", h.RevokeSession)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/sessions/cleanup", h.CleanupSessions)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPatch, prefix+"/profile", h.UpdateProfile)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/add-phone", h.AddPhone)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/account", h.DeleteAccount)

	// OAuth and account linking. These handlers arrive already wrapped in the
	// CSRF middleware and, where the route needs one, the auth middleware, so
	// they mount with r.Method rather than r.With(...).MethodFunc.
	r.Method(http.MethodGet, prefix+"/oauth/{provider}", h.OAuthAuthorizeHandler())
	r.Method(http.MethodGet, prefix+"/oauth/{provider}/callback", h.OAuthCallbackHandler())
	r.Method(http.MethodGet, prefix+"/linked-accounts", h.LinkedAccountsHandler())
	r.Method(http.MethodDelete, prefix+"/linked-accounts/{provider}/{providerAccountId}", h.UnlinkAccountHandler())
	r.Method(http.MethodPost, prefix+"/link-request", h.LinkRequestHandler())
	r.Method(http.MethodPost, prefix+"/link-verify", h.LinkVerifyHandler())
	// Passwordless and 2FA. Chi serves the net/http handlers unchanged, so the
	// only chi-specific part is the registration.
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/magic-link/send", h.MagicLinkSend)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/magic-link/verify", h.MagicLinkVerify)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/sms/send", h.SMSSend)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/sms/verify", h.SMSVerify)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/setup", h.TwoFactorSetup)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/verify-setup", h.TwoFactorVerifySetup)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/2fa/verify", h.TwoFactorVerify)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/disable", h.TwoFactorDisable)
	// Password management and email verification (wire-contract §2).
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/forgot-password", h.ForgotPassword)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/reset-password", h.ResetPassword)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-password", h.ChangePassword)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/send-verification-email", h.SendVerificationEmail)
	r.With(csrf).MethodFunc(http.MethodGet, prefix+"/verify-email", h.VerifyEmail)
	r.With(csrf, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-email/request", h.ChangeEmailRequest)
	r.With(csrf).MethodFunc(http.MethodPost, prefix+"/change-email/confirm", h.ChangeEmailConfirm)
}
