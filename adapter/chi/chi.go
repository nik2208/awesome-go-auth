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

	// OAuth and account linking. These handlers arrive already wrapped in the
	// CSRF middleware and, where the route needs one, the auth middleware, so
	// they mount with r.Method rather than r.With(...).MethodFunc.
	r.Method(http.MethodGet, prefix+"/oauth/{provider}", h.OAuthAuthorizeHandler())
	r.Method(http.MethodGet, prefix+"/oauth/{provider}/callback", h.OAuthCallbackHandler())
	r.Method(http.MethodGet, prefix+"/linked-accounts", h.LinkedAccountsHandler())
	r.Method(http.MethodDelete, prefix+"/linked-accounts/{provider}/{providerAccountId}", h.UnlinkAccountHandler())
	r.Method(http.MethodPost, prefix+"/link-request", h.LinkRequestHandler())
	r.Method(http.MethodPost, prefix+"/link-verify", h.LinkVerifyHandler())
}
