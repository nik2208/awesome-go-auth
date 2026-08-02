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
}
