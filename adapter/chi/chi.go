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
h := nethttpadapter.New(a)
r.MethodFunc(http.MethodPost, "/auth/register", h.Register)
r.MethodFunc(http.MethodPost, "/auth/login", h.Login)
r.MethodFunc(http.MethodPost, "/auth/refresh", h.Refresh)
r.MethodFunc(http.MethodPost, "/auth/logout", h.Logout)
r.With(Middleware(a)).MethodFunc(http.MethodGet, "/auth/me", h.Me)
}
