package nethttp_test

import (
	"net/http"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// TestMiddlewareSkipsClaimsHook pins that a host route behind Middleware never
// runs Config.BuildTokenClaims, while GET /me runs it exactly once.
func TestMiddlewareSkipsClaimsHook(t *testing.T) {
	wiretest.RunProtectedRouteSkipsClaimsHook(t, mount, func(t *testing.T, a *auth.Auth) http.Handler {
		return nethttpadapter.Middleware(a)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := nethttpadapter.UserFromContext(r.Context())
			if !ok {
				t.Error("expected the user in context")
			}
			auth.WriteJSON(w, http.StatusOK, map[string]any{"email": user.Email, "customClaims": user.CustomClaims})
		}))
	})
}
