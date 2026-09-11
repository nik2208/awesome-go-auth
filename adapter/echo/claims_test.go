package echo_test

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoadapter "github.com/nik2208/awesome-go-auth/adapter/echo"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

// TestMiddlewareSkipsClaimsHook pins that a host route behind Middleware never
// runs Config.BuildTokenClaims, while GET /me runs it exactly once.
func TestMiddlewareSkipsClaimsHook(t *testing.T) {
	wiretest.RunProtectedRouteSkipsClaimsHook(t, mount, func(t *testing.T, a *auth.Auth) http.Handler {
		e := echo.New()
		e.GET("/protected", func(c echo.Context) error {
			user, ok := echoadapter.UserFromContext(c)
			if !ok {
				t.Error("expected the user in context")
			}
			auth.WriteJSON(c.Response(), http.StatusOK, map[string]any{"email": user.Email, "customClaims": user.CustomClaims})
			return nil
		}, echoadapter.Middleware(a))
		return e
	})
}
