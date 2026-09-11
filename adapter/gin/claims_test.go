package gin_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginadapter "github.com/nik2208/awesome-go-auth/adapter/gin"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

// TestMiddlewareSkipsClaimsHook pins that a host route behind Middleware never
// runs Config.BuildTokenClaims, while GET /me runs it exactly once.
func TestMiddlewareSkipsClaimsHook(t *testing.T) {
	wiretest.RunProtectedRouteSkipsClaimsHook(t, mount, func(t *testing.T, a *auth.Auth) http.Handler {
		r := gin.New()
		r.GET("/protected", ginadapter.Middleware(a), func(c *gin.Context) {
			user, ok := ginadapter.UserFromContext(c)
			if !ok {
				t.Error("expected the user in context")
			}
			auth.WriteJSON(c.Writer, http.StatusOK, map[string]any{"email": user.Email, "customClaims": user.CustomClaims})
		})
		return r
	})
}
