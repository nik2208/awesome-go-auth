package gin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginadapter "github.com/nik2208/awesome-go-auth/adapter/gin"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func mount(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
	r := gin.New()
	ginadapter.MountWithConfig(r, a, cfg)
	return r
}

// TestWireContract runs the shared conformance suite. Gin used to disagree with
// net/http on cookie attributes and response envelopes; this is what stops that
// from recurring.
func TestWireContract(t *testing.T) {
	wiretest.Run(t, mount)
}

func TestMiddlewareGuardsHostRoutes(t *testing.T) {
	env := wiretest.NewEnv(t, mount, auth.DefaultHTTPConfig())
	_, tokens := env.Seed("ginmw@example.com")

	r := gin.New()
	r.GET("/protected", ginadapter.Middleware(env.Auth), func(c *gin.Context) {
		user, ok := ginadapter.UserFromContext(c)
		if !ok {
			t.Error("expected the user in context")
		}
		auth.WriteJSON(c.Writer, http.StatusOK, map[string]any{"email": user.Email})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	wiretest.AssertStatus(t, rec, http.StatusOK)

	anonymous := httptest.NewRecorder()
	r.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/protected", nil))
	wiretest.AssertError(t, anonymous, http.StatusForbidden, "No access token provided", "")
}
