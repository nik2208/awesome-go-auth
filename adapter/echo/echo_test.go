package echo_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoadapter "github.com/nik2208/awesome-go-auth/adapter/echo"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

func mount(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
	e := echo.New()
	echoadapter.MountWithConfig(e.Group(""), a, cfg)
	return e
}

// TestWireContract runs the shared conformance suite. Echo used to disagree
// with net/http on cookie attributes and response envelopes; this is what stops
// that from recurring.
func TestWireContract(t *testing.T) {
	wiretest.Run(t, mount)
}

func TestMiddlewareGuardsHostRoutes(t *testing.T) {
	env := wiretest.NewEnv(t, mount, auth.DefaultHTTPConfig())
	_, tokens := env.Seed("echomw@example.com")

	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		user, ok := echoadapter.UserFromContext(c)
		if !ok {
			t.Error("expected the user in context")
		}
		auth.WriteJSON(c.Response(), http.StatusOK, map[string]any{"email": user.Email})
		return nil
	}, echoadapter.Middleware(env.Auth))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	wiretest.AssertStatus(t, rec, http.StatusOK)

	anonymous := httptest.NewRecorder()
	e.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/protected", nil))
	wiretest.AssertError(t, anonymous, http.StatusForbidden, "No access token provided", "")
}
