package nethttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

func mount(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
	mux := http.NewServeMux()
	nethttpadapter.MountWithConfig(mux, a, cfg)
	return mux
}

// TestWireContract runs the shared conformance suite. The same suite runs
// against chi, gin and echo, which is what keeps the four adapters
// interchangeable for a family client.
func TestWireContract(t *testing.T) {
	wiretest.Run(t, mount)
}

func TestMiddlewareGuardsHostRoutes(t *testing.T) {
	env := wiretest.NewEnv(t, mount, auth.DefaultHTTPConfig())
	_, tokens := env.Seed("mw@example.com")

	protected := nethttpadapter.Middleware(env.Auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := nethttpadapter.UserFromContext(r.Context())
		if !ok {
			t.Error("expected the user in context")
		}
		auth.WriteJSON(w, http.StatusOK, map[string]any{"email": user.Email})
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	wiretest.AssertStatus(t, rec, http.StatusOK)

	anonymous := httptest.NewRecorder()
	protected.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/protected", nil))
	wiretest.AssertError(t, anonymous, http.StatusForbidden, "No access token provided", "")
}
