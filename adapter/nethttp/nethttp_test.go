package nethttp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestOIDCEndpointsCannotBeMountedTwice pins what (*auth.IDP).RegisterHandlers
// documents: an Auth built WithIDP already serves the four OIDC endpoints from
// the adapter's mount, so calling RegisterHandlers on the same mux with the
// same prefix is the host's mistake — and it is a mount-time panic rather than
// an endpoint silently split between two handlers.
//
// The per-endpoint half is the load-bearing one. Re-registering the adapter's
// own pattern has to collide, which is true only because the adapter registers
// each OIDC endpoint method-lessly, exactly as RegisterHandlers does: a
// "GET <path>" pattern would be *more specific* than RegisterHandlers' and
// ServeMux would accept both, leaving GET answered by one handler and POST by
// the other. That is the failure this shape exists to rule out, and it would
// pass every other test in the suite.
//
// Every case names the pattern it expects to be told about, because "it
// panicked with a conflict" is too weak an assertion to catch the regression:
// RegisterHandlers registers the JWKS route before it walks OIDCMounts, so the
// whole-method case collides there and would keep collapsing the same way if
// the adapters stopped mounting the four OIDC endpoints entirely.
func TestOIDCEndpointsCannotBeMountedTwice(t *testing.T) {
	idp, err := auth.NewIDP(auth.IDPConfig{Issuer: "https://idp.example.com" + auth.DefaultAPIPrefix}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	a, err := auth.New(auth.WithIDP(idp))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	// assertMultipleRegistration mounts the adapter, runs register against the
	// same mux, and requires the panic to be ServeMux's pattern conflict naming
	// wantPattern — the pattern the adapter had already registered.
	assertMultipleRegistration := func(t *testing.T, what, wantPattern string, register func(*http.ServeMux)) {
		t.Helper()
		mux := http.NewServeMux()
		nethttpadapter.Mount(mux, a)
		defer func() {
			recovered := recover()
			text := fmt.Sprint(recovered)
			switch {
			case recovered == nil:
				t.Errorf("%s did not panic: the endpoint is now split between two handlers "+
					"instead of refusing the second registration", what)
			case !strings.Contains(text, "conflicts with pattern"):
				t.Errorf("%s panicked with %v, want ServeMux's pattern-conflict panic", what, recovered)
			case !strings.Contains(text, wantPattern):
				t.Errorf("%s panicked over some other pattern (%v), want the conflict to name %q",
					what, recovered, wantPattern)
			}
		}()
		register(mux)
	}

	for _, mount := range idp.OIDCMounts() {
		t.Run(mount.Path, func(t *testing.T) {
			assertMultipleRegistration(t, "re-registering "+mount.Path, auth.DefaultAPIPrefix+mount.Path,
				func(mux *http.ServeMux) {
					mux.Handle(auth.DefaultAPIPrefix+mount.Path, mount.Handler)
				})
		})
	}

	// RegisterHandlers refuses before it reaches the four: its first
	// registration is the JWKS route, which the adapter has already mounted, so
	// this is where the host is told. Which pattern collides first is not the
	// point — that the call cannot quietly add a second copy of any of these
	// endpoints to a mux the adapter owns is.
	t.Run("RegisterHandlers collides at the JWKS route it registers first", func(t *testing.T) {
		assertMultipleRegistration(t, "RegisterHandlers on the adapter's own mux",
			"GET "+auth.DefaultAPIPrefix+idp.JWKSPath(),
			func(mux *http.ServeMux) {
				idp.RegisterHandlers(mux, auth.DefaultAPIPrefix)
			})
	})
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
