package wiretest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The JWKS group: the one route the adapters mount conditionally, on an Auth
// built with auth.WithIDP.
//
// The reference registers it on the auth router before any middleware, so that
// it is public, and only when the idProvider block carries a key or is enabled
// (auth.router.ts:473-475); the path is idProvider.jwksPath ?? the well-known
// one (:475); the response carries Cache-Control: public, max-age=3600 (:502)
// and an Access-Control-Allow-Origin resolved from jwksCorsOrigins (:492-500).
// Everything below is that route, asserted on all four adapters.
//
// The other half of the contract — that the route is absent without WithIDP,
// and that the generated OpenAPI document tracks it in both directions — is the
// "jwks" conditional set at the bottom of this file, replayed by testOpenAPI.

// testIDPKeyID is the kid the suite's IdP signs and publishes under. It is not
// the default, so an assertion on it cannot pass by accident on an IdP that
// ignored the configuration.
const testIDPKeyID = "wiretest-key-1"

// testIDPIssuer is the issuer of the suite's IdP. Nothing on the JWKS route
// reads it; it is here so the IdP is configured the way a host configures one.
const testIDPIssuer = "https://idp.example.com/auth"

// testJWKSCORSOrigin and testJWKSOtherOrigin are the allowlisted and the
// unlisted Origin of the CORS matrix.
const (
	testJWKSCORSOrigin  = "https://app.example.com"
	testJWKSOtherOrigin = "https://evil.example.com"
)

// testJWKSCustomPath is what IDPConfig.JWKSPath is set to when the suite checks
// that the mount follows the configuration rather than the constant.
const testJWKSCustomPath = "/keys.json"

// testIDPKey is one RSA-2048 key for the whole test binary. Key generation is
// the only slow thing in this group and the key's value is irrelevant to every
// assertion, so it is generated once and shared.
var testIDPKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		// Unreachable short of a broken entropy source, and conditionalRouteSet
		// hooks have no *testing.T to fail through.
		panic("wiretest: rsa.GenerateKey: " + err.Error())
	}
	return key
})

// newTestIDP builds the IdP the JWKS cases mount, with opts applied to the
// config before construction.
//
// The Service is nil: auth.WithIDP binds the one the Auth is built around, and
// nothing on the JWKS route needs a Service anyway.
func newTestIDP(opts ...func(*auth.IDPConfig)) *auth.IDP {
	cfg := auth.IDPConfig{Issuer: testIDPIssuer, Signer: testIDPKey(), KeyID: testIDPKeyID}
	for _, opt := range opts {
		opt(&cfg)
	}
	idp, err := auth.NewIDP(cfg, nil)
	if err != nil {
		panic("wiretest: auth.NewIDP: " + err.Error())
	}
	return idp
}

// wantJWKSDocument is the exact body the route must serve for the suite's key:
// the reference's document (jwks.service.ts:184-186) with the reference's six
// members in the reference's order (:5-12, :168-179).
func wantJWKSDocument() string {
	pub := testIDPKey().PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	return `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"` + testIDPKeyID +
		`","n":"` + n + `","e":"AQAB"}]}`
}

// jwksRequest builds a request for the JWKS route below the mount prefix. An
// empty origin sends no Origin header at all, which is the browserless case the
// reference treats as the empty string (auth.router.ts:496).
func jwksRequest(env *Env, method, path, origin string) *http.Request {
	req := httptest.NewRequest(method, env.Config.Prefix()+path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

// assertJWKSDocument holds one response to everything the reference's handler
// writes apart from the CORS header, which each caller asserts for itself.
func assertJWKSDocument(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q (auth.router.ts:502)", got, "public, max-age=3600")
	}
	// A cacheable public document must not carry a credential, and the route is
	// mounted ahead of the CSRF middleware precisely so that it does not.
	AssertNoCookies(t, rec)
	if got := strings.TrimSpace(rec.Body.String()); got != wantJWKSDocument() {
		t.Errorf("body = %s\nwant   %s", got, wantJWKSDocument())
	}
	// The shape, stated again through the decoder, so a body that happens to
	// match a stale literal still has to be this object.
	body := Body(t, rec)
	AssertKeys(t, body, "keys")
	keys, ok := body["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %#v, want one JWK", body["keys"])
	}
	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("keys[0] = %#v, want an object", keys[0])
	}
	AssertKeys(t, key, "kty", "use", "alg", "kid", "n", "e")
	for member, want := range map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testIDPKeyID, "e": "AQAB",
	} {
		if key[member] != want {
			t.Errorf("keys[0].%s = %v, want %q", member, key[member], want)
		}
	}
	if n, _ := key["n"].(string); n == "" {
		t.Error("keys[0].n is empty")
	}
}

// assertJWKSUnrouted fails unless the request missed the JWKS route entirely.
// Express answers 404 for a method no route on the path handles; the Go routers
// disagree on 404 versus 405 among themselves and always have, so both are
// accepted — what matters is that no document and no cache directive came back.
func assertJWKSUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q on an unrouted request, want none", got)
	}
	if strings.Contains(rec.Body.String(), `"keys"`) {
		t.Errorf("an unrouted request was served the JWKS document: %s", rec.Body.String())
	}
}

func testJWKS(t *testing.T, mount Mounter) {
	t.Run("serves the document with the reference headers", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP()))
		rec := env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, ""))
		assertJWKSDocument(t, rec)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Access-Control-Allow-Origin = %q, want %q (auth.router.ts:492-494)", got, "*")
		}
	})

	t.Run("no credential of any kind is required", func(t *testing.T) {
		// The reference registers the route before the auth middleware and
		// before its CSRF check (auth.router.ts:473-474), so a request with no
		// cookie, no bearer and no CSRF pair is the normal one — it is how a
		// relying party fetches the keys.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP()))
		req := jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, "")
		req.Header.Set("Authorization", "Bearer not-a-token")
		assertJWKSDocument(t, env.Do(req))
	})

	t.Run("the default CORS origin is the wildcard whatever the Origin says", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP()))
		for _, origin := range []string{"", testJWKSCORSOrigin, testJWKSOtherOrigin} {
			rec := env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, origin))
			AssertStatus(t, rec, http.StatusOK)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Origin %q: Access-Control-Allow-Origin = %q, want %q", origin, got, "*")
			}
		}
	})

	t.Run("a configured allowlist echoes a listed Origin and answers an unlisted one bare", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP(func(cfg *auth.IDPConfig) {
			cfg.JWKSCORSOrigins = []string{testJWKSCORSOrigin, "https://admin.example.com"}
		})))
		for _, tc := range []struct {
			name   string
			origin string
			want   string
		}{
			{"listed", testJWKSCORSOrigin, testJWKSCORSOrigin},
			{"listed, second entry", "https://admin.example.com", "https://admin.example.com"},
			{"unlisted", testJWKSOtherOrigin, ""},
			{"absent", "", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, tc.origin))
				// The document is served either way: CORS bounds what a browser
				// script may read, and the reference refuses nothing here.
				assertJWKSDocument(t, rec)
				got, present := rec.Header()["Access-Control-Allow-Origin"]
				switch {
				case tc.want == "" && present:
					t.Errorf("Access-Control-Allow-Origin = %q for an unlisted Origin, want no header at all (auth.router.ts:497-499)", got)
				case tc.want != "" && (!present || got[0] != tc.want):
					t.Errorf("Access-Control-Allow-Origin = %v, want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("HEAD is served from the GET route", func(t *testing.T) {
		// Express falls back from HEAD to the GET handler when no HEAD handler
		// is registered, which is what router.get gives the reference route
		// (auth.router.ts:490). net/http does the same for a "GET" pattern;
		// chi, gin and echo do not, so the adapters register HEAD explicitly.
		// The recorder does not strip the body a real server would, so only the
		// status and the headers are asserted.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP()))
		rec := env.Do(jwksRequest(env, http.MethodHead, auth.DefaultJWKSPath, ""))
		AssertStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
			t.Errorf("HEAD Cache-Control = %q, want %q", got, "public, max-age=3600")
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("HEAD Access-Control-Allow-Origin = %q, want %q", got, "*")
		}
	})

	t.Run("the route is GET-only", func(t *testing.T) {
		// router.get registers GET alone (auth.router.ts:490); a POST matches no
		// route on the path and falls through the reference router to its 404.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP()))
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(method, func(t *testing.T) {
				assertJWKSUnrouted(t, env.Do(jwksRequest(env, method, auth.DefaultJWKSPath, "")))
			})
		}
	})

	t.Run("the mount follows IDPConfig.JWKSPath", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithIDP(newTestIDP(func(cfg *auth.IDPConfig) {
			cfg.JWKSPath = testJWKSCustomPath
		})))
		assertJWKSDocument(t, env.Do(jwksRequest(env, http.MethodGet, testJWKSCustomPath, "")))
		// And only there: the constant is a default, not a second mount.
		assertJWKSUnrouted(t, env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, "")))
	})

	t.Run("without WithIDP there is no route", func(t *testing.T) {
		// The reference registers nothing when the idProvider block is absent
		// (auth.router.ts:473). testOpenAPI asserts the same thing through the
		// conditional set; this is the group saying it in its own terms.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		assertJWKSUnrouted(t, env.Do(jwksRequest(env, http.MethodGet, auth.DefaultJWKSPath, "")))
	})
}

// jwksRouteSet is the conditional set testOpenAPI replays: configured, the
// adapter serves GET <prefix>/.well-known/jwks.json and the document generated
// with OpenAPIInfo.IDProvider describes it; unconfigured, neither does.
func jwksRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name: "jwks",
		configure: func(pc *probeConfig) {
			pc.Opts = append(pc.Opts, auth.WithIDP(newTestIDP()))
		},
		routes: map[string]string{auth.DefaultJWKSPath: http.MethodGet},
		spec:   func() auth.OpenAPIInfo { return auth.OpenAPIInfo{IDProvider: true} },
	}
}
