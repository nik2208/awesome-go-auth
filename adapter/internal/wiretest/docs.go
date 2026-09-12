package wiretest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The documentation group: the two routes the adapters mount under
// HTTPConfig.Docs.Enabled.
//
// The reference registers both at the end of its auth router, with no guard of
// their own — no auth middleware, no session — under one condition,
// swagger === true || (swagger !== false && NODE_ENV !== "production")
// (auth.router.ts:1652-1656). GET <prefix>/openapi.json answers the generated
// document as application/json (:1658-1671) and GET <prefix>/docs answers the
// Swagger UI page built by buildSwaggerUiHtml, pointed at specBasePath +
// "/openapi.json" (:1674-1677, openapi.ts:1646-1669). Everything below is
// those two routes, asserted on all four adapters.
//
// "No guard of their own" is not "outside every middleware": unlike the JWKS
// route, which is registered at :490 and really is bare, these two are
// registered after the router-level CSRF auto-init at :529-538, and Express
// runs every earlier router.use layer for a route registered later. So a
// reader's first fetch of either answers with a fresh csrf-token cookie, and
// that is what the cookie assertions below pin.
//
// The other half of the contract — that neither route exists without the flag,
// and that the generated document tracks both in either direction — is the
// "docs" conditional set at the bottom of this file, replayed by testOpenAPI.

// testDocsBasePath is what DocsOptions.BasePath is set to when the suite checks
// that the description follows the configuration rather than the mount. It is
// deliberately not the mount prefix, so an assertion on it cannot pass by
// accident.
const testDocsBasePath = "/public/api/auth"

// swaggerUIMarkers are the load-bearing literals of the reference's page: the
// two CDN bundles it pulls swagger-ui-dist@5 from, and the call it hands them
// to. They are asserted rather than the whole page because the whole page is
// pinned byte for byte in the root package (docs_test.go); here the question is
// only that each adapter serves that page and not something else.
var swaggerUIMarkers = []string{
	"https://unpkg.com/swagger-ui-dist@5/swagger-ui.css",
	"https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js",
	"SwaggerUIBundle({",
}

// docsConfig is the wire configuration with the documentation routes on, plus
// whatever else the case needs.
func docsConfig(opts ...func(*auth.DocsOptions)) auth.HTTPConfig {
	cfg := auth.DefaultHTTPConfig()
	cfg.Docs.Enabled = true
	for _, opt := range opts {
		opt(&cfg.Docs)
	}
	return cfg
}

// docsRequest builds a request for one documentation route below the mount
// prefix. No credential and no CSRF pair: that is how a reader fetches these.
// Neither route has an auth gate to satisfy, and the CSRF middleware in front
// of them never checks a GET or a HEAD, so a bare request is the normal one.
func docsRequest(env *Env, method, path string) *http.Request {
	return httptest.NewRequest(method, env.Config.Prefix()+path, nil)
}

// assertDocsCookies holds the Set-Cookie headers of a documentation response
// fetched without one: exactly the csrf-token cookie the reference's
// router-level auto-init writes when the request carries none
// (auth.router.ts:529-538), on the same terms as every other route below that
// layer, and nothing else. A document is not a credential: no access or refresh
// cookie may ride out on either route.
func assertDocsCookies(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	names := cookieNames(rec)
	if len(names) != 1 || names[0] != hostCSRF {
		t.Fatalf("Set-Cookie = %v, want exactly [%s]", names, hostCSRF)
	}
	csrf := Cookie(t, rec, hostCSRF)
	if len(csrf.Value) != 32 {
		t.Errorf("csrf token = %q, want 32 hex characters", csrf.Value)
	}
	AssertCookieAttrs(t, csrf, csrfCookieSpec())
}

// assertDocsUnrouted fails unless the request missed both documentation routes
// entirely. Express answers 404 for a method no route on the path handles; the
// Go routers disagree on 404 versus 405 among themselves and always have, so
// both are accepted — what matters is that no document and no page came back.
func assertDocsUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	for _, marker := range append([]string{`"openapi"`}, swaggerUIMarkers...) {
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("an unrouted request was served documentation (%q): %s", marker, rec.Body.String())
		}
	}
}

// assertOpenAPIDocument holds one response to what the reference's route
// writes: 200, application/json, and a document whose paths object describes
// the mount it was served from.
func assertOpenAPIDocument(t *testing.T, rec *httptest.ResponseRecorder, base string) {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q (auth.router.ts:1670)", got, "application/json")
	}
	assertDocsCookies(t, rec)

	body := Body(t, rec)
	paths, ok := body["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %#v, want an object", body["paths"])
	}
	if len(paths) == 0 {
		t.Fatal("the document describes no paths at all")
	}
	// The routes the document must describe: one of the unconditional group, so
	// this is the real spec and not an empty shell, and its own two, which are
	// there only because the flag that mounted them is set.
	for _, route := range []string{"/login", auth.DocsSpecPath, auth.DocsUIPath} {
		if _, ok := paths[base+route]; !ok {
			t.Errorf("the document does not describe %q", base+route)
		}
	}
	for path := range paths {
		if !strings.HasPrefix(path, base) {
			t.Errorf("documented path %q is not under the base path %q", path, base)
		}
	}
}

// assertSwaggerUIPage holds one response to the reference's Swagger UI page:
// 200, HTML, the two CDN bundles, and the spec URL this mount serves.
func assertSwaggerUIPage(t *testing.T, rec *httptest.ResponseRecorder, base string) {
	t.Helper()
	AssertStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q (auth.router.ts:1675)", got, "text/html; charset=utf-8")
	}
	assertDocsCookies(t, rec)

	page := rec.Body.String()
	for _, marker := range swaggerUIMarkers {
		if !strings.Contains(page, marker) {
			t.Errorf("the page does not carry %q (openapi.ts:1646-1669)", marker)
		}
	}
	// The url SwaggerUIBundle is given: specBasePath + "/openapi.json"
	// (auth.router.ts:1676), JSON-quoted as the reference quotes it.
	want := `url: "` + base + auth.DocsSpecPath + `"`
	if !strings.Contains(page, want) {
		t.Errorf("the page does not point at the document: want %q in\n%s", want, page)
	}
}

func testDocs(t *testing.T, mount Mounter) {
	t.Run("serves the generated document as JSON", func(t *testing.T) {
		env := NewEnv(t, mount, docsConfig())
		assertOpenAPIDocument(t, env.Do(docsRequest(env, http.MethodGet, auth.DocsSpecPath)), env.Config.Prefix())
	})

	t.Run("serves the reference Swagger UI page", func(t *testing.T) {
		env := NewEnv(t, mount, docsConfig())
		assertSwaggerUIPage(t, env.Do(docsRequest(env, http.MethodGet, auth.DocsUIPath)), env.Config.Prefix())
	})

	t.Run("no credential of any kind is required", func(t *testing.T) {
		// Neither route has a guard of its own in the reference
		// (auth.router.ts:1658, :1674) — no auth middleware to satisfy — and
		// the CSRF layer they do sit under never checks a GET. So a request
		// with no cookie, no bearer and no CSRF pair is the normal one, and one
		// carrying a bearer token that would not verify anywhere is still
		// served: nothing on these two routes looks at it. It does suppress the
		// cookie, which is why this case asserts the status alone — the port
		// sends no cookie to a caller that presented a bearer credential, on
		// every route.
		env := NewEnv(t, mount, docsConfig())
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			req := docsRequest(env, http.MethodGet, path)
			req.Header.Set("Authorization", "Bearer not-a-token")
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
			AssertNoCookies(t, rec)
		}
	})

	t.Run("a reader that already has the CSRF cookie is given no other", func(t *testing.T) {
		// The reference's auto-init writes one only when the request carries
		// none (auth.router.ts:532-535). A second fetch of either route, with
		// the cookie the first one set, therefore sets nothing at all.
		env := NewEnv(t, mount, docsConfig())
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			req := docsRequest(env, http.MethodGet, path)
			req.AddCookie(&http.Cookie{Name: hostCSRF, Value: csrfPairValue})
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
			AssertNoCookies(t, rec)
		}
	})

	t.Run("both follow DocsOptions.BasePath", func(t *testing.T) {
		// swaggerBasePath moves the description, never the mount
		// (auth.router.ts:1657): the routes stay where the adapter is, and both
		// the documented paths and the page's spec URL move.
		env := NewEnv(t, mount, docsConfig(func(docs *auth.DocsOptions) {
			docs.BasePath = testDocsBasePath
		}))
		assertOpenAPIDocument(t, env.Do(docsRequest(env, http.MethodGet, auth.DocsSpecPath)), testDocsBasePath)
		assertSwaggerUIPage(t, env.Do(docsRequest(env, http.MethodGet, auth.DocsUIPath)), testDocsBasePath)
	})

	t.Run("HEAD is served from the GET route", func(t *testing.T) {
		// Express falls back from HEAD to the GET handler when no HEAD handler
		// is registered, which is what router.get gives the reference routes
		// (auth.router.ts:1658, :1674). net/http does the same for a GET
		// pattern; chi, gin and echo do not, so the adapters register HEAD
		// explicitly. The recorder does not strip the body a real server would,
		// so only the status and the headers are asserted.
		env := NewEnv(t, mount, docsConfig())
		for path, contentType := range map[string]string{
			auth.DocsSpecPath: "application/json",
			auth.DocsUIPath:   "text/html; charset=utf-8",
		} {
			rec := env.Do(docsRequest(env, http.MethodHead, path))
			AssertStatus(t, rec, http.StatusOK)
			if got := rec.Header().Get("Content-Type"); got != contentType {
				t.Errorf("HEAD %s Content-Type = %q, want %q", path, got, contentType)
			}
		}
	})

	t.Run("the routes are GET-only", func(t *testing.T) {
		// router.get registers GET alone (auth.router.ts:1658, :1674); a POST
		// matches no route on the path and falls through to the router 404.
		env := NewEnv(t, mount, docsConfig())
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				t.Run(method+" "+path, func(t *testing.T) {
					assertDocsUnrouted(t, env.Do(docsRequest(env, method, path)))
				})
			}
		}
	})

	t.Run("without Docs.Enabled there is neither route", func(t *testing.T) {
		// The reference registers nothing when its swagger option is off
		// (auth.router.ts:1656). testOpenAPI asserts the same thing through the
		// conditional set; this is the group saying it in its own terms.
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			assertDocsUnrouted(t, env.Do(docsRequest(env, http.MethodGet, path)))
		}
	})
}

// docsRouteSet is the conditional set testOpenAPI replays: configured, the
// adapter serves GET <prefix>/openapi.json and GET <prefix>/docs and the
// document generated with OpenAPIInfo.Docs describes both; unconfigured,
// neither does.
func docsRouteSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      "docs",
		configure: func(pc *probeConfig) { pc.HTTP.Docs.Enabled = true },
		routes: map[string]string{
			auth.DocsSpecPath: http.MethodGet,
			auth.DocsUIPath:   http.MethodGet,
		},
		spec: func() auth.OpenAPIInfo { return auth.OpenAPIInfo{Docs: true} },
	}
}
