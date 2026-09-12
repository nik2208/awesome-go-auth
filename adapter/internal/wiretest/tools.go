package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The tools router: the skeleton of tools.router.ts, which is the mount, the
// feature flags, the guard slot and the two documentation routes.
//
// M9's tools half is split by authentication posture rather than by route group,
// and U22 is the PR that decides who gets in. Everything U23 through U25 mount
// goes behind auth.ToolsProtectMiddleware or — for the inbound webhook and the
// two routes below — deliberately does not, so the cases here are written as a
// mount-and-posture suite that happens to have two routes attached.
//
// What the reference does, and what this suite pins instead: createToolsRouter
// builds its guard as `authMiddleware ? [authMiddleware] : []`
// (tools.router.ts:135) with all four feature flags defaulting to true
// (:121-124), so a host that forgets the middleware publishes the whole surface
// unauthenticated and is told nothing. This port mounts nothing until
// HTTPConfig.ToolsMounted() — the block enabled, an AuthTools supplied and an
// access decision made — which is the
// tools-router-requires-an-explicit-guard-decision deviation, and the
// reference's own default is auth.ToolsPublic(). Both halves are asserted below.
//
// It is a conditional set in the sense the admin one is, and like that one it is
// deliberately **not** registered in suite.go's conditionalRoutes. That registry
// holds every set to auth.GenerateOpenAPISpec, which describes the auth router:
// its paths are relative to HTTPConfig.Prefix(), while the tools router mounts
// beside that prefix. The document that describes this router is a second
// generator — auth.GenerateToolsOpenAPISpec, the port of the reference's own
// second builder (openapi.ts:1366) — so a set registered there would have to
// claim the auth document describes /tools/*. The two-direction comparison is
// therefore done here instead, against that generator, in
// "the document and the mount agree"; U23 through U25 extend
// toolsDocumentedRoutes as they add routes.

// toolsDocumentedRoutes is the operation set the tools document must describe
// and the mount must serve, relative to the tools mount.
//
// It is spelled out by hand for the reason documentedRoutes is: a list derived
// from the document agrees with whatever the document happens to say. U22 mounts
// two routes; U23 adds /track/{eventName} and /notify/{target} here, U24
// /stream, U25 /telemetry and /webhook/{provider}.
var toolsDocumentedRoutes = map[string]string{
	auth.DocsSpecPath: http.MethodGet,
	auth.DocsUIPath:   http.MethodGet,
}

// toolsFeatureRoutes are the five feature routes of the reference's router,
// none of which U22 mounts. Every case that probes "not mounted" walks these as
// well as the two documented ones, so a route cannot arrive without the PR that
// owns it noticing this list.
var toolsFeatureRoutes = []string{
	auth.ToolsTrackPath + "/identity.probe",
	auth.ToolsNotifyPath + "/global",
	auth.ToolsStreamPath,
	auth.ToolsTelemetryPath,
	auth.ToolsWebhookPath + "/probe",
}

// testToolsBasePath is what Tools.Docs.BasePath is set to when the suite checks
// that the description follows the configuration rather than the mount.
// Deliberately not the mount, so an assertion on it cannot pass by accident.
const testToolsBasePath = "/public/tools"

// testToolsPath is a non-default mount, for the same reason.
const testToolsPath = "/internal/tools"

// toolsFacade builds the AuthTools every mounted configuration needs. SSE is off
// and every store is nil: U22 mounts no route that reaches any of them, and a
// facade is a precondition of the mount rather than of an assertion here.
func toolsFacade(t *testing.T) *auth.AuthTools {
	t.Helper()
	tools, err := auth.NewAuthTools(context.Background(), auth.NewEventBus(), auth.AuthToolsOptions{})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	return tools
}

// toolsConfig is the wire configuration with the tools router fully configured —
// enabled, a facade, an access decision and its own documentation routes on —
// plus whatever else the case needs.
func toolsConfig(t *testing.T, opts ...func(*auth.ToolsOptions)) auth.HTTPConfig {
	t.Helper()
	cfg := auth.DefaultHTTPConfig()
	cfg.Tools = auth.ToolsOptions{
		Enabled:   true,
		AuthTools: toolsFacade(t),
		Access:    auth.ToolsPublic(),
	}
	cfg.Tools.Docs.Enabled = true
	for _, opt := range opts {
		opt(&cfg.Tools)
	}
	return cfg
}

// toolsRequest builds a request for one route below the tools mount. No
// credential and no CSRF pair: the two routes U22 mounts have no guard, and the
// tools router carries none of the auth router's middleware either.
func toolsRequest(env *Env, method, path string) *http.Request {
	return httptest.NewRequest(method, env.Config.ToolsPath()+path, nil)
}

// assertToolsUnrouted fails unless the request missed every tools route. Express
// answers 404 for a method no route on the path handles; the Go routers disagree
// on 404 versus 405 among themselves and always have, so both are accepted —
// what matters is that no document, no page and no `ok` came back.
func assertToolsUnrouted(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	switch rec.Code {
	case http.StatusNotFound, http.StatusMethodNotAllowed:
	default:
		t.Fatalf("status = %d, want 404 or 405 (body %q)", rec.Code, rec.Body.String())
	}
	for _, marker := range append([]string{`"openapi"`, `"ok"`}, swaggerUIMarkers...) {
		if strings.Contains(rec.Body.String(), marker) {
			t.Errorf("an unrouted request was served a tools response (%q): %s", marker, rec.Body.String())
		}
	}
}

// assertNoToolsRoutes fails unless every path of the tools router is unrouted:
// the two documentation routes and the five feature routes, on the methods the
// reference registers them with.
func assertNoToolsRoutes(t *testing.T, env *Env) {
	t.Helper()
	for path := range toolsDocumentedRoutes {
		assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodGet, path)))
	}
	for _, path := range toolsFeatureRoutes {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			assertToolsUnrouted(t, env.Do(toolsRequest(env, method, path)))
		}
	}
}

// toolsDocument fetches and decodes the served tools document.
func toolsDocument(t *testing.T, env *Env) map[string]any {
	t.Helper()
	rec := env.Do(toolsRequest(env, http.MethodGet, auth.DocsSpecPath))
	AssertStatus(t, rec, http.StatusOK)
	return Body(t, rec)
}

// toolsDocumentPaths is the served document's paths object.
func toolsDocumentPaths(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	paths, ok := body["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %#v, want an object", body["paths"])
	}
	return paths
}

// toolsTagNames is the document's tags block, by name.
func toolsTagNames(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["tags"].([]any)
	if !ok {
		t.Fatalf("tags = %#v, want an array", body["tags"])
	}
	names := make([]string, 0, len(raw))
	for _, entry := range raw {
		tag, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("tag = %#v, want an object", entry)
		}
		name, _ := tag["name"].(string)
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func testTools(t *testing.T, mount Mounter) {
	t.Run("an access decision is required to mount anything", func(t *testing.T) {
		// The deviation, in its own terms. The reference builds the router with
		// an empty protect slot and serves every route (tools.router.ts:135);
		// here the configuration is incomplete, so no route under the mount is
		// registered at all — not even the two that would carry no guard in any
		// case.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.Access = nil }))
		assertNoToolsRoutes(t, env)
	})

	t.Run("a nil middleware is not an access decision", func(t *testing.T) {
		// auth.ToolsProtected(nil) is a host whose middleware variable was never
		// assigned. It resolves to "not set" rather than to an open router, so
		// the mount is refused instead of silently degrading.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(nil)
		}))
		assertNoToolsRoutes(t, env)
	})

	t.Run("the block must be enabled", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.Enabled = false }))
		assertNoToolsRoutes(t, env)
	})

	t.Run("a facade is required", func(t *testing.T) {
		// Every route of this router calls AuthTools. Without one the reference
		// could not have been constructed at all — the facade is its first,
		// required argument (tools.router.ts:117).
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.AuthTools = nil }))
		assertNoToolsRoutes(t, env)
	})

	t.Run("the default configuration mounts nothing", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		assertNoToolsRoutes(t, env)
	})

	t.Run("ToolsPublic is the reference's default, by name", func(t *testing.T) {
		// One call restores what createToolsRouter does with no authMiddleware.
		// In U22 that is observable on the two documentation routes; from U23 it
		// is the whole surface.
		env := NewEnv(t, mount, toolsConfig(t))
		AssertStatus(t, env.Do(toolsRequest(env, http.MethodGet, auth.DocsSpecPath)), http.StatusOK)
		AssertStatus(t, env.Do(toolsRequest(env, http.MethodGet, auth.DocsUIPath)), http.StatusOK)
	})

	t.Run("serves its own document as JSON", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t))
		rec := env.Do(toolsRequest(env, http.MethodGet, auth.DocsSpecPath))
		AssertStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q (tools.router.ts:344)", got, "application/json")
		}
		body := Body(t, rec)
		info, ok := body["info"].(map[string]any)
		if !ok {
			t.Fatalf("info = %#v, want an object", body["info"])
		}
		// The document is the tools one and not the auth router's: its title
		// names the tools surface (openapi.ts:1629) and it describes no auth
		// route.
		if title, _ := info["title"].(string); !strings.Contains(title, "Tools API") {
			t.Errorf("info.title = %q, want it to name the Tools API", title)
		}
		for path := range toolsDocumentPaths(t, body) {
			if strings.HasSuffix(path, "/login") {
				t.Errorf("the tools document describes an auth route (%q)", path)
			}
		}
	})

	t.Run("serves the reference Swagger UI page", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t))
		rec := env.Do(toolsRequest(env, http.MethodGet, auth.DocsUIPath))
		AssertStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want %q (tools.router.ts:349)", got, "text/html; charset=utf-8")
		}
		page := rec.Body.String()
		// The same page the auth router serves, because the reference has one
		// builder for all three of its routers (openapi.ts:1646, read at
		// tools.router.ts:350) — including the title, which says "Tools API" on
		// every one of them and is the only one of the three where it is true.
		for _, marker := range append([]string{"Tools API"}, swaggerUIMarkers...) {
			if !strings.Contains(page, marker) {
				t.Errorf("the page does not carry %q (openapi.ts:1646-1669)", marker)
			}
		}
		want := `url: "` + env.Config.ToolsPath() + auth.DocsSpecPath + `"`
		if !strings.Contains(page, want) {
			t.Errorf("the page does not point at the document: want %q in\n%s", want, page)
		}
	})

	t.Run("the documentation routes carry no guard", func(t *testing.T) {
		// The reference spreads no protect onto either (tools.router.ts:333,
		// :348), so a guard that refuses everything must not be in front of
		// them. This is the case that tells "the guard is wired to the right
		// routes" from "the guard is not wired at all": it fails if U23 through
		// U25 ever wrap these two.
		refused := 0
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					refused++
					w.WriteHeader(http.StatusForbidden)
				})
			})
		}))
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			AssertStatus(t, env.Do(toolsRequest(env, http.MethodGet, path)), http.StatusOK)
		}
		if refused != 0 {
			t.Errorf("the guard ran %d times on the documentation routes, want 0", refused)
		}
	})

	t.Run("none of the auth router's middleware is in front of it", func(t *testing.T) {
		// The tools router is a separate Express router, outside the auth
		// router's CSRF auto-init (auth.router.ts:529-538) and its rate-limiter
		// slot. So unlike the auth router's own documentation routes, which
		// hand a reader a csrf-token cookie, these two set no cookie at all —
		// and that is what keeps POST <tools>/track reachable by a
		// server-to-server caller from U23 on.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, path := range []string{auth.DocsSpecPath, auth.DocsUIPath} {
			rec := env.Do(toolsRequest(env, http.MethodGet, path))
			AssertStatus(t, rec, http.StatusOK)
			AssertNoCookies(t, rec)
		}
	})

	t.Run("the document and the mount agree", func(t *testing.T) {
		// Both directions, as testOpenAPI does for the auth router: every
		// documented operation is reachable, and every route the adapter mounts
		// is documented. The generator is the tools one.
		env := NewEnv(t, mount, toolsConfig(t))
		base := env.Config.ToolsPath()
		paths := toolsDocumentPaths(t, toolsDocument(t, env))

		for path, method := range toolsDocumentedRoutes {
			item, ok := paths[base+path]
			if !ok {
				t.Errorf("the document does not describe %q", base+path)
				continue
			}
			operations, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("path item %q = %#v, want an object", base+path, item)
			}
			if _, ok := operations[strings.ToLower(method)]; !ok {
				t.Errorf("the document describes %q without %s", base+path, method)
			}
			rec := env.Do(toolsRequest(env, method, path))
			if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("%s %s is documented and answers %d", method, base+path, rec.Code)
			}
		}
		for path := range paths {
			rel := strings.TrimPrefix(path, base)
			if _, ok := toolsDocumentedRoutes[rel]; !ok {
				t.Errorf("the document describes %q, which is not in toolsDocumentedRoutes", path)
			}
		}
		// The generated document and the served one must be the same document:
		// the adapter has to pass its own configuration to the generator, not a
		// default.
		generated := auth.GenerateToolsOpenAPISpec(env.Config.ToolsOpenAPIInfo())
		for path := range generated["paths"].(map[string]any) {
			if _, ok := paths[path]; !ok {
				t.Errorf("the served document omits %q, which the generator describes", path)
			}
		}
	})

	t.Run("the four feature groups are not mounted yet", func(t *testing.T) {
		// U22 mounts the skeleton and none of the feature routes: track and
		// notify are U23, the stream is U24, the telemetry query and the inbound
		// webhook are U25. This case is the stop-point — the PR that mounts one
		// of these replaces its entry here with real assertions, so a route
		// cannot arrive without this list being edited.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, path := range toolsFeatureRoutes {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				assertToolsUnrouted(t, env.Do(toolsRequest(env, method, path)))
			}
		}
	})

	t.Run("the document tracks the feature flags", func(t *testing.T) {
		// The four flags default to on, as the reference's do
		// (tools.router.ts:121-124) — which in Go means the zero value of the
		// four Disable fields. What they select today is the tags block, the
		// reference's own flag-driven vocabulary (openapi.ts:1621-1625).
		for _, tc := range []struct {
			name string
			edit func(*auth.ToolsOptions)
			want []string
		}{
			{"all four on by default", func(*auth.ToolsOptions) {}, []string{"Notifications", "Telemetry", "Webhooks"}},
			{"telemetry off", func(o *auth.ToolsOptions) { o.DisableTelemetry = true }, []string{"Notifications", "Webhooks"}},
			{"webhook off", func(o *auth.ToolsOptions) { o.DisableWebhook = true }, []string{"Notifications", "Telemetry"}},
			{"notify and stream off", func(o *auth.ToolsOptions) {
				o.DisableNotify = true
				o.DisableStream = true
			}, []string{"Telemetry", "Webhooks"}},
			{"notify off alone keeps Notifications", func(o *auth.ToolsOptions) { o.DisableNotify = true },
				[]string{"Notifications", "Telemetry", "Webhooks"}},
			{"all four off", func(o *auth.ToolsOptions) {
				o.DisableTelemetry = true
				o.DisableNotify = true
				o.DisableStream = true
				o.DisableWebhook = true
			}, []string{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				env := NewEnv(t, mount, toolsConfig(t, tc.edit))
				got := toolsTagNames(t, toolsDocument(t, env))
				if strings.Join(got, ",") != strings.Join(tc.want, ",") {
					t.Errorf("tags = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("without Docs.Enabled there is neither documentation route", func(t *testing.T) {
		// This router has its own swagger option, separate from the auth
		// router's (tools.router.ts:93 against auth.router.ts:123), and off it
		// registers neither route (:332).
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.Docs.Enabled = false }))
		for path := range toolsDocumentedRoutes {
			assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodGet, path)))
		}
	})

	t.Run("Docs.BasePath moves the description, not the mount", func(t *testing.T) {
		// swaggerBasePath is read into the document's paths and the page's spec
		// URL (tools.router.ts:342, :350) and nowhere else, so the routes stay
		// where the adapter mounted them.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.Docs.BasePath = testToolsBasePath
		}))
		paths := toolsDocumentPaths(t, toolsDocument(t, env))
		for path := range toolsDocumentedRoutes {
			if _, ok := paths[testToolsBasePath+path]; !ok {
				t.Errorf("the document does not describe %q", testToolsBasePath+path)
			}
		}
		page := env.Do(toolsRequest(env, http.MethodGet, auth.DocsUIPath))
		AssertStatus(t, page, http.StatusOK)
		want := `url: "` + testToolsBasePath + auth.DocsSpecPath + `"`
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("the page does not point at %q", want)
		}
	})

	t.Run("the mount follows Tools.Path", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.Path = testToolsPath }))
		if got := env.Config.ToolsPath(); got != testToolsPath {
			t.Fatalf("ToolsPath() = %q, want %q", got, testToolsPath)
		}
		AssertStatus(t, env.Do(toolsRequest(env, http.MethodGet, auth.DocsSpecPath)), http.StatusOK)
		// And nothing is left behind at the default mount.
		assertToolsUnrouted(t, env.Do(httptest.NewRequest(http.MethodGet, auth.DefaultToolsPath+auth.DocsSpecPath, nil)))
	})

	t.Run("it mounts beside the API prefix, not under it", func(t *testing.T) {
		// The reference's createToolsRouter is a second router the host mounts
		// itself, and its own swaggerBasePath default is '/tools'
		// (tools.router.ts:114, :127) — not the auth router's apiPrefix. With
		// both sets of documentation routes on, the two documents are different
		// documents served from different mounts.
		cfg := toolsConfig(t)
		cfg.Docs.Enabled = true
		env := NewEnv(t, mount, cfg)

		authSpec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+auth.DocsSpecPath, nil))
		AssertStatus(t, authSpec, http.StatusOK)
		authPaths := toolsDocumentPaths(t, Body(t, authSpec))
		if _, ok := authPaths[env.Config.Prefix()+"/login"]; !ok {
			t.Errorf("the auth document at %q does not describe /login", env.Config.Prefix()+auth.DocsSpecPath)
		}

		toolsPaths := toolsDocumentPaths(t, toolsDocument(t, env))
		if _, ok := toolsPaths[env.Config.ToolsPath()+auth.DocsSpecPath]; !ok {
			t.Errorf("the tools document does not describe itself at %q", env.Config.ToolsPath()+auth.DocsSpecPath)
		}
	})

	t.Run("HEAD is served from the GET route", func(t *testing.T) {
		// Express falls back from HEAD to the GET handler when no HEAD handler
		// is registered, which is what router.get gives these two
		// (tools.router.ts:333, :348). net/http does the same for a GET
		// pattern; chi, gin and echo do not, so the adapters mount this router
		// for every method and the switch inside it accepts both.
		env := NewEnv(t, mount, toolsConfig(t))
		for path, contentType := range map[string]string{
			auth.DocsSpecPath: "application/json",
			auth.DocsUIPath:   "text/html; charset=utf-8",
		} {
			rec := env.Do(toolsRequest(env, http.MethodHead, path))
			AssertStatus(t, rec, http.StatusOK)
			if got := rec.Header().Get("Content-Type"); got != contentType {
				t.Errorf("HEAD %s Content-Type = %q, want %q", path, got, contentType)
			}
		}
	})

	t.Run("the documentation routes are read-only", func(t *testing.T) {
		// router.get registers GET alone (tools.router.ts:333, :348); anything
		// else matches no layer and falls through to the router 404.
		env := NewEnv(t, mount, toolsConfig(t))
		for path := range toolsDocumentedRoutes {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				t.Run(method+" "+path, func(t *testing.T) {
					assertToolsUnrouted(t, env.Do(toolsRequest(env, method, path)))
				})
			}
		}
	})

	t.Run("the bare mount is a 404", func(t *testing.T) {
		// The reference's router has no layer on '/', so GET /tools itself ends
		// at the router 404 — the mount exists to be a prefix.
		env := NewEnv(t, mount, toolsConfig(t))
		assertToolsUnrouted(t, env.Do(httptest.NewRequest(http.MethodGet, env.Config.ToolsPath(), nil)))
	})
}
