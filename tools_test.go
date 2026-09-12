package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The parts of the tools skeleton that are decisions rather than wire: where it
// mounts, whether it mounts at all, how the four flags resolve, and what the
// guard slot does with each of its three configurations.
//
// The wire itself — the two documentation routes, the document, the page — is
// pinned for all four adapters in adapter/internal/wiretest/tools.go. What is
// here is what that suite cannot reach: the guard wrapper on its own, which U22
// installs and U23 is the first to put a route behind.

func TestToolsPathNormalises(t *testing.T) {
	for input, want := range map[string]string{
		"":              DefaultToolsPath,
		"   ":           DefaultToolsPath,
		"tools":         "/tools",
		"/tools":        "/tools",
		"/tools/":       "/tools",
		"internal/ops/": "/internal/ops",
	} {
		cfg := HTTPConfig{Tools: ToolsOptions{Path: input}}
		if got := cfg.ToolsPath(); got != want {
			t.Errorf("ToolsPath(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestToolsMounted is the tools-router-requires-an-explicit-guard-decision
// deviation stated as a truth table. The third row is the one the reference
// serves unguarded and says nothing about (tools.router.ts:135).
func TestToolsMounted(t *testing.T) {
	facade := &AuthTools{Events: NewEventBus()}
	cases := []struct {
		name string
		opts ToolsOptions
		want bool
	}{
		{"nothing configured", ToolsOptions{}, false},
		{"a facade and an access decision but no flag", ToolsOptions{AuthTools: facade, Access: ToolsPublic()}, false},
		{"the flag and a facade but no access decision", ToolsOptions{Enabled: true, AuthTools: facade}, false},
		{"the flag and an access decision but no facade", ToolsOptions{Enabled: true, Access: ToolsPublic()}, false},
		{"the flag, a facade and a guard", ToolsOptions{
			Enabled:   true,
			AuthTools: facade,
			Access:    ToolsProtected(func(next http.Handler) http.Handler { return next }),
		}, true},
		{"the flag, a facade and the reference's default by name", ToolsOptions{
			Enabled:   true,
			AuthTools: facade,
			Access:    ToolsPublic(),
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (HTTPConfig{Tools: c.opts}).ToolsMounted(); got != c.want {
				t.Errorf("ToolsMounted() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestToolsProtectedRefusesANilMiddleware pins the one place a configuration
// could silently degrade from guarded to open: a host whose middleware variable
// was never assigned.
func TestToolsProtectedRefusesANilMiddleware(t *testing.T) {
	if got := ToolsProtected(nil); got != nil {
		t.Errorf("ToolsProtected(nil) = %#v, want nil so that nothing mounts", got)
	}
	if got := ToolsPublic(); got == nil || got.Middleware != nil {
		t.Errorf("ToolsPublic() = %#v, want a non-nil access with no middleware", got)
	}
}

// TestToolsProtectMiddleware is the guard slot itself: the wrapper U23 through
// U25 put every guarded route behind. The reference's `...protect` is an empty
// array when authMiddleware is absent (tools.router.ts:135), which is the
// pass-through below.
func TestToolsProtectMiddleware(t *testing.T) {
	reached := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

	t.Run("ToolsPublic is a pass-through", func(t *testing.T) {
		cfg := HTTPConfig{Tools: ToolsOptions{Access: ToolsPublic()}}
		rec := httptest.NewRecorder()
		ToolsProtectMiddleware(cfg)(http.HandlerFunc(reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/stream", nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("status = %d, want %d: the handler was not reached", rec.Code, http.StatusTeapot)
		}
	})

	t.Run("a configured guard is applied", func(t *testing.T) {
		calls := 0
		cfg := HTTPConfig{Tools: ToolsOptions{Access: ToolsProtected(func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusUnauthorized)
			})
		})}}
		rec := httptest.NewRecorder()
		ToolsProtectMiddleware(cfg)(http.HandlerFunc(reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/stream", nil))
		if rec.Code != http.StatusUnauthorized || calls != 1 {
			t.Errorf("status = %d after %d guard calls, want %d after 1", rec.Code, calls, http.StatusUnauthorized)
		}
	})

	t.Run("an unconfigured access is a pass-through too", func(t *testing.T) {
		// Unreachable through a mount — ToolsMounted is false for it, so no
		// route exists to wrap — and defined anyway, because a wrapper that
		// panicked on nil would turn a configuration error into a crash in
		// whichever route U23 adds first.
		rec := httptest.NewRecorder()
		ToolsProtectMiddleware(HTTPConfig{})(http.HandlerFunc(reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/stream", nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
		}
	})
}

// TestToolsFeaturesDefaultToOn is the reference's four defaults
// (tools.router.ts:121-124) against Go's zero value, which is the whole reason
// the fields are spelled in the negative.
func TestToolsFeaturesDefaultToOn(t *testing.T) {
	if got := (ToolsOptions{}).Features(); got != (ToolsFeatures{true, true, true, true}) {
		t.Errorf("zero ToolsOptions Features() = %+v, want all four on", got)
	}
	off := ToolsOptions{DisableTelemetry: true, DisableNotify: true, DisableStream: true, DisableWebhook: true}
	if got := off.Features(); got != (ToolsFeatures{}) {
		t.Errorf("all four disabled Features() = %+v, want all four off", got)
	}
	one := ToolsOptions{DisableStream: true}.Features()
	if !one.Telemetry || !one.Notify || one.Stream || !one.Webhook {
		t.Errorf("DisableStream alone Features() = %+v, want only Stream off", one)
	}
}

func TestToolsDocsBasePath(t *testing.T) {
	for _, c := range []struct {
		name string
		opts ToolsOptions
		want string
	}{
		{"unset follows the mount", ToolsOptions{}, DefaultToolsPath},
		{"unset follows a configured mount", ToolsOptions{Path: "ops"}, "/ops"},
		{"set moves the description", ToolsOptions{Docs: DocsOptions{BasePath: "public/tools/"}}, "/public/tools"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := (HTTPConfig{Tools: c.opts}).ToolsDocsBasePath(); got != c.want {
				t.Errorf("ToolsDocsBasePath() = %q, want %q", got, c.want)
			}
		})
	}
}

// toolsTestConfig is a fully configured tools block, which is what
// ToolsHandler is built from.
func toolsTestConfig() HTTPConfig {
	cfg := DefaultHTTPConfig()
	cfg.Tools = ToolsOptions{Enabled: true, AuthTools: &AuthTools{Events: NewEventBus()}, Access: ToolsPublic()}
	cfg.Tools.Docs.Enabled = true
	return cfg
}

func TestToolsHandlerRoutes(t *testing.T) {
	cfg := toolsTestConfig()
	handler := (&Auth{}).ToolsHandler(cfg)

	serve := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}

	t.Run("the two documentation routes answer", func(t *testing.T) {
		for path, contentType := range map[string]string{
			DefaultToolsPath + DocsSpecPath: "application/json",
			DefaultToolsPath + DocsUIPath:   "text/html; charset=utf-8",
		} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := serve(method, path)
				if rec.Code != http.StatusOK {
					t.Errorf("%s %s = %d, want 200", method, path, rec.Code)
				}
				if got := rec.Header().Get("Content-Type"); got != contentType {
					t.Errorf("%s %s Content-Type = %q, want %q", method, path, got, contentType)
				}
			}
		}
	})

	t.Run("everything else is a 404", func(t *testing.T) {
		// The remaining feature routes are U23's and U25's, and the reference's
		// router has no layer on its own root either. GET /stream is not here
		// any more: U24 mounts it, and tools_stream_test.go is where it answers.
		for _, path := range []string{
			DefaultToolsPath,
			DefaultToolsPath + "/",
			DefaultToolsPath + ToolsTrackPath + "/identity.probe",
			DefaultToolsPath + ToolsNotifyPath + "/global",
			DefaultToolsPath + ToolsTelemetryPath,
			DefaultToolsPath + ToolsWebhookPath + "/probe",
		} {
			if rec := serve(http.MethodGet, path); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", path, rec.Code)
			}
		}
	})

	t.Run("the documentation routes are read-only", func(t *testing.T) {
		for _, path := range []string{DefaultToolsPath + DocsSpecPath, DefaultToolsPath + DocsUIPath} {
			if rec := serve(http.MethodPost, path); rec.Code != http.StatusNotFound {
				t.Errorf("POST %s = %d, want 404", path, rec.Code)
			}
		}
	})

	t.Run("without Docs.Enabled neither is served", func(t *testing.T) {
		bare := toolsTestConfig()
		bare.Tools.Docs.Enabled = false
		handler := (&Auth{}).ToolsHandler(bare)
		for _, path := range []string{DefaultToolsPath + DocsSpecPath, DefaultToolsPath + DocsUIPath} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", path, rec.Code)
			}
		}
	})
}

// TestToolsSwaggerPageIsTheAuthRouterPage pins the quirk the reference's one
// builder creates: buildSwaggerUiHtml serves its auth, admin and tools routers
// alike and titles all three "Tools API" (openapi.ts:1652, read at
// tools.router.ts:350 and auth.router.ts:1676). On this router the title is the
// only one of the three that is true, and the page is the same page — the two
// differ in the spec URL and nothing else.
func TestToolsSwaggerPageIsTheAuthRouterPage(t *testing.T) {
	cfg := toolsTestConfig()
	rec := httptest.NewRecorder()
	(&Auth{}).ToolsHandler(cfg).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DefaultToolsPath+DocsUIPath, nil))

	want := swaggerUIHTML(DefaultToolsPath + DocsSpecPath)
	if rec.Body.String() != want {
		t.Errorf("the tools page is not the reference's page:\n%s", rec.Body.String())
	}
	if !strings.Contains(want, "<title>awesome-node-auth Tools API — Swagger UI</title>") {
		t.Error("the page no longer carries the reference's title")
	}
}

func TestGenerateToolsOpenAPISpec(t *testing.T) {
	t.Run("the reference's info block", func(t *testing.T) {
		// openapi.ts:1628-1632, with the package name changed as the auth
		// generator changes it.
		document := GenerateToolsOpenAPISpec(ToolsOpenAPIInfo{})
		if got := document["openapi"]; got != "3.0.3" {
			t.Errorf("openapi = %v, want 3.0.3", got)
		}
		info := document["info"].(map[string]any)
		for field, want := range map[string]string{
			"title":       "awesome-go-auth Tools API",
			"version":     "1.0.0",
			"description": "Optional event-driven tools: telemetry, SSE notifications, and webhooks.",
		} {
			if got := info[field]; got != want {
				t.Errorf("info.%s = %v, want %q", field, got, want)
			}
		}
	})

	t.Run("the four schemas and the bearer scheme are always present", func(t *testing.T) {
		// The reference builds the components block whole and lets the flags
		// decide only which paths reference it (openapi.ts:1588-1619). They are
		// what the path items U23 through U25 add a $ref against, so they are
		// written once rather than one per PR.
		components := GenerateToolsOpenAPISpec(ToolsOpenAPIInfo{})["components"].(map[string]any)
		schemas := components["schemas"].(map[string]any)
		for _, name := range []string{"OkResponse", "TrackPayload", "NotifyPayload", "TelemetryEvent"} {
			if _, ok := schemas[name]; !ok {
				t.Errorf("components.schemas has no %q", name)
			}
		}
		if _, ok := components["securitySchemes"].(map[string]any)["BearerAuth"]; !ok {
			t.Error("components.securitySchemes has no BearerAuth (openapi.ts:1590-1596)")
		}
	})

	t.Run("the tags follow the four flags", func(t *testing.T) {
		// openapi.ts:1621-1625: Telemetry, Notifications for notify or stream,
		// Webhooks. A flag that is off drops its tag.
		names := func(info ToolsOpenAPIInfo) string {
			tags := GenerateToolsOpenAPISpec(info)["tags"].([]map[string]any)
			got := make([]string, 0, len(tags))
			for _, tag := range tags {
				got = append(got, tag["name"].(string))
			}
			return strings.Join(got, ",")
		}
		for _, c := range []struct {
			name string
			info ToolsOpenAPIInfo
			want string
		}{
			{"all four", ToolsOpenAPIInfo{Telemetry: true, Notify: true, Stream: true, Webhook: true}, "Telemetry,Notifications,Webhooks"},
			{"stream alone still names Notifications", ToolsOpenAPIInfo{Stream: true}, "Notifications"},
			{"notify alone still names Notifications", ToolsOpenAPIInfo{Notify: true}, "Notifications"},
			{"none", ToolsOpenAPIInfo{}, ""},
		} {
			if got := names(c.info); got != c.want {
				t.Errorf("%s: tags = %q, want %q", c.name, got, c.want)
			}
		}
	})

	t.Run("the documentation routes follow the base path", func(t *testing.T) {
		document := GenerateToolsOpenAPISpec(ToolsOpenAPIInfo{BasePath: "/public/tools", Docs: true})
		paths := document["paths"].(map[string]any)
		for _, path := range []string{"/public/tools" + DocsSpecPath, "/public/tools" + DocsUIPath} {
			if _, ok := paths[path]; !ok {
				t.Errorf("the document does not describe %q", path)
			}
		}
		if len(paths) != 2 {
			t.Errorf("paths = %v, want exactly the two documentation routes", paths)
		}
	})

	t.Run("without Docs the only feature route described is the stream", func(t *testing.T) {
		// U24 mounts GET <tools>/stream and adds its path item here beside the
		// switch case that mounts it; track, notify, the telemetry query and the
		// inbound webhook are still U23's and U25's. A path item written ahead
		// of its route would document an endpoint that answers 404, which is
		// what the conformance suite exists to catch.
		document := GenerateToolsOpenAPISpec(ToolsOpenAPIInfo{Telemetry: true, Notify: true, Stream: true, Webhook: true})
		paths := document["paths"].(map[string]any)
		if len(paths) != 1 {
			t.Errorf("paths = %v, want only the stream until U23 mounts its two", paths)
		}
		if _, ok := paths[DefaultToolsPath+ToolsStreamPath]; !ok {
			t.Errorf("the document does not describe %q (openapi.ts:1492-1522)", DefaultToolsPath+ToolsStreamPath)
		}
		if off := GenerateToolsOpenAPISpec(ToolsOpenAPIInfo{Telemetry: true, Notify: true, Webhook: true}); len(off["paths"].(map[string]any)) != 0 {
			t.Errorf("paths = %v with the stream flag off, want none", off["paths"])
		}
	})
}
