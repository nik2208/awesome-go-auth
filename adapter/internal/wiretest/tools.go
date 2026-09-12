package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
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
// U23 attached two more: POST <tools>/track/{eventName} and
// POST <tools>/notify/{target}, the first pair to share that posture. What the
// cases for them assert is what a route can get wrong that the facade cannot:
// which request reaches a handler at all, what the handler read off the request,
// and what it answered. The fan-out itself is auth_tools_test.go's, so these
// read one telemetry record and one broadcast rather than four sinks. Two of
// them carry a deviation apiece —
// tools-track-ip-comes-from-the-configured-seam is
// "the client address is the configured seam, not X-Forwarded-For", and
// tools-request-bodies-are-typed is "a body that will not decode is refused".
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
// from the document agrees with whatever the document happens to say. U22
// mounted the two documentation routes, U23 the two POST routes and U24 the
// stream; U25 adds /telemetry and /webhook/{provider}.
var toolsDocumentedRoutes = map[string]string{
	auth.DocsSpecPath:                    http.MethodGet,
	auth.DocsUIPath:                      http.MethodGet,
	auth.ToolsTrackPath + "/{eventName}": http.MethodPost,
	auth.ToolsNotifyPath + "/{target}":   http.MethodPost,
	auth.ToolsStreamPath:                 http.MethodGet,
}

// toolsFeatureRoutes are the feature routes of the reference's router that are
// not mounted yet. Every case that probes "not mounted" walks these as well as
// the documented ones, so a route cannot arrive without the PR that owns it
// noticing this list — U24 moved /stream out of here and into
// toolsDocumentedRoutes and U23 moved track and notify, which is what mounting
// one of these looks like.
var toolsFeatureRoutes = []string{
	auth.ToolsTelemetryPath,
	auth.ToolsWebhookPath + "/probe",
}

// toolsDocsRoutes are the two documentation routes alone: the subset of
// toolsDocumentedRoutes that is GET, carries no guard, and is switched by
// Tools.Docs rather than by one of the four feature flags.
var toolsDocsRoutes = []string{auth.DocsSpecPath, auth.DocsUIPath}

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
// credential and no CSRF pair: the routes mounted so far are either unguarded
// or behind whatever guard the case configured, and the tools router carries
// none of the auth router's middleware either.
func toolsRequest(env *Env, method, path string) *http.Request {
	return httptest.NewRequest(method, env.Config.ToolsPath()+toolsProbePath(path), nil)
}

// toolsPost builds a POST below the tools mount carrying a JSON body, which is
// what the two feature routes take.
func toolsPost(env *Env, path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, env.Config.ToolsPath()+toolsProbePath(path), stringReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// toolsProbePath fills a documented path template with a segment every router
// will route, the way openAPIProbe does for the auth document. A path with no
// parameter comes back unchanged.
func toolsProbePath(path string) string {
	return openAPIPathParam.ReplaceAllString(path, openAPIProbeSegment)
}

// toolsRecorder is a facade whose sinks can be read back: a memory telemetry
// store for what Track persisted, and an SSE distributor for what Track and
// Notify broadcast. Both are the ordinary seams rather than a double for the
// facade — what these cases are about is what the two routes hand it.
type toolsRecorder struct {
	tools     *auth.AuthTools
	telemetry *auth.MemoryTelemetryStore

	mu     sync.Mutex
	topics []string
	frames []auth.StreamEvent
}

// Publish and Subscribe make this an auth.SseDistributor. With a distributor
// configured Broadcast publishes and does not also deliver locally, so every
// broadcast either route causes arrives here exactly once.
func (r *toolsRecorder) Publish(_ context.Context, topic string, ev auth.StreamEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.topics = append(r.topics, topic)
	r.frames = append(r.frames, ev)
	return nil
}

func (r *toolsRecorder) Subscribe(context.Context, func(string, auth.StreamEvent)) error { return nil }

// broadcasts is the topics broadcast to and the frames sent, in order.
func (r *toolsRecorder) broadcasts() ([]string, []auth.StreamEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.topics...), append([]auth.StreamEvent(nil), r.frames...)
}

// tracked is the telemetry records Track persisted, in order.
func (r *toolsRecorder) tracked(t *testing.T) []auth.TelemetryEvent {
	t.Helper()
	events, err := r.telemetry.Query(context.Background(), auth.TelemetryFilter{})
	if err != nil {
		t.Fatalf("telemetry query: %v", err)
	}
	return events
}

// onlyTracked is the single record a case expects, or a failure naming how many
// there actually were.
func (r *toolsRecorder) onlyTracked(t *testing.T) auth.TelemetryEvent {
	t.Helper()
	events := r.tracked(t)
	if len(events) != 1 {
		t.Fatalf("telemetry records = %d, want exactly 1", len(events))
	}
	return events[0]
}

// toolsRecordingConfig is toolsConfig with a facade whose sinks are readable.
// The override goes in ahead of the caller's edits, so a case that wants some
// other facade can still say so.
func toolsRecordingConfig(t *testing.T, opts ...func(*auth.ToolsOptions)) (auth.HTTPConfig, *toolsRecorder) {
	t.Helper()
	rec := &toolsRecorder{telemetry: auth.NewMemoryTelemetryStore()}
	tools, err := auth.NewAuthTools(context.Background(), auth.NewEventBus(), auth.AuthToolsOptions{
		Telemetry:  rec.telemetry,
		SSE:        true,
		SSEOptions: []auth.SseOption{auth.WithSseDistributor(rec)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	rec.tools = tools
	edits := append([]func(*auth.ToolsOptions){func(o *auth.ToolsOptions) { o.AuthTools = tools }}, opts...)
	return toolsConfig(t, edits...), rec
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
	// Each documented route on its own method as well as on GET: from U23 the set
	// holds POST routes, and a POST route probed only with GET answers 404
	// whether or not it is mounted, which would make this assertion pass on a
	// configuration that had in fact mounted it.
	for path, method := range toolsDocumentedRoutes {
		for _, probe := range []string{http.MethodGet, method} {
			assertToolsUnrouted(t, env.Do(toolsRequest(env, probe, path)))
		}
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

	t.Run("the remaining feature groups are not mounted yet", func(t *testing.T) {
		// The telemetry query and the inbound webhook are U25's. This case is
		// U22's stop-point — the PR that mounts one of these replaces its entry
		// in toolsFeatureRoutes with real assertions, the way U23 did for track
		// and notify and U24 for the stream, so a route cannot arrive without
		// this list being edited.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, path := range toolsFeatureRoutes {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				assertToolsUnrouted(t, env.Do(toolsRequest(env, method, path)))
			}
		}
	})

	t.Run("POST <tools>/track/{eventName} tracks the event", func(t *testing.T) {
		// tools.router.ts:141-159. The event name is the path parameter, the
		// five identifiers come off the body, and the answer is 202 {"ok":true}
		// whatever the four sinks did — track is awaited there and its result
		// is discarded (:156-163).
		cfg, rec := toolsRecordingConfig(t)
		env := NewEnv(t, mount, cfg)

		req := toolsPost(env, auth.ToolsTrackPath+"/identity.probe",
			`{"data":{"k":"v"},"userId":"u1","tenantId":"acme","sessionId":"s1","correlationId":"c1"}`)
		req.Header.Set("User-Agent", "probe/1.0")
		got := env.Do(req)

		AssertStatus(t, got, http.StatusAccepted)
		if body := Body(t, got); body["ok"] != true {
			t.Errorf("body = %v, want {\"ok\": true} (tools.router.ts:158)", body)
		}

		event := rec.onlyTracked(t)
		for _, f := range []struct{ name, got, want string }{
			{"EventName", event.EventName, "identity.probe"},
			{"UserID", event.UserID, "u1"},
			{"TenantID", event.TenantID, "acme"},
			{"SessionID", event.SessionID, "s1"},
			{"CorrelationID", event.CorrelationID, "c1"},
			{"UserAgent", event.UserAgent, "probe/1.0"},
		} {
			if f.got != f.want {
				t.Errorf("record.%s = %q, want %q", f.name, f.got, f.want)
			}
		}
		if event.Meta["k"] != "v" {
			t.Errorf("record.Meta = %v, want the body's data", event.Meta)
		}
		// And the event reached the stream as well as the store, which is what
		// makes this the facade's Track and not a store write: no tenant, user
		// or session topic is asserted here — EventTopics is auth_tools_test's.
		topics, _ := rec.broadcasts()
		if len(topics) == 0 {
			t.Error("the tracked event reached no SSE topic (auth-tools.ts:233-246)")
		}
	})

	t.Run("the client address is the configured seam, not X-Forwarded-For", func(t *testing.T) {
		// tools-track-ip-comes-from-the-configured-seam. The reference's route
		// reads the left-most element of X-Forwarded-For and falls back to the
		// socket (tools.router.ts:144); this port reads HTTPConfig.ClientIP,
		// whose default is the socket peer, so that one binary does not hold two
		// address rules and a host's trust configuration is not overridden by
		// one route.
		t.Run("the default is the socket peer", func(t *testing.T) {
			cfg, rec := toolsRecordingConfig(t)
			env := NewEnv(t, mount, cfg)
			req := toolsPost(env, auth.ToolsTrackPath+"/identity.probe", `{}`)
			req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.4")
			AssertStatus(t, env.Do(req), http.StatusAccepted)

			ip := rec.onlyTracked(t).IP
			if strings.Contains(ip, "203.0.113.9") {
				t.Errorf("record.IP = %q, which is the caller's X-Forwarded-For: the header must be "+
					"read nowhere, or a caller chooses the address in the telemetry store", ip)
			}
			if ip == "" {
				t.Error("record.IP is empty, want the socket peer with its port stripped")
			}
		})

		t.Run("a configured ClientIP is authoritative", func(t *testing.T) {
			cfg, rec := toolsRecordingConfig(t)
			cfg.ClientIP = func(*http.Request) string { return "198.51.100.7" }
			env := NewEnv(t, mount, cfg)
			req := toolsPost(env, auth.ToolsTrackPath+"/identity.probe", `{}`)
			req.Header.Set("X-Forwarded-For", "203.0.113.9")
			AssertStatus(t, env.Do(req), http.StatusAccepted)

			if ip := rec.onlyTracked(t).IP; ip != "198.51.100.7" {
				t.Errorf("record.IP = %q, want the value HTTPConfig.ClientIP returned: a deployment "+
					"that has stated which hop it trusts must not be overridden by this route", ip)
			}
		})
	})

	t.Run("the user id falls back to the authenticated principal", func(t *testing.T) {
		// `userId ?? req.user?.id ?? req.user?.sub` (tools.router.ts:147). The
		// principal is whatever the configured guard put on the context, which
		// for a host passing its adapter's Middleware is the authenticated user.
		principal := func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := auth.ContextWithUser(r.Context(), auth.User{ID: "from-the-guard"})
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			})
		}
		for _, c := range []struct{ name, body, want string }{
			{"no userId in the body", `{}`, "from-the-guard"},
			{"a userId in the body wins", `{"userId":"u9"}`, "u9"},
			// "" is not nullish, so it wins there too — which is why the field
			// is decoded into a pointer rather than a string.
			{"an explicit empty userId wins", `{"userId":""}`, ""},
		} {
			t.Run(c.name, func(t *testing.T) {
				cfg, rec := toolsRecordingConfig(t, principal)
				env := NewEnv(t, mount, cfg)
				AssertStatus(t, env.Do(toolsPost(env, auth.ToolsTrackPath+"/identity.probe", c.body)), http.StatusAccepted)
				if got := rec.onlyTracked(t).UserID; got != c.want {
					t.Errorf("record.UserID = %q, want %q", got, c.want)
				}
			})
		}
	})

	t.Run("POST <tools>/notify/{target} broadcasts to that topic alone", func(t *testing.T) {
		// tools.router.ts:166-178. The target is the path parameter, decoded —
		// `user:123` is the document's own example (openapi.ts:1470) — and the
		// four options come off the body.
		cfg, rec := toolsRecordingConfig(t)
		env := NewEnv(t, mount, cfg)

		got := env.Do(toolsPost(env, auth.ToolsNotifyPath+"/user%3A123",
			`{"data":{"m":1},"type":"alert","tenantId":"acme","userId":"u1","metadata":{"x":true}}`))

		AssertStatus(t, got, http.StatusAccepted)
		if body := Body(t, got); body["ok"] != true {
			t.Errorf("body = %v, want {\"ok\": true} (tools.router.ts:177)", body)
		}

		topics, frames := rec.broadcasts()
		if len(topics) != 1 || topics[0] != "user:123" {
			t.Fatalf("broadcast topics = %v, want exactly [user:123]: notify addresses the topic it "+
				"is given and does not fan out across EventTopics", topics)
		}
		frame := frames[0]
		if frame.Type != "alert" || frame.TenantID != "acme" || frame.UserID != "u1" {
			t.Errorf("frame = %+v, want type alert for acme/u1", frame)
		}
		if frame.Metadata["x"] != true {
			t.Errorf("frame.Metadata = %v, want the body's metadata", frame.Metadata)
		}
		// Nothing was persisted: notify is not track, and the telemetry store
		// is not one of the channels it reaches.
		if events := rec.tracked(t); len(events) != 0 {
			t.Errorf("notify wrote %d telemetry records, want 0", len(events))
		}
	})

	t.Run("notify reaches the SSE channel and only that one", func(t *testing.T) {
		// The route destructures data, type, tenantId, userId and metadata
		// (tools.router.ts:168) and passes those four options (:171-176). It
		// never reads `channels`, so NotifyOptions.Channels falls to its default
		// ['sse'] on every request and the email and SMS channels of the facade
		// are unreachable over HTTP — the quirk, and the safer shape.
		cfg, rec := toolsRecordingConfig(t)
		env := NewEnv(t, mount, cfg)
		AssertStatus(t, env.Do(toolsPost(env, auth.ToolsNotifyPath+"/global",
			`{"data":"hello","channels":["email","sms"],"userId":"u1"}`)), http.StatusAccepted)

		topics, frames := rec.broadcasts()
		if len(topics) != 1 || topics[0] != "global" {
			t.Fatalf("broadcast topics = %v, want exactly [global]", topics)
		}
		// And the default type, which Notify resolves rather than the route
		// (auth-tools.ts:298).
		if frames[0].Type != "notification" {
			t.Errorf("frame.Type = %q, want %q", frames[0].Type, "notification")
		}
		if frames[0].Data != "hello" {
			t.Errorf("frame.Data = %v, want the body's data: notify's payload is not narrowed to an object", frames[0].Data)
		}
	})

	t.Run("both routes go behind the configured guard", func(t *testing.T) {
		// The reference spreads ...protect onto both (tools.router.ts:141,
		// :166). A guard that refuses must stop the call before the facade sees
		// it — a route that fanned out first and then refused would have sent
		// the webhooks already.
		refused := 0
		cfg, rec := toolsRecordingConfig(t, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					refused++
					w.WriteHeader(http.StatusForbidden)
				})
			})
		})
		env := NewEnv(t, mount, cfg)

		for _, path := range []string{auth.ToolsTrackPath + "/identity.probe", auth.ToolsNotifyPath + "/global"} {
			AssertStatus(t, env.Do(toolsPost(env, path, `{"data":{"k":"v"}}`)), http.StatusForbidden)
		}
		if refused != 2 {
			t.Errorf("the guard ran %d times, want 2", refused)
		}
		if events := rec.tracked(t); len(events) != 0 {
			t.Errorf("a refused call still tracked %d events", len(events))
		}
		if topics, _ := rec.broadcasts(); len(topics) != 0 {
			t.Errorf("a refused call still broadcast to %v", topics)
		}
	})

	t.Run("a body that will not decode is refused", func(t *testing.T) {
		// tools-request-bodies-are-typed. The reference casts and cannot fail —
		// `{"data": 42}` is tracked as 42 there, where Track takes a
		// map[string]any here. The envelope is this router's own, a bare
		// {"error": ...} (tools.router.ts:194, :230, :323), and nothing is
		// handed to the facade.
		cfg, rec := toolsRecordingConfig(t)
		env := NewEnv(t, mount, cfg)
		for _, c := range []struct{ path, body string }{
			{auth.ToolsTrackPath + "/identity.probe", `{`},
			{auth.ToolsTrackPath + "/identity.probe", `{"data": 42}`},
			{auth.ToolsTrackPath + "/identity.probe", `{"tenantId": 7}`},
			{auth.ToolsNotifyPath + "/global", `{"metadata": "not-an-object"}`},
		} {
			got := env.Do(toolsPost(env, c.path, c.body))
			AssertStatus(t, got, http.StatusBadRequest)
			body := Body(t, got)
			if _, ok := body["error"].(string); !ok || len(body) != 1 {
				t.Errorf("POST %s with %s answered %v, want a bare {\"error\": ...}", c.path, c.body, body)
			}
		}
		if events := rec.tracked(t); len(events) != 0 {
			t.Errorf("a refused body still tracked %d events", len(events))
		}
		if topics, _ := rec.broadcasts(); len(topics) != 0 {
			t.Errorf("a refused body still broadcast to %v", topics)
		}
	})

	t.Run("a bodyless call is accepted", func(t *testing.T) {
		// express.json leaves req.body = {} and both handlers read undefined off
		// it, so neither requires a body — which is why track's requestBody is
		// documented `required: false` (openapi.ts:1400-1401).
		cfg, rec := toolsRecordingConfig(t)
		env := NewEnv(t, mount, cfg)
		for _, path := range []string{auth.ToolsTrackPath + "/identity.probe", auth.ToolsNotifyPath + "/global"} {
			AssertStatus(t, env.Do(toolsRequest(env, http.MethodPost, path)), http.StatusAccepted)
		}
		if event := rec.onlyTracked(t); event.EventName != "identity.probe" || len(event.Meta) != 0 {
			t.Errorf("record = %+v, want identity.probe with no payload", event)
		}
	})

	t.Run("a feature flag unmounts its own route and no other", func(t *testing.T) {
		// `if (telemetry)` and `if (notify)` (tools.router.ts:140, :165): the
		// route is not registered at all, so what answers is the router's 404
		// and not a handler's refusal — and the document stops describing it.
		for _, c := range []struct {
			name string
			edit func(*auth.ToolsOptions)
			gone string
			kept string
		}{
			{"telemetry off", func(o *auth.ToolsOptions) { o.DisableTelemetry = true },
				auth.ToolsTrackPath + "/{eventName}", auth.ToolsNotifyPath + "/{target}"},
			{"notify off", func(o *auth.ToolsOptions) { o.DisableNotify = true },
				auth.ToolsNotifyPath + "/{target}", auth.ToolsTrackPath + "/{eventName}"},
		} {
			t.Run(c.name, func(t *testing.T) {
				env := NewEnv(t, mount, toolsConfig(t, c.edit))
				assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodPost, c.gone)))
				AssertStatus(t, env.Do(toolsRequest(env, http.MethodPost, c.kept)), http.StatusAccepted)

				paths := toolsDocumentPaths(t, toolsDocument(t, env))
				base := env.Config.ToolsPath()
				if _, ok := paths[base+c.gone]; ok {
					t.Errorf("the document still describes %q with its flag off", base+c.gone)
				}
				if _, ok := paths[base+c.kept]; !ok {
					t.Errorf("the document no longer describes %q", base+c.kept)
				}
			})
		}
	})

	t.Run("the two feature routes are POST only, with one segment", func(t *testing.T) {
		// Express's :param captures a single segment and router.post registers
		// POST alone, so every shape below matches no layer and ends at the
		// router's 404 — ahead of the guard, which is why an unauthenticated
		// caller is told 404 rather than 401.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, prefix := range []string{auth.ToolsTrackPath, auth.ToolsNotifyPath} {
			for _, c := range []struct{ method, path string }{
				{http.MethodGet, prefix + "/probe"},
				{http.MethodPut, prefix + "/probe"},
				{http.MethodDelete, prefix + "/probe"},
				{http.MethodPost, prefix},
				{http.MethodPost, prefix + "/"},
				{http.MethodPost, prefix + "/a/b"},
			} {
				t.Run(c.method+" "+c.path, func(t *testing.T) {
					assertToolsUnrouted(t, env.Do(toolsRequest(env, c.method, c.path)))
				})
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
		// The two by name rather than every documented route: from U24 on
		// toolsDocumentedRoutes also holds feature routes, which this option
		// does not touch.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.Docs.Enabled = false }))
		for _, path := range toolsDocsRoutes {
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
		for _, path := range toolsDocsRoutes {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				t.Run(method+" "+path, func(t *testing.T) {
					assertToolsUnrouted(t, env.Do(toolsRequest(env, method, path)))
				})
			}
		}
	})

	// GET <tools>/stream, the first feature route to be mounted, in its own
	// file: an SSE route cannot be asserted on through Env.Do, which only
	// returns once the handler does — and this one does not return until the
	// connection ends.
	t.Run("Stream", func(t *testing.T) { testToolsStream(t, mount) })

	t.Run("the bare mount is a 404", func(t *testing.T) {
		// The reference's router has no layer on '/', so GET /tools itself ends
		// at the router 404 — the mount exists to be a prefix.
		env := NewEnv(t, mount, toolsConfig(t))
		assertToolsUnrouted(t, env.Do(httptest.NewRequest(http.MethodGet, env.Config.ToolsPath(), nil)))
	})
}
