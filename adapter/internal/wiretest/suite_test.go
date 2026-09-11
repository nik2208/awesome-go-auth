package wiretest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// The OpenAPI harness is checked here against a fake conditional set, because
// no route the adapters mount today is conditional: conditionalRoutes is empty,
// so the adapter suites only ever walk the base path. The fake stands in for
// what a JWKS or docs set will be — a route the adapter serves only once
// configured, documented only by a spec generated with the matching flag —
// and the cases below pin the three things testOpenAPI promises for one: the
// configured comparison, the unconfigured 404, and the set's name in every
// failure.

// mountNetHTTP is the reference adapter. The harness is adapter-agnostic, so
// one is enough to drive it; chi delegates to these handlers anyway.
func mountNetHTTP(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
	mux := http.NewServeMux()
	nethttpadapter.MountWithConfig(mux, a, cfg)
	return mux
}

const (
	fakeSetName = "fake"
	fakeRoute   = "/fake/{id}"
	// fakeSpecTitle is the OpenAPIInfo "flag" the fake set's spec() raises. The
	// generator below adds fakeRoute to the paths when it sees it, the way a
	// real flag will make GenerateOpenAPISpec add a real set's paths.
	fakeSpecTitle = "with-fake-set"
)

// withFakeRoute wraps a Mounter so the handler also serves GET <prefix>/fake/{id}.
// It is what a real set's configure hook must never do — the route has to come
// from the adapter — but for the harness's own test it is the whole point.
func withFakeRoute(inner Mounter) Mounter {
	return func(t *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("GET "+cfg.Prefix()+"/fake/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.Handle("/", inner(t, a, cfg))
		return mux
	}
}

// generateWithFake is GenerateOpenAPISpec plus the routes in extra whenever the
// info carries the fake flag.
func generateWithFake(extra ...string) func(auth.OpenAPIInfo) map[string]any {
	return func(info auth.OpenAPIInfo) map[string]any {
		spec := auth.GenerateOpenAPISpec(info)
		if info.Title != fakeSpecTitle {
			return spec
		}
		prefix := auth.HTTPConfig{APIPrefix: info.APIPrefix}.Prefix()
		paths := spec["paths"].(map[string]any)
		for _, route := range append([]string{fakeRoute}, extra...) {
			paths[prefix+route] = map[string]any{"get": map[string]any{"summary": "fake"}}
		}
		return spec
	}
}

// fakeRemovedRoute is the base route the subtractive fake set unmounts. It is
// the OpenAPI probe of a real documented operation, so the harness is exercised
// against the same machinery a real removal uses.
const fakeRemovedRoute = "/add-phone"

// generateWithoutFakeRemoved is GenerateOpenAPISpec minus fakeRemovedRoute
// whenever the info carries the fake flag — a stand-in for what
// OpenAPIInfo.ResourceServer does to the real spec.
func generateWithoutFakeRemoved(info auth.OpenAPIInfo) map[string]any {
	spec := auth.GenerateOpenAPISpec(info)
	if info.Title != fakeSpecTitle {
		return spec
	}
	prefix := auth.HTTPConfig{APIPrefix: info.APIPrefix}.Prefix()
	delete(spec["paths"].(map[string]any), prefix+fakeRemovedRoute)
	return spec
}

// withoutRoute wraps a Mounter so the handler answers 404 for one path, which
// is what an adapter that never registered it does.
func withoutRoute(inner Mounter, route string) Mounter {
	return func(t *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
		h := inner(t, a, cfg)
		gone := cfg.Prefix() + route
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == gone {
				http.NotFound(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

// fakeRemovalSet is a well-formed subtractive set: configured, the mount stops
// serving fakeRemovedRoute and the flagged spec stops documenting it.
func fakeRemovalSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      fakeSetName,
		configure: func(pc *probeConfig) { pc.Mount = withoutRoute(pc.Mount, fakeRemovedRoute) },
		removes:   map[string]string{fakeRemovedRoute: http.MethodPost},
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{Title: fakeSpecTitle} },
	}
}

// fakeSet is a well-formed conditional set: configured, the mount serves
// fakeRoute and the flagged spec documents it; unconfigured, neither does.
func fakeSet() conditionalRouteSet {
	return conditionalRouteSet{
		name:      fakeSetName,
		configure: func(pc *probeConfig) { pc.Mount = withFakeRoute(pc.Mount) },
		routes:    map[string]string{fakeRoute: http.MethodGet},
		spec:      func() auth.OpenAPIInfo { return auth.OpenAPIInfo{Title: fakeSpecTitle} },
	}
}

// recorder collects what the harness would have reported to testing.T.
type recorder struct{ failures []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorder) dump() string { return strings.Join(r.failures, "\n") }

// TestOpenAPIHarnessBase pins that an empty registry is the base comparison
// alone: the adapter suites run exactly this, so it must report nothing.
func TestOpenAPIHarnessBase(t *testing.T) {
	rec := &recorder{}
	runOpenAPI(t, openAPIHarness{mount: mountNetHTTP, generate: auth.GenerateOpenAPISpec, report: rec})
	if len(rec.failures) != 0 {
		t.Fatalf("the base configuration must pass with no sets registered, got:\n%s", rec.dump())
	}
}

// TestOpenAPIHarnessConditionalSet is the positive case: a set whose configure
// mounts its routes and whose spec flag documents them passes in full, under
// both prefixes, and its routes are absent from the base env.
func TestOpenAPIHarnessConditionalSet(t *testing.T) {
	rec := &recorder{}
	runOpenAPI(t, openAPIHarness{
		mount:    mountNetHTTP,
		sets:     []conditionalRouteSet{fakeSet()},
		generate: generateWithFake(),
		report:   rec,
	})
	if len(rec.failures) != 0 {
		t.Fatalf("a well-formed conditional set must pass, got:\n%s", rec.dump())
	}
}

// TestOpenAPIHarnessSubtractiveSet is the positive case for the other
// direction: a set whose configure unmounts a base route and whose spec flag
// stops documenting it passes in full. Resource-server mode is exactly this
// shape, so the harness has to be right about it before the real set is
// trusted.
func TestOpenAPIHarnessSubtractiveSet(t *testing.T) {
	rec := &recorder{}
	runOpenAPI(t, openAPIHarness{
		mount:    mountNetHTTP,
		sets:     []conditionalRouteSet{fakeRemovalSet()},
		generate: generateWithoutFakeRemoved,
		report:   rec,
	})
	if len(rec.failures) != 0 {
		t.Fatalf("a well-formed subtractive set must pass, got:\n%s", rec.dump())
	}
}

// TestOpenAPIHarnessConditionalSetFailures is every way a set can be wrong,
// each answered by a failure that names the set. The counts are exact: a
// broken set must produce its own failure and nothing else, or a real
// registration mistake would surface as a wall of unrelated route errors.
func TestOpenAPIHarnessConditionalSetFailures(t *testing.T) {
	prefixes := len(openAPIPrefixes)
	cases := []struct {
		name     string
		mount    Mounter
		sets     func() []conditionalRouteSet
		generate func(auth.OpenAPIInfo) map[string]any
		// want are substrings each of which must appear in some failure.
		want []string
		// count is the exact number of failures expected.
		count int
	}{
		{
			name: "a route reachable without the set is flagged as unconditional",
			// The adapter serves the route whether or not the set is configured.
			mount:    withFakeRoute(mountNetHTTP),
			sets:     func() []conditionalRouteSet { return []conditionalRouteSet{fakeSet()} },
			generate: generateWithFake(),
			want:     []string{`GET /auth/fake/probe of conditional set "fake" is reachable (200) without the set configured`},
			count:    prefixes,
		},
		{
			name:  "a set route the flagged spec does not document",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeSet()
				set.spec = func() auth.OpenAPIInfo { return auth.OpenAPIInfo{} }
				return []conditionalRouteSet{set}
			},
			generate: generateWithFake(),
			want:     []string{`route "/fake/{id}" is mounted but missing from the spec (conditional set "fake")`},
			count:    prefixes,
		},
		{
			name:  "a documented set route the configure hook does not mount",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeSet()
				set.configure = func(*probeConfig) {}
				return []conditionalRouteSet{set}
			},
			generate: generateWithFake(),
			want:     []string{`GET /auth/fake/probe is documented but not mounted (404) (conditional set "fake")`},
			count:    prefixes,
		},
		{
			name:     "the flagged spec documents a route the set does not declare",
			mount:    mountNetHTTP,
			sets:     func() []conditionalRouteSet { return []conditionalRouteSet{fakeSet()} },
			generate: generateWithFake("/fake-extra"),
			want: []string{
				`spec documents "/fake-extra", which is not in documentedRoutes or conditional set "fake"`,
				`GET /auth/fake-extra is documented but not mounted (404) (conditional set "fake")`,
			},
			count: 2 * prefixes,
		},
		{
			name:  "a set that changes the mount prefix",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeSet()
				set.configure = func(pc *probeConfig) { pc.HTTP.APIPrefix = "/elsewhere" }
				return []conditionalRouteSet{set}
			},
			generate: generateWithFake(),
			want:     []string{`conditional set "fake" changed the mount prefix to "/elsewhere", want "/auth"`},
			count:    prefixes,
		},
		{
			name:  "a set that redeclares a base route",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeSet()
				set.routes = map[string]string{"/login": http.MethodPost}
				return []conditionalRouteSet{set}
			},
			generate: generateWithFake(),
			want:     []string{`conditional set "fake" redeclares "/login", which is already in documentedRoutes`},
			count:    1,
		},
		{
			name:  "a set with no routes",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeSet()
				set.routes = nil
				return []conditionalRouteSet{set}
			},
			generate: generateWithFake(),
			want:     []string{`conditional set "fake" declares no routes`},
			count:    1,
		},
		{
			name: "a removed route the adapter still serves",
			// The configure hook does not unmount anything, so the base route
			// is still there while the set says it is gone.
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeRemovalSet()
				set.configure = func(*probeConfig) {}
				return []conditionalRouteSet{set}
			},
			generate: generateWithoutFakeRemoved,
			want: []string{
				`POST /auth/add-phone is still reachable`,
			},
			count: prefixes,
		},
		{
			name:  "a removed route the flagged spec still documents",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				return []conditionalRouteSet{fakeRemovalSet()}
			},
			// The unmodified generator keeps documenting the removed route.
			generate: auth.GenerateOpenAPISpec,
			want: []string{
				`spec documents "/add-phone", which is not in documentedRoutes or conditional set "fake"`,
				`POST /auth/add-phone is documented but not mounted (404) (conditional set "fake")`,
			},
			count: 2 * prefixes,
		},
		{
			name:  "a set removing a route the base set does not have",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeRemovalSet()
				set.removes = map[string]string{"/not-a-route": http.MethodGet}
				return []conditionalRouteSet{set}
			},
			generate: generateWithoutFakeRemoved,
			want:     []string{`conditional set "fake" removes "/not-a-route", which is not in documentedRoutes`},
			count:    1,
		},
		{
			name:  "a set removing a route under the wrong method",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeRemovalSet()
				set.removes = map[string]string{fakeRemovedRoute: http.MethodGet}
				return []conditionalRouteSet{set}
			},
			generate: generateWithoutFakeRemoved,
			want:     []string{`conditional set "fake" removes "/add-phone" as GET, but documentedRoutes has it as POST`},
			count:    1,
		},
		{
			name:  "a set that both adds and removes a route",
			mount: mountNetHTTP,
			sets: func() []conditionalRouteSet {
				set := fakeRemovalSet()
				set.routes = map[string]string{fakeRemovedRoute: http.MethodPost}
				return []conditionalRouteSet{set}
			},
			generate: generateWithoutFakeRemoved,
			want: []string{
				`conditional set "fake" both adds and removes "/add-phone"`,
				`conditional set "fake" redeclares "/add-phone", which is already in documentedRoutes`,
			},
			count: 2,
		},
		{
			name:     "a set registered twice",
			mount:    mountNetHTTP,
			sets:     func() []conditionalRouteSet { return []conditionalRouteSet{fakeSet(), fakeSet()} },
			generate: generateWithFake(),
			want:     []string{`conditional set "fake" is registered twice`},
			count:    1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			runOpenAPI(t, openAPIHarness{mount: tc.mount, sets: tc.sets(), generate: tc.generate, report: rec})

			if len(rec.failures) != tc.count {
				t.Errorf("got %d failures, want %d:\n%s", len(rec.failures), tc.count, rec.dump())
			}
			for _, want := range tc.want {
				found := false
				for _, failure := range rec.failures {
					if strings.Contains(failure, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no failure contains %q, got:\n%s", want, rec.dump())
				}
			}
			// The set is named in every failure, so a registry with several sets
			// points at the one that is wrong.
			for _, failure := range rec.failures {
				if !strings.Contains(failure, `"`+fakeSetName+`"`) {
					t.Errorf("failure does not name the set: %s", failure)
				}
			}
		})
	}
}
