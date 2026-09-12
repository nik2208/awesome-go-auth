package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// These cases pin the half of the carrier that lives in this package: the
// header reads, the address resolution and the two context functions. The other
// half — that all four adapters actually install it, and install it outermost —
// is in the shared wire suite, because it is a property of the adapters and
// asserting it here would leave three of them untested.

func TestEventContextFromRequestReadsTheThreeFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set(CorrelationIDHeader, "corr-1")
	req.Header.Set("User-Agent", "family-client/1.9.0")

	got := EventContextFromRequest(req, DefaultHTTPConfig())
	if got.CorrelationID != "corr-1" {
		t.Errorf("CorrelationID = %q, want %q", got.CorrelationID, "corr-1")
	}
	if got.UserAgent != "family-client/1.9.0" {
		t.Errorf("UserAgent = %q, want the User-Agent value", got.UserAgent)
	}
	if got.IP != "192.0.2.1" {
		t.Errorf("IP = %q, want the socket peer with its port stripped", got.IP)
	}
}

// Header lookup is case-insensitive on both sides. Express lowercases its keys
// and indexes with 'x-correlation-id'; Go canonicalises. A client sending any
// casing must be read identically, or the two implementations disagree on a
// request neither considers unusual.
func TestEventContextHeaderLookupIsCaseInsensitive(t *testing.T) {
	for _, spelling := range []string{"X-Correlation-Id", "x-correlation-id", "X-CORRELATION-ID"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header[http.CanonicalHeaderKey(spelling)] = []string{"corr-case"}
		if got := EventContextFromRequest(req, DefaultHTTPConfig()).CorrelationID; got != "corr-case" {
			t.Errorf("%s: CorrelationID = %q, want %q", spelling, got, "corr-case")
		}
	}
}

// `Array.isArray(h) ? h[0] : h` (node-auth auth.router.ts:407-408, :409-410).
func TestEventContextRepeatedHeaderTakesTheFirstValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Add(CorrelationIDHeader, "first")
	req.Header.Add(CorrelationIDHeader, "second")
	req.Header.Del("User-Agent")
	req.Header.Add("User-Agent", "ua-first")
	req.Header.Add("User-Agent", "ua-second")

	got := EventContextFromRequest(req, DefaultHTTPConfig())
	if got.CorrelationID != "first" {
		t.Errorf("CorrelationID = %q, want %q", got.CorrelationID, "first")
	}
	if got.UserAgent != "ua-first" {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, "ua-first")
	}
}

// No id is minted for a request that sent none: the reference does not
// (node-auth auth.router.ts:407-408, :412), and an invented one would be
// indistinguishable from a caller's own.
func TestEventContextDoesNotInventACorrelationID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Del("User-Agent")

	got := EventContextFromRequest(req, DefaultHTTPConfig())
	if got.CorrelationID != "" {
		t.Errorf("CorrelationID = %q for a request that sent none, want empty", got.CorrelationID)
	}
	if got.UserAgent != "" {
		t.Errorf("UserAgent = %q for a request that sent none, want empty", got.UserAgent)
	}
	if got.IP == "" {
		t.Error("IP is empty: it comes from the connection, not from a header")
	}
}

// The default address resolution is the socket peer with its port stripped —
// `req.socket.remoteAddress`, which is also Express's req.ip under the default
// `trust proxy` setting. A RemoteAddr that does not split is used whole rather
// than discarded: an httptest request, a Unix socket and a bare address are all
// better reported as themselves than as "".
func TestEventContextClientIPDefault(t *testing.T) {
	cases := []struct{ remote, want string }{
		{"192.0.2.1:1234", "192.0.2.1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"192.0.2.9", "192.0.2.9"},
		{"", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.RemoteAddr = c.remote
		if got := EventContextFromRequest(req, DefaultHTTPConfig()).IP; got != c.want {
			t.Errorf("RemoteAddr %q: IP = %q, want %q", c.remote, got, c.want)
		}
	}
}

// HTTPConfig.ClientIP is the trust-proxy seam, and its answer is used as given
// — including an empty one. A host that returns "" has said the address is
// unknown, and second-guessing it with the socket peer would defeat the point
// of a deployment declaring that its proxy headers are not trustworthy.
func TestEventContextClientIPSeamIsAuthoritative(t *testing.T) {
	cfg := DefaultHTTPConfig()
	cfg.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.2")
	if got := EventContextFromRequest(req, cfg).IP; got != "203.0.113.7, 198.51.100.2" {
		t.Errorf("IP = %q, want the seam's answer verbatim", got)
	}

	bare := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	if got := EventContextFromRequest(bare, cfg).IP; got != "" {
		t.Errorf("IP = %q, want the seam's empty answer rather than the socket peer", got)
	}
}

func TestEventContextFromRequestToleratesANilRequest(t *testing.T) {
	if got := EventContextFromRequest(nil, DefaultHTTPConfig()); got != (EventContext{}) {
		t.Errorf("EventContextFromRequest(nil) = %+v, want the zero value", got)
	}
}

// The bool distinguishes "no carrier" from "a carrier with empty fields". They
// are different facts and a host's diagnostics may care.
func TestEventContextRoundTripsOnAContext(t *testing.T) {
	if _, ok := EventContextFromContext(context.Background()); ok {
		t.Error("a bare context reports a carrier")
	}
	empty := ContextWithEventContext(context.Background(), EventContext{})
	if _, ok := EventContextFromContext(empty); !ok {
		t.Error("an installed zero-value carrier reports as absent")
	}

	want := EventContext{CorrelationID: "c", IP: "i", UserAgent: "u"}
	got, ok := EventContextFromContext(ContextWithEventContext(context.Background(), want))
	if !ok || got != want {
		t.Errorf("round trip = %+v (%t), want %+v (true)", got, ok, want)
	}
}

func TestEventContextMiddlewareInstallsOnTheRequestContext(t *testing.T) {
	var got EventContext
	var found bool
	handler := EventContextMiddleware(DefaultHTTPConfig())(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			got, found = EventContextFromContext(r.Context())
		}))

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Header.Set(CorrelationIDHeader, "corr-mw")
	req.Header.Set("User-Agent", "ua-mw")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !found {
		t.Fatal("the middleware did not install a carrier")
	}
	if got.CorrelationID != "corr-mw" || got.UserAgent != "ua-mw" || got.IP != "192.0.2.1" {
		t.Errorf("carrier = %+v, want the request's three values", got)
	}
}

// Each request gets its own carrier. This is the failure the product's
// rotationScopeMiddleware precedent exists to rule out: a value installed on
// anything longer-lived than the request would publish the first request's
// correlation id for every later one.
func TestEventContextMiddlewareIsPerRequest(t *testing.T) {
	var seen []string
	handler := EventContextMiddleware(DefaultHTTPConfig())(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			ec, _ := EventContextFromContext(r.Context())
			seen = append(seen, ec.CorrelationID)
		}))

	for _, id := range []string{"one", "two", "three"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set(CorrelationIDHeader, id)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	// A fourth request with no header must report empty rather than inherit.
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	want := []string{"one", "two", "three", ""}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("request %d saw %q, want %q: the carrier is shared between requests",
				i, seen[i], want[i])
		}
	}
}

func TestEventContextMiddlewareLeavesTheRequestOtherwiseIntact(t *testing.T) {
	var gotMethod, gotPath, gotHeader string
	handler := EventContextMiddleware(DefaultHTTPConfig())(http.HandlerFunc(
		func(_ http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath, gotHeader = r.Method, r.URL.Path, r.Header.Get(CorrelationIDHeader)
		}))

	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.Header.Set(CorrelationIDHeader, "corr-intact")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if gotMethod != http.MethodPatch || gotPath != "/auth/profile" || gotHeader != "corr-intact" {
		t.Errorf("the middleware changed the request it forwarded: %s %s, header %q",
			gotMethod, gotPath, gotHeader)
	}
}
