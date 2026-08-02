package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func csrfHandler(cfg HTTPConfig) http.Handler {
	return CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func insecureHTTPConfig() HTTPConfig {
	cfg := DefaultHTTPConfig()
	cfg.Cookies.Secure = false
	return cfg
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCSRFMiddlewareAutoInitialisesTheCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	c := findCookie(rec, "csrf-token")
	if c == nil {
		t.Fatal("expected the csrf-token cookie to be initialised")
	}
	if len(c.Value) != 32 {
		t.Errorf("token = %q, want 32 hex characters", c.Value)
	}
	if c.HttpOnly {
		t.Error("the csrf cookie must stay readable by JS for double-submit to work")
	}
}

func TestCSRFMiddlewareDoesNotRotateAnExistingCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "existing"})
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("unexpected rotation: %s", c.String())
	}
}

func TestCSRFMiddlewareReadsThePrefixedCookie(t *testing.T) {
	// The write side may have emitted __Host-csrf-token; the read side has to
	// find it whatever the current configuration would write.
	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-csrf-token", Value: "match"})
	req.Header.Set(CSRFHeaderName, "match")
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestCSRFMiddlewareEnforcementMatrix(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		cookie     string
		header     string
		authHeader string
		strategy   string
		want       int
	}{
		{name: "matching header passes", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "tok", want: http.StatusOK},
		{name: "missing header is rejected", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", want: http.StatusForbidden},
		{name: "mismatched header is rejected", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "other", want: http.StatusForbidden},
		{name: "missing cookie is rejected", method: http.MethodDelete, path: "/auth/account", header: "tok", want: http.StatusForbidden},
		{name: "safe methods are exempt", method: http.MethodGet, path: "/auth/profile", cookie: "tok", want: http.StatusOK},
		{name: "bearer credentials are exempt", method: http.MethodDelete, path: "/auth/account", authHeader: "Bearer abc", want: http.StatusOK},
		{name: "bearer strategy is exempt", method: http.MethodDelete, path: "/auth/account", strategy: AuthStrategyBearer, want: http.StatusOK},
		{name: "login is exempt", method: http.MethodPost, path: "/auth/login", cookie: "tok", want: http.StatusOK},
		{name: "refresh is exempt", method: http.MethodPost, path: "/auth/refresh", cookie: "tok", want: http.StatusOK},
		// The reference deliberately mounts logout without its auth middleware,
		// so a stale CSRF cookie must not trap a client in a logged-in state.
		{name: "logout is exempt", method: http.MethodPost, path: "/auth/logout", cookie: "tok", want: http.StatusOK},
		{name: "routes outside the prefix are untouched", method: http.MethodPost, path: "/api/orders", cookie: "tok", want: http.StatusOK},
		// A path that merely starts with the prefix's characters is not the mount.
		{name: "a longer segment is not the prefix", method: http.MethodPost, path: "/authenticate/login", cookie: "tok", want: http.StatusOK},
		{name: "an unrelated segment containing the prefix is untouched", method: http.MethodPost, path: "/api/authors/create", cookie: "tok", want: http.StatusOK},
		// gin/echo groups and chi Route serve <base><prefix>/<route>: enforcement
		// must not switch itself off just because the mount sits below a base path.
		{name: "a group-mounted protected route is enforced", method: http.MethodPatch, path: "/api/auth/profile", cookie: "tok", want: http.StatusForbidden},
		{name: "a group-mounted protected route passes with the header", method: http.MethodPatch, path: "/api/auth/profile", cookie: "tok", header: "tok", want: http.StatusOK},
		{name: "a group-mounted exempt route stays exempt", method: http.MethodPost, path: "/api/auth/login", cookie: "tok", want: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "csrf-token", Value: tc.cookie})
			}
			if tc.header != "" {
				req.Header.Set(CSRFHeaderName, tc.header)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.strategy != "" {
				req.Header.Set(AuthStrategyHeader, tc.strategy)
			}
			rec := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestCSRFExemptionsMatchTheReference pins the exemption table route by route
// against wire-contract.md. Every route in the reference auth router that this
// port will eventually mount is listed, so a route added later cannot inherit a
// wrong default: the table itself is the thing under test, not the five routes
// that happen to be mounted today (all of which are exempt, which is why the
// per-adapter suites cannot catch a mistake here).
func TestCSRFExemptionsMatchTheReference(t *testing.T) {
	// Enforced: the reference puts these behind authMiddleware, where the
	// double-submit check lives — plus /link-request, which has no auth
	// middleware but does its own manual check (auth.router.ts:1489-1495).
	enforced := []string{
		"/profile",
		"/add-phone",
		"/change-password",
		"/send-verification-email",
		"/change-email/request",
		"/2fa/setup",
		"/2fa/verify-setup",
		"/2fa/disable",
		"/sessions/some-handle",
		"/account",
		"/linked-accounts/google/123",
		"/link-request",
	}
	// Exempt: mounted without authMiddleware, so never checked.
	exempt := []string{
		"/login",
		"/register",
		"/refresh",
		"/logout",
		"/forgot-password",
		"/reset-password",
		"/verify-email",
		"/change-email/confirm",
		"/magic-link/send",
		"/magic-link/verify",
		"/sms/send",
		"/sms/verify",
		"/2fa/verify",
		"/link-verify",
		"/sessions/cleanup",
	}

	for _, route := range enforced {
		t.Run("enforced"+route, func(t *testing.T) {
			if got := statusFor(t, http.MethodPost, "/auth"+route); got != http.StatusForbidden {
				t.Errorf("POST %s = %d, want 403: CSRF is not enforced on a protected route", route, got)
			}
		})
	}
	for _, route := range exempt {
		t.Run("exempt"+route, func(t *testing.T) {
			if got := statusFor(t, http.MethodPost, "/auth"+route); got != http.StatusOK {
				t.Errorf("POST %s = %d, want 200: an unauthenticated route must not be CSRF-checked", route, got)
			}
		})
	}
}

// statusFor drives the middleware with a CSRF cookie and no header — the shape
// every cookie client has before it mirrors the token.
func statusFor(t *testing.T, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
	return rec.Code
}

func TestCSRFRejectionBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body["error"] != "CSRF token validation failed" || body["code"] != CodeCSRFInvalid {
		t.Fatalf("body = %v", body)
	}
	if len(body) != 2 {
		t.Fatalf("unexpected extra fields: %v", body)
	}
}

func TestCSRFMiddlewareDisabled(t *testing.T) {
	cfg := insecureHTTPConfig()
	cfg.CSRF.Enabled = false

	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	rec := httptest.NewRecorder()
	csrfHandler(cfg).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("no cookie should be distributed when csrf is disabled: %s", c.String())
	}
}
