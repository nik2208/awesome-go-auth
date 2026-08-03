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
		// The reference exempts a request because its token *came from* the
		// Authorization header (usingBearer, auth.middleware.ts:22-26), not because
		// the client said so. X-Auth-Strategy is set by the caller on any request
		// the caller can make at all, so honouring it here would let an attacker
		// switch the control off with one header.
		{name: "the bearer strategy header alone is not exempt", method: http.MethodDelete, path: "/auth/account", strategy: AuthStrategyBearer, want: http.StatusForbidden},
		{name: "the bearer strategy header does not exempt a cookie-authenticated request", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", strategy: AuthStrategyBearer, want: http.StatusForbidden},
		// It stays exempt when the credential is really there, whatever it declares.
		{name: "the bearer strategy header with real bearer credentials is exempt", method: http.MethodPatch, path: "/auth/profile", authHeader: "Bearer abc", strategy: AuthStrategyBearer, want: http.StatusOK},
		// A double-submit that matches still passes with the strategy header set:
		// narrowing the exemption must not break a bearer-declaring cookie client.
		{name: "the bearer strategy header with a matching double-submit passes", method: http.MethodPatch, path: "/auth/profile", cookie: "tok", header: "tok", strategy: AuthStrategyBearer, want: http.StatusOK},
		// Keyed on method as well as path: DELETE <prefix>/sessions/cleanup is
		// DELETE /sessions/{handle} with the handle "cleanup", which the reference
		// puts behind authMiddleware. Only POST /sessions/cleanup is unauthenticated.
		{name: "cleanup is exempt only for POST", method: http.MethodDelete, path: "/auth/sessions/cleanup", cookie: "tok", want: http.StatusForbidden},
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
// wrong default: the table itself is the thing under test, not the routes that
// happen to be mounted today.
//
// Each row carries the reference's method, because the exemptions are Express
// routes and not paths: an exempt path reached with a method the reference did
// not mount unauthenticated must still be checked.
func TestCSRFExemptionsMatchTheReference(t *testing.T) {
	// Enforced: the reference puts these behind authMiddleware, where the
	// double-submit check lives — plus POST /link-request, which has no auth
	// middleware but does its own manual check (auth.router.ts:1489-1495).
	enforced := []struct{ method, route string }{
		{http.MethodPatch, "/profile"},
		{http.MethodPost, "/add-phone"},
		{http.MethodPost, "/change-password"},
		{http.MethodPost, "/send-verification-email"},
		{http.MethodPost, "/change-email/request"},
		{http.MethodPost, "/2fa/setup"},
		{http.MethodPost, "/2fa/verify-setup"},
		{http.MethodPost, "/2fa/disable"},
		{http.MethodDelete, "/sessions/some-handle"},
		{http.MethodDelete, "/account"},
		{http.MethodDelete, "/linked-accounts/google/123"},
		{http.MethodPost, "/link-request"},
		// The method-qualified rows: the exempt path reached with the method the
		// reference mounts behind authMiddleware. DELETE /sessions/cleanup is
		// DELETE /sessions/{handle} with the handle "cleanup".
		{http.MethodDelete, "/sessions/cleanup"},
		// GET /verify-email is the table's only non-POST exemption, so a POST to it
		// proves the key really carries the method.
		{http.MethodPost, "/verify-email"},
	}
	// Exempt: mounted without authMiddleware, so never checked. Methods from
	// src/router/auth.router.ts:541, 590, 622, 715, 736, 777, 802, 859, 969, 1040,
	// 1078, 1126, 1176, 1244, 1544.
	exempt := []struct{ method, route string }{
		{http.MethodPost, "/login"},
		{http.MethodPost, "/register"},
		{http.MethodPost, "/refresh"},
		{http.MethodPost, "/logout"},
		{http.MethodPost, "/forgot-password"},
		{http.MethodPost, "/reset-password"},
		// A GET, so exempt as a safe method whatever the table says.
		{http.MethodGet, "/verify-email"},
		{http.MethodPost, "/change-email/confirm"},
		{http.MethodPost, "/magic-link/send"},
		{http.MethodPost, "/magic-link/verify"},
		{http.MethodPost, "/sms/send"},
		{http.MethodPost, "/sms/verify"},
		{http.MethodPost, "/2fa/verify"},
		{http.MethodPost, "/link-verify"},
		{http.MethodPost, "/sessions/cleanup"},
	}

	for _, tc := range enforced {
		t.Run("enforced "+tc.method+tc.route, func(t *testing.T) {
			if got := statusFor(t, tc.method, "/auth"+tc.route); got != http.StatusForbidden {
				t.Errorf("%s %s = %d, want 403: CSRF is not enforced on a protected route", tc.method, tc.route, got)
			}
		})
	}
	for _, tc := range exempt {
		t.Run("exempt "+tc.method+tc.route, func(t *testing.T) {
			if got := statusFor(t, tc.method, "/auth"+tc.route); got != http.StatusOK {
				t.Errorf("%s %s = %d, want 200: an unauthenticated route must not be CSRF-checked", tc.method, tc.route, got)
			}
		})
	}
}

// TestCSRFCookieDistributionStillHonoursTheStrategyHeader guards the other half
// of the narrowed exemption: X-Auth-Strategy no longer switches enforcement off,
// but it must still keep cookies off a bearer client's response — "bearer
// requests set no cookies" is asserted of whole responses across the adapter
// suites.
func TestCSRFCookieDistributionStillHonoursTheStrategyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set(AuthStrategyHeader, AuthStrategyBearer)
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a safe method", rec.Code)
	}
	if c := findCookie(rec, "csrf-token"); c != nil {
		t.Fatalf("a bearer-strategy caller must not be sent a csrf cookie: %s", c.String())
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
