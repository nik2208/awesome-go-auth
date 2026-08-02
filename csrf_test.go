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
