package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieNameResolution(t *testing.T) {
	cases := []struct {
		name    string
		options CookieOptions
		want    string
	}{
		{name: "insecure stays bare", options: CookieOptions{Secure: false, Path: "/"}, want: "accessToken"},
		{name: "secure and root-scoped earns __Host-", options: CookieOptions{Secure: true, Path: "/"}, want: "__Host-accessToken"},
		{name: "an unset path is treated as root", options: CookieOptions{Secure: true}, want: "__Host-accessToken"},
		{name: "a domain downgrades to __Secure-", options: CookieOptions{Secure: true, Path: "/", Domain: "example.com"}, want: "__Secure-accessToken"},
		{name: "a non-root path downgrades to __Secure-", options: CookieOptions{Secure: true, Path: "/app"}, want: "__Secure-accessToken"},
		{name: "an insecure domain cookie stays bare", options: CookieOptions{Domain: "example.com"}, want: "accessToken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.options.CookieName(AccessTokenCookieName); got != tc.want {
				t.Fatalf("CookieName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostPrefixedCookiesAreForcedHostScoped(t *testing.T) {
	// A browser silently drops a __Host- cookie that carries a Domain or is not
	// scoped to "/", so the refresh cookie's own path has to give way.
	options := CookieOptions{Secure: true, Path: "/", Domain: "", RefreshTokenPath: "/auth/refresh", RefreshTokenMaxAge: time.Hour}
	rec := httptest.NewRecorder()
	options.SetRefreshTokenCookie(rec, "token")

	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-refreshToken" {
		t.Fatalf("name = %q", c.Name)
	}
	if c.Path != "/" || c.Domain != "" || !c.Secure {
		t.Fatalf("__Host- attributes not enforced: %s", c.String())
	}
}

func TestCookieValueReadPriority(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "accessToken", Value: "bare"})
	if got := CookieValue(req, AccessTokenCookieName); got != "bare" {
		t.Fatalf("bare = %q", got)
	}

	req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: "secure"})
	if got := CookieValue(req, AccessTokenCookieName); got != "secure" {
		t.Fatalf("__Secure- must outrank bare, got %q", got)
	}

	req.AddCookie(&http.Cookie{Name: "__Host-accessToken", Value: "host"})
	if got := CookieValue(req, AccessTokenCookieName); got != "host" {
		t.Fatalf("__Host- must outrank the rest, got %q", got)
	}
}

func TestClearAuthCookiesExpiresEveryVariant(t *testing.T) {
	options := DefaultCookieOptions()
	options.RefreshTokenPath = "/auth/refresh"
	rec := httptest.NewRecorder()
	options.ClearAuthCookies(rec, true)

	cleared := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 || c.Value != "" {
			t.Errorf("%s is not expired: %s", c.Name, c.String())
		}
		cleared[c.Name] = true
	}
	for _, name := range []string{
		"accessToken", "__Secure-accessToken", "__Host-accessToken",
		"refreshToken", "__Secure-refreshToken", "__Host-refreshToken",
		"csrf-token", "__Secure-csrf-token", "__Host-csrf-token",
	} {
		if !cleared[name] {
			t.Errorf("variant %q was not cleared", name)
		}
	}
}

func TestClearAuthCookiesSkipsCSRFWhenDisabled(t *testing.T) {
	rec := httptest.NewRecorder()
	DefaultCookieOptions().ClearAuthCookies(rec, false)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-csrf-token" {
			t.Fatal("the csrf cookie must only be cleared when csrf is enabled")
		}
	}
}

func TestIsBearerRequestMatchesExactly(t *testing.T) {
	cases := map[string]bool{"bearer": true, "Bearer": false, "BEARER": false, "bearer ": false, "": false}
	for value, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if value != "" {
			req.Header.Set(AuthStrategyHeader, value)
		}
		if got := IsBearerRequest(req); got != want {
			t.Errorf("IsBearerRequest(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestErrorEnvelopeOmitsAnAbsentCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, HTTPErrNoAccessToken)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 1 || body["error"] != "No access token provided" {
		t.Fatalf("body = %v, want the message alone", body)
	}
}

// TestErrorCatalogLiterals pins the wire strings themselves. Every other test
// compares against the constants, so without this a rename of a constant's
// value would change the wire and still pass.
func TestErrorCatalogLiterals(t *testing.T) {
	codes := map[string]string{
		CodeInvalidCredentials:  "INVALID_CREDENTIALS",
		CodeEmailNotVerified:    "EMAIL_NOT_VERIFIED",
		CodeSessionRevoked:      "SESSION_REVOKED",
		CodeInvalidToken:        "INVALID_TOKEN",
		CodeInvalidRefreshToken: "INVALID_REFRESH_TOKEN",
		CodeCSRFInvalid:         "CSRF_INVALID",
		CodeTwoFactorRequired:   "2FA_REQUIRED",
		CodeUserNotFound:        "USER_NOT_FOUND",
		CodeNotImplemented:      "NOT_IMPLEMENTED",
	}
	for got, want := range codes {
		if got != want {
			t.Errorf("code %q must be %q", got, want)
		}
	}

	if AuthStrategyHeader != "X-Auth-Strategy" || AuthStrategyBearer != "bearer" {
		t.Errorf("bearer opt-in = %q: %q", AuthStrategyHeader, AuthStrategyBearer)
	}
	if CSRFHeaderName != "X-CSRF-Token" {
		t.Errorf("csrf header = %q", CSRFHeaderName)
	}
	if AccessTokenCookieName != "accessToken" || RefreshTokenCookieName != "refreshToken" || CSRFTokenCookieName != "csrf-token" {
		t.Errorf("cookie base names drifted: %q %q %q", AccessTokenCookieName, RefreshTokenCookieName, CSRFTokenCookieName)
	}

	messages := map[HTTPError]struct {
		status  int
		message string
		code    string
	}{
		HTTPErrSessionRevoked:      {401, "Session has been revoked", "SESSION_REVOKED"},
		HTTPErrCSRFInvalid:         {403, "CSRF token validation failed", "CSRF_INVALID"},
		HTTPErrInvalidCredentials:  {401, "Invalid credentials", "INVALID_CREDENTIALS"},
		HTTPErrEmailNotVerified:    {403, "Email address is not verified", "EMAIL_NOT_VERIFIED"},
		HTTPErrNoAccessToken:       {403, "No access token provided", ""},
		HTTPErrInvalidAccessToken:  {403, "Invalid or expired access token", ""},
		HTTPErrNoRefreshToken:      {401, "No refresh token provided", ""},
		HTTPErrInvalidRefreshToken: {401, "Invalid refresh token", ""},
		HTTPErrExpiredRefreshToken: {401, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN"},
		HTTPErrInternal:            {500, "Internal server error", ""},
	}
	for got, want := range messages {
		if got.Status != want.status || got.Message != want.message || got.Code != want.code {
			t.Errorf("catalog entry %+v drifted from %d %q %q", got, want.status, want.message, want.code)
		}
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		mapper func(error) HTTPError
		want   HTTPError
	}{
		{ErrInvalidCredentials, HTTPErrorFor, HTTPErrInvalidCredentials},
		{ErrEmailNotVerified, HTTPErrorFor, HTTPErrEmailNotVerified},
		{ErrUserExists, HTTPErrorFor, HTTPErrUserExists},
		{ErrWeakPassword, HTTPErrorFor, HTTPErrWeakPassword},
		{ErrSessionRevoked, HTTPErrorFor, HTTPErrSessionRevoked},
		{ErrFeatureNotSupported, HTTPErrorFor, HTTPErrNotImplemented},
		// A revoked session must never collapse into a generic token failure:
		// the clients branch on this code to stop refreshing.
		{ErrSessionRevoked, RefreshHTTPError, HTTPErrSessionRevoked},
		{ErrInvalidToken, RefreshHTTPError, HTTPErrExpiredRefreshToken},
		{ErrSessionNotFound, RefreshHTTPError, HTTPErrInvalidRefreshToken},
		{ErrSessionRevoked, AccessHTTPError, HTTPErrSessionRevoked},
		{ErrInvalidToken, AccessHTTPError, HTTPErrInvalidAccessToken},
	}

	for _, tc := range cases {
		if got := tc.mapper(tc.err); got != tc.want {
			t.Errorf("mapping %v = %+v, want %+v", tc.err, got, tc.want)
		}
	}
}

func TestHTTPConfigResolvesDerivedDefaults(t *testing.T) {
	cfg := HTTPConfig{APIPrefix: "api/auth/"}.resolve(10*time.Minute, 48*time.Hour)

	if cfg.APIPrefix != "/api/auth" {
		t.Errorf("APIPrefix = %q", cfg.APIPrefix)
	}
	if cfg.Cookies.RefreshTokenPath != "/api/auth/refresh" {
		t.Errorf("RefreshTokenPath = %q", cfg.Cookies.RefreshTokenPath)
	}
	if cfg.Cookies.AccessTokenMaxAge != 10*time.Minute || cfg.Cookies.RefreshTokenMaxAge != 48*time.Hour {
		t.Errorf("cookie lifetimes do not track the token lifetimes: %+v", cfg.Cookies)
	}
	if cfg.CSRF.CookieName != CSRFTokenCookieName || cfg.CSRF.HeaderName != CSRFHeaderName {
		t.Errorf("csrf names = %q/%q", cfg.CSRF.CookieName, cfg.CSRF.HeaderName)
	}
}

func TestRefreshTokenFromRequestPrefersTheBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"refreshToken":"from-body"}`))
	req.AddCookie(&http.Cookie{Name: "refreshToken", Value: "from-cookie"})
	if got := RefreshTokenFromRequest(req); got != "from-body" {
		t.Fatalf("got %q", got)
	}
}

func TestRefreshTokenFromRequestFallsBackToTheCookie(t *testing.T) {
	// Cookie-mode clients send no body at all; that must not read as an error.
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-refreshToken", Value: "from-cookie"})
	if got := RefreshTokenFromRequest(req); got != "from-cookie" {
		t.Fatalf("got %q", got)
	}
}
