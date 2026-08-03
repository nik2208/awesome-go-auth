package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Cookie names under the default (Secure) configuration.
const (
	hostAccess  = "__Host-accessToken"
	hostRefresh = "__Host-refreshToken"
	hostCSRF    = "__Host-csrf-token"
)

const (
	defaultAccessMaxAge  = int(15 * time.Minute / time.Second)
	defaultRefreshMaxAge = int(30 * 24 * time.Hour / time.Second)
	defaultCSRFMaxAge    = int(15 * time.Minute / time.Second)
)

// Run executes the wire-contract conformance suite against one adapter.
func Run(t *testing.T, mount Mounter) {
	t.Run("Register", func(t *testing.T) { testRegister(t, mount) })
	t.Run("Login", func(t *testing.T) { testLogin(t, mount) })
	t.Run("Refresh", func(t *testing.T) { testRefresh(t, mount) })
	t.Run("Logout", func(t *testing.T) { testLogout(t, mount) })
	t.Run("Me", func(t *testing.T) { testMe(t, mount) })
	t.Run("SessionRevoked", func(t *testing.T) { testSessionRevoked(t, mount) })
	t.Run("CookieNames", func(t *testing.T) { testCookieNames(t, mount) })
	t.Run("CookieReadPriority", func(t *testing.T) { testCookieReadPriority(t, mount) })
	t.Run("CSRF", func(t *testing.T) { testCSRF(t, mount) })
	t.Run("Redaction", func(t *testing.T) { testRedaction(t, mount) })
	t.Run("PasswordAndEmail", func(t *testing.T) { testPasswordAndEmail(t, mount) })
}

// sensitiveFields must never appear in an adapter response body.
var sensitiveFields = []string{
	"PasswordHash",
	"TOTPSecret",
	"ResetTokenHash",
	"MagicLinkTokenHash",
	"SMSCodeHash",
	"EmailVerificationTokenHash",
	"EmailChangeTokenHash",
	"PendingEmail",
}

// testRedaction re-pins the v0.1.0 fix: no route may serialise credential
// material, and the envelope change must not have reopened that hole.
func testRedaction(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	seeded, _ := env.Seed("redact@example.com")
	if seeded.PasswordHash == "" {
		t.Fatal("expected the stored user to carry a password hash")
	}

	register := env.Do(env.Request(http.MethodPost, "/register", credentials("redactnew@example.com")))
	login := env.Do(env.Request(http.MethodPost, "/login", credentials("redact@example.com")))
	meReq := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
	me := env.Do(Replay(meReq, login))

	for label, rec := range map[string]*httptest.ResponseRecorder{"register": register, "login": login, "me": me} {
		body := rec.Body.String()
		lowered := strings.ToLower(body)
		for _, field := range sensitiveFields {
			if strings.Contains(lowered, strings.ToLower(field)) {
				t.Errorf("%s response exposes %q: %s", label, field, body)
			}
		}
		if strings.Contains(body, seeded.PasswordHash) {
			t.Errorf("%s response leaked the stored password hash: %s", label, body)
		}
	}
}

func credentials(email string) map[string]string {
	return map[string]string{"email": email, "password": "password1", "tenantId": "t1"}
}

func accessCookieSpec() CookieSpec {
	return CookieSpec{Path: "/", MaxAge: defaultAccessMaxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func refreshCookieSpec() CookieSpec {
	// __Host- forces Path=/, so the /auth/refresh scoping is deliberately lost.
	return CookieSpec{Path: "/", MaxAge: defaultRefreshMaxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func csrfCookieSpec() CookieSpec {
	// Not HttpOnly: double-submit needs the page to read and mirror it.
	return CookieSpec{Path: "/", MaxAge: defaultCSRFMaxAge, Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode}
}

func testRegister(t *testing.T, mount Mounter) {
	t.Run("cookie mode sets cookies and returns no tokens", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/register", credentials("reg@example.com")))

		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		if id, _ := body["userId"].(string); id == "" {
			t.Fatalf("userId = %v, want a non-empty id", body["userId"])
		}
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostCSRF), csrfCookieSpec())
	})

	t.Run("bearer mode returns tokens and sets no cookies", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.Request(http.MethodPost, "/register", credentials("regbearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusCreated)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "userId", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("duplicate address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("dup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/register", credentials("dup@example.com")))
		AssertError(t, rec, http.StatusConflict, "User already exists", auth.CodeUserExists)
	})

	t.Run("weak password", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/register", map[string]string{"email": "weak@example.com", "password": "x"}))
		AssertError(t, rec, http.StatusBadRequest, "Password is too weak", auth.CodeWeakPassword)
	})

	t.Run("malformed body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/register", stringReader("{not json"))
		req.Header.Set("Content-Type", "application/json")
		rec := env.Do(req)
		AssertError(t, rec, http.StatusBadRequest, "Invalid request body", auth.CodeInvalidBody)
	})
}

func testLogin(t *testing.T, mount Mounter) {
	t.Run("cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("login@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/login", credentials("login@example.com")))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostCSRF), csrfCookieSpec())
	})

	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginbearer@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("loginbearer@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("the strategy header is matched exactly", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginexact@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("loginexact@example.com"))
		req.Header.Set(auth.AuthStrategyHeader, "Bearer")
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		Cookie(t, rec, hostAccess)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("loginbad@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/login", map[string]string{"email": "loginbad@example.com", "password": "wrong", "tenantId": "t1"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", auth.CodeInvalidCredentials)
	})
}

func testRefresh(t *testing.T, mount Mounter) {
	t.Run("cookie mode succeeds with an empty body", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("refresh@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("refresh@example.com")))

		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil)
		rec := env.Do(Replay(req, login))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("refreshbearer@example.com")
		req := env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("no token anywhere", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil))
		AssertError(t, rec, http.StatusUnauthorized, "No refresh token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": "bogus"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired refresh token", auth.CodeInvalidRefreshToken)
	})
}

func testLogout(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	env.Seed("logout@example.com")
	login := env.Do(env.Request(http.MethodPost, "/login", credentials("logout@example.com")))

	req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
	rec := env.Do(Replay(req, login))

	AssertStatus(t, rec, http.StatusOK)
	AssertKeys(t, Body(t, rec), "success")

	// Every name variant is expired, not just the one this configuration writes:
	// a cookie left over from a differently configured release must not survive.
	for _, name := range []string{
		hostAccess, "__Secure-accessToken", "accessToken",
		hostRefresh, "__Secure-refreshToken", "refreshToken",
		hostCSRF, "__Secure-csrf-token", "csrf-token",
	} {
		AssertCleared(t, rec, name)
	}

	t.Run("succeeds without a token", func(t *testing.T) {
		fresh := NewEnv(t, mount, auth.DefaultHTTPConfig())
		bare := fresh.Do(httptest.NewRequest(http.MethodPost, fresh.Config.Prefix()+"/logout", nil))
		AssertStatus(t, bare, http.StatusOK)
		AssertKeys(t, Body(t, bare), "success")
	})

	// Answering 200 {"success":true} is only half of logout. The session has to
	// be dead afterwards, and it has to be dead in the configurations where the
	// refresh cookie is path-scoped away from <prefix>/logout — otherwise the
	// browser looks logged out while the refresh token stays usable forever.
	for _, tc := range []struct {
		name   string
		mutate func(*auth.HTTPConfig)
	}{
		{name: "__Host- configuration", mutate: func(*auth.HTTPConfig) {}},
		// Both of these keep the access cookie at "/" but scope the refresh cookie
		// to <prefix>/refresh, so logout only ever sees the access cookie — which
		// is exactly the credential the reference logout reads.
		{name: "__Secure- via domain", mutate: func(c *auth.HTTPConfig) { c.Cookies.Domain = "example.com" }},
		{name: "bare via insecure", mutate: func(c *auth.HTTPConfig) { c.Cookies.Secure = false }},
		// Cookies.Path = "/app" is deliberately not covered: it scopes every auth
		// cookie away from the auth mount itself, so no credential reaches logout
		// in any implementation, the reference included.
	} {
		t.Run("revokes the session, "+tc.name, func(t *testing.T) {
			cfg := auth.DefaultHTTPConfig()
			tc.mutate(&cfg)
			env := NewEnv(t, mount, cfg)
			env.Seed("logoutrevoke@example.com")
			login := env.Do(env.Request(http.MethodPost, "/login", credentials("logoutrevoke@example.com")))

			logoutReq := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
			AssertStatus(t, env.Do(Replay(logoutReq, login)), http.StatusOK)

			// The refresh credential the login handed out must be dead. Replay it
			// against /refresh the way the client would, path scoping and all.
			refreshReq := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil)
			rec := env.Do(Replay(refreshReq, login))
			AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
		})
	}
}

func testMe(t *testing.T, mount Mounter) {
	t.Run("returns the user unwrapped", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("me@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("me@example.com")))

		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		rec := env.Do(Replay(req, login))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		if _, wrapped := body["user"]; wrapped {
			t.Fatalf("GET /me is wrapped in a user envelope: %s", rec.Body.String())
		}
		if body["email"] != "me@example.com" {
			t.Fatalf("email = %v, want me@example.com (body %s)", body["email"], rec.Body.String())
		}
		for _, key := range []string{"id", "isEmailVerified", "isTotpEnabled", "createdAt"} {
			if _, ok := body[key]; !ok {
				t.Errorf("missing key %q in %s", key, rec.Body.String())
			}
		}
	})

	t.Run("bearer credential", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("mebearer@example.com")
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if Body(t, rec)["email"] != "mebearer@example.com" {
			t.Fatalf("unexpected body %s", rec.Body.String())
		}
		AssertNoCookies(t, rec)
	})

	// 403 with no code is the reference's own behaviour for a missing or
	// unusable access token, odd as it looks beside the 401s.
	t.Run("no token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		rec := env.Do(req)
		AssertError(t, rec, http.StatusForbidden, "Invalid or expired access token", "")
	})
}

func testSessionRevoked(t *testing.T, mount Mounter) {
	// Both browser clients log out on exactly this code and refresh-loop on
	// anything else, so both emission points are pinned.
	t.Run("refresh", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("revoked@example.com")
		if err := env.Auth.Logout(context.Background(), tokens.RefreshToken); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		rec := env.Do(env.Request(http.MethodPost, "/refresh", map[string]string{"refreshToken": tokens.RefreshToken}))
		AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})

	t.Run("protected route under allcalls", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionCheckOn(auth.SessionCheckOnAllCalls))
		_, tokens := env.Seed("revokedme@example.com")
		if err := env.Auth.Logout(context.Background(), tokens.RefreshToken); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)
		AssertError(t, rec, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})
}

func testCookieNames(t *testing.T, mount Mounter) {
	cases := []struct {
		name        string
		mutate      func(*auth.HTTPConfig)
		access      string
		refresh     string
		csrf        string
		refreshPath string
		domain      string
		secure      bool
	}{
		{
			name:        "bare when insecure",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Secure = false },
			access:      "accessToken",
			refresh:     "refreshToken",
			csrf:        "csrf-token",
			refreshPath: "/auth/refresh",
		},
		{
			name:        "__Host- when secure, root-scoped and domainless",
			mutate:      func(c *auth.HTTPConfig) {},
			access:      hostAccess,
			refresh:     hostRefresh,
			csrf:        hostCSRF,
			refreshPath: "/",
			secure:      true,
		},
		{
			name:        "__Secure- when a domain is set",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Domain = "example.com" },
			access:      "__Secure-accessToken",
			refresh:     "__Secure-refreshToken",
			csrf:        "__Secure-csrf-token",
			refreshPath: "/auth/refresh",
			domain:      "example.com",
			secure:      true,
		},
		{
			name:        "__Secure- when the path is not root",
			mutate:      func(c *auth.HTTPConfig) { c.Cookies.Path = "/app" },
			access:      "__Secure-accessToken",
			refresh:     "__Secure-refreshToken",
			csrf:        "__Secure-csrf-token",
			refreshPath: "/auth/refresh",
			secure:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auth.DefaultHTTPConfig()
			tc.mutate(&cfg)
			env := NewEnv(t, mount, cfg)
			rec := env.Do(env.Request(http.MethodPost, "/register", credentials("names@example.com")))
			AssertStatus(t, rec, http.StatusCreated)

			access := Cookie(t, rec, tc.access)
			if access.Secure != tc.secure {
				t.Errorf("%s Secure = %v, want %v", access.Name, access.Secure, tc.secure)
			}
			if access.Domain != tc.domain {
				t.Errorf("%s Domain = %q, want %q", access.Name, access.Domain, tc.domain)
			}
			if refresh := Cookie(t, rec, tc.refresh); refresh.Path != tc.refreshPath {
				t.Errorf("%s Path = %q, want %q", refresh.Name, refresh.Path, tc.refreshPath)
			}
			if csrf := Cookie(t, rec, tc.csrf); csrf.HttpOnly {
				t.Errorf("%s must stay readable by JS", csrf.Name)
			}
		})
	}
}

func testCookieReadPriority(t *testing.T, mount Mounter) {
	env := NewEnv(t, mount, auth.DefaultHTTPConfig())
	_, tokens := env.Seed("priority@example.com")

	// The read side is configuration-independent: a bare cookie is honoured by a
	// server that writes __Host- names, and __Host- outranks the others.
	for _, name := range []string{"accessToken", "__Secure-accessToken", hostAccess} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
			req.AddCookie(&http.Cookie{Name: name, Value: tokens.AccessToken})
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
		})
	}

	t.Run("__Host- outranks __Secure- and bare", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: hostAccess, Value: tokens.AccessToken})
		req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: "wrong"})
		req.AddCookie(&http.Cookie{Name: "accessToken", Value: "wrong"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})

	t.Run("__Secure- outranks bare", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: "__Secure-accessToken", Value: tokens.AccessToken})
		req.AddCookie(&http.Cookie{Name: "accessToken", Value: "wrong"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})
}

func testCSRF(t *testing.T, mount Mounter) {
	t.Run("the cookie is distributed to cookie clients", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil))
		csrf := Cookie(t, rec, hostCSRF)
		if len(csrf.Value) != 32 {
			t.Errorf("csrf token = %q, want 32 hex characters", csrf.Value)
		}
		AssertCookieAttrs(t, csrf, csrfCookieSpec())
	})

	t.Run("an existing cookie is not rotated", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil)
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "existing"})
		AssertNoCookie(t, env.Do(req), hostCSRF)
	})

	// The reference mounts logout without its auth middleware, so CSRF is never
	// checked there — a client whose CSRF cookie has expired can still log out.
	t.Run("logout is exempt", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/logout", nil)
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})

	t.Run("login is exempt", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("csrflogin@example.com")
		req := env.Request(http.MethodPost, "/login", credentials("csrflogin@example.com"))
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, env.Do(req), http.StatusOK)
	})
}

func assertNonEmptyString(t *testing.T, body map[string]any, key string) {
	t.Helper()
	if v, _ := body[key].(string); v == "" {
		t.Fatalf("%s = %v, want a non-empty string", key, body[key])
	}
}
