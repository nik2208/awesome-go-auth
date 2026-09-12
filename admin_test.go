package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The parts of the admin skeleton that are decisions rather than wire: where it
// mounts, whether it mounts at all, and what the session cookie is called.
//
// The wire itself — the six routes, the guard's branches, the four policies —
// is pinned once for all four adapters in adapter/internal/wiretest/admin.go.
// What is here is what that suite can only reach through one configuration.

func TestAdminPathNormalises(t *testing.T) {
	for input, want := range map[string]string{
		"":              DefaultAdminPath,
		"   ":           DefaultAdminPath,
		"admin":         "/admin",
		"/admin":        "/admin",
		"/admin/":       "/admin",
		"back/office/":  "/back/office",
		"/back/office/": "/back/office",
	} {
		cfg := HTTPConfig{Admin: AdminOptions{Path: input}}
		if got := cfg.AdminPath(); got != want {
			t.Errorf("AdminPath(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestAdminMounted is the admin-console-requires-an-explicit-policy deviation
// stated as a truth table. The third row is the one the reference serves
// unguarded after a warning on stderr (admin.router.ts:531-536).
func TestAdminMounted(t *testing.T) {
	secret := "s"
	cases := []struct {
		name string
		opts AdminOptions
		want bool
	}{
		{"nothing configured", AdminOptions{}, false},
		{"a policy but no flag", AdminOptions{AccessPolicy: AdminOpen()}, false},
		{"the flag but no access decision", AdminOptions{Enabled: true}, false},
		{"the flag and a blank secret", AdminOptions{Enabled: true, Secret: "   "}, false},
		{"the flag and a policy", AdminOptions{Enabled: true, AccessPolicy: AdminIsAdminFlag()}, true},
		{"the flag and the legacy secret", AdminOptions{Enabled: true, Secret: secret}, true},
		{"the flag and an open policy", AdminOptions{Enabled: true, AccessPolicy: AdminOpen()}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (HTTPConfig{Admin: c.opts}).AdminMounted(); got != c.want {
				t.Errorf("AdminMounted() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestAdminCookieName pins resolveAdminCookieName (admin.router.ts:218-231)
// over the seam this port reads instead of the request header, and pins
// applyHostCookieRequirements (:243-252) in the one configuration where it is
// load-bearing: an explicit "__Host-" prefix over cookie options that would
// otherwise violate the prefix's rules.
func TestAdminCookieName(t *testing.T) {
	prefix := func(s string) *string { return &s }

	cases := []struct {
		name       string
		cookies    CookieOptions
		prefix     *string
		wantName   string
		wantSecure bool
		wantPath   string
		wantDomain string
	}{
		{
			name:       "secure, root-scoped and domainless earns __Host-",
			cookies:    CookieOptions{Secure: true, Path: "/"},
			wantName:   "__Host-accessToken",
			wantSecure: true,
			wantPath:   "/",
		},
		{
			name:       "a domain demotes it to __Secure-",
			cookies:    CookieOptions{Secure: true, Path: "/", Domain: "example.com"},
			wantName:   "__Secure-accessToken",
			wantSecure: true,
			wantPath:   "/",
			wantDomain: "example.com",
		},
		{
			name:     "an insecure deployment stays bare",
			cookies:  CookieOptions{Path: "/"},
			wantName: "accessToken",
			wantPath: "/",
		},
		{
			name:       "an explicit prefix overrides the derivation",
			cookies:    CookieOptions{Secure: true, Path: "/"},
			prefix:     prefix(""),
			wantName:   "accessToken",
			wantSecure: true,
			wantPath:   "/",
		},
		{
			// The reference's applyHostCookieRequirements exists for exactly
			// this: a name a caller forced, over attributes the browser would
			// reject it under. Secure and Path are repaired and Domain dropped.
			name:       "an explicit __Host- prefix repairs the attributes",
			cookies:    CookieOptions{Path: "/deep", Domain: "example.com"},
			prefix:     prefix("__Host-"),
			wantName:   "__Host-accessToken",
			wantSecure: true,
			wantPath:   "/",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := HTTPConfig{Cookies: c.cookies, Admin: AdminOptions{CookiePrefix: c.prefix}}
			if got := cfg.adminCookieName(); got != c.wantName {
				t.Fatalf("adminCookieName() = %q, want %q", got, c.wantName)
			}
			cookie := cfg.adminCookie("value", adminSessionTTL)
			if cookie.Secure != c.wantSecure {
				t.Errorf("Secure = %v, want %v", cookie.Secure, c.wantSecure)
			}
			if cookie.Path != c.wantPath {
				t.Errorf("Path = %q, want %q", cookie.Path, c.wantPath)
			}
			if cookie.Domain != c.wantDomain {
				t.Errorf("Domain = %q, want %q", cookie.Domain, c.wantDomain)
			}
			if !cookie.HttpOnly {
				t.Error("the admin session cookie must be HttpOnly")
			}
			if cookie.MaxAge != int(adminSessionTTL/time.Second) {
				t.Errorf("Max-Age = %d, want %d to match expiresIn '24h'",
					cookie.MaxAge, int(adminSessionTTL/time.Second))
			}
		})
	}
}

func TestAdminRouterPath(t *testing.T) {
	cfg := HTTPConfig{Admin: AdminOptions{Path: "/back/office"}}
	for path, want := range map[string]string{
		"/back/office":          "/",
		"/back/office/":         "/",
		"/back/office/api/ping": "/api/ping",
		"/back/office/assets/x": "/assets/x",
		"/elsewhere":            "/elsewhere",
		"/back/officeabc":       "/back/officeabc",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if got := adminRouterPath(req, cfg); got != want {
			t.Errorf("adminRouterPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestAdminShellInjectionIsEscaped is the ui-ssr-config-json-is-html-escaped
// reasoning applied to the admin shell: every string in __ADMIN_CONFIG__ comes
// from configuration, and one of them closing the script element would hand the
// auth origin to whoever set it.
func TestAdminShellInjectionIsEscaped(t *testing.T) {
	a := newAdminTestAuth(t)
	cfg := HTTPConfig{
		APIPrefix: "/auth",
		Admin: AdminOptions{
			Enabled:       true,
			AccessPolicy:  AdminOpen(),
			UploadBaseURL: `</script><img src=x onerror=alert(1)>`,
		},
	}
	page := string(a.adminShellHTML(cfg, false, false))
	if strings.Contains(page, "</script><img") {
		t.Fatalf("the injected config broke out of its script element:\n%s", page)
	}
	if !strings.Contains(page, `\u003c/script\u003e`) {
		t.Errorf("expected the escaped form in the injected config:\n%s", page)
	}
}

// TestAdminShellNeedsAuthWithholdsFeatures is the second half of the
// admin-unauthenticated-get-serves-only-the-login-form deviation.
func TestAdminShellNeedsAuthWithholdsFeatures(t *testing.T) {
	a := newAdminTestAuth(t)
	cfg := HTTPConfig{APIPrefix: "/auth", Admin: AdminOptions{
		Enabled: true, AccessPolicy: AdminIsAdminFlag(), UploadBaseURL: "/uploads",
	}}

	authed := string(a.adminShellHTML(cfg, true, false))
	if !strings.Contains(authed, `"featSessions":true`) {
		t.Fatalf("an authenticated shell must carry the real flags:\n%s", authed)
	}

	anonymous := string(a.adminShellHTML(cfg, true, true))
	for _, flag := range []string{"featSessions", "featRoles", "featTenants", "featMetadata"} {
		if strings.Contains(anonymous, `"`+flag+`":true`) {
			t.Errorf("the unauthenticated shell disclosed %s:\n%s", flag, anonymous)
		}
	}
	if strings.Contains(anonymous, `"uploadBaseUrl":"/uploads"`) {
		t.Error("the unauthenticated shell disclosed uploadBaseUrl")
	}
	if !strings.Contains(anonymous, `id="login"`) {
		t.Error("the unauthenticated shell must render the login form")
	}
}

// newAdminTestAuth builds an Auth with the stores the feature flags read, so
// adminFeatures reports something other than an empty set.
func newAdminTestAuth(t *testing.T) *Auth {
	t.Helper()
	a, err := New(
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		WithRBACProvider(NewMemoryRolesPermissionsStore()),
		WithTenantProvider(NewMemoryTenantStore()),
		WithMetadataProvider(NewMemoryMetadataStore()),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}
