package auth

import (
	"regexp"
	"strings"
	"testing"
)

// The served browser assets are the third thing in this repository that nobody
// executed and that therefore rotted: auth.js called /auth/totp/setup,
// /auth/email/verify and /auth/metadata — none of which any adapter has ever
// mounted — sent snake_case bodies, and read tokens out of a `tokens` object the
// server stopped returning in 0.2.0.
//
// These tests pin the assets to the routes that exist. The chain is
//
//	asset paths ⊆ GenerateOpenAPISpec paths ⊆ mounted routes
//
// and the second link is enforced by the wire conformance suite, which replays
// every documented operation against all four adapters. So a call in auth.js to
// a route nobody serves now fails the build here.

// assetRoutePattern matches a single-quoted path literal in the embedded JS/HTML.
var assetRoutePattern = regexp.MustCompile(`'(/[A-Za-z0-9/_.\-{}]*)'`)

// documentedAssetPaths is the mounted route set, taken from the spec and stripped
// of the mount prefix.
func documentedAssetPaths(t *testing.T) map[string]bool {
	t.Helper()
	spec := GenerateOpenAPISpec(OpenAPIInfo{})
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatalf("spec has no paths object: %T", spec["paths"])
	}
	out := make(map[string]bool, len(paths))
	for path := range paths {
		out[strings.TrimPrefix(path, DefaultAPIPrefix)] = true
	}
	if len(out) == 0 {
		t.Fatal("no documented paths: the guard below would pass vacuously")
	}
	return out
}

// knownAssetPath reports whether a literal found in an asset names a route that
// exists. A literal may be the whole path, or the constant head of one built by
// concatenation ("/sessions/" + handle), which has to match a parameterised
// documented path.
func knownAssetPath(literal string, documented map[string]bool) bool {
	clean := normaliseAssetPath(literal)
	if documented[clean] {
		return true
	}
	if !strings.HasSuffix(clean, "/") {
		return false
	}
	for path := range documented {
		// "/sessions/" is the head of "/sessions/{handle}".
		if strings.HasPrefix(path, clean) && strings.Contains(path[len(clean):], "{") {
			return true
		}
	}
	return false
}

// normaliseAssetPath strips the query and the mount prefix, so a literal written
// as "/auth/login" (the HTML pages concatenate an origin with the full path) and
// one written as "/login" (the SDK prepends the prefix itself) compare equal.
func normaliseAssetPath(literal string) string {
	clean := literal
	if i := strings.IndexByte(clean, '?'); i >= 0 {
		clean = clean[:i]
	}
	if clean == DefaultAPIPrefix {
		return "/"
	}
	if strings.HasPrefix(clean, DefaultAPIPrefix+"/") {
		clean = strings.TrimPrefix(clean, DefaultAPIPrefix)
	}
	return clean
}

// assetSource reads one embedded asset.
func assetSource(t *testing.T, name string) string {
	t.Helper()
	data, err := uiFS.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// TestServedAssetsCallRoutesThatExist is the guard that would have caught the
// rot. Every path literal in the served SDK has to name a mounted route.
func TestServedAssetsCallRoutesThatExist(t *testing.T) {
	documented := documentedAssetPaths(t)

	// An individual asset may legitimately contain no path at all — auth.html
	// calls everything through the SDK — so the "did the regex still match
	// anything" guard is counted across all of them rather than per asset.
	checked := 0
	for _, asset := range []string{"ui/auth.js", "ui/auth.html", "ui/admin.html"} {
		t.Run(asset, func(t *testing.T) {
			source := assetSource(t, asset)
			for _, match := range assetRoutePattern.FindAllStringSubmatch(source, -1) {
				// The assets also carry paths that are not auth routes —
				// stylesheets, UI pages the host mounts — so only literals whose
				// first segment belongs to the router are held to the contract.
				literal := match[1]
				if !isAuthRouteLiteral(literal) {
					continue
				}
				checked++
				if !knownAssetPath(literal, documented) {
					t.Errorf("%s calls %q, which no adapter mounts", asset, literal)
				}
			}
		})
	}
	if checked == 0 {
		t.Error("no auth route literals found in any asset — the extraction regex has stopped matching")
	}
}

// isAuthRouteLiteral filters the path literals down to the ones that name an
// auth route, so an unrelated asset path in the HTML is not held to the contract.
// The list is the first segment of every mounted route.
func isAuthRouteLiteral(literal string) bool {
	literal = normaliseAssetPath(literal)
	heads := []string{
		"/register", "/login", "/refresh", "/logout", "/me",
		"/sessions", "/profile", "/add-phone", "/account",
		"/oauth", "/linked-accounts", "/link-request", "/link-verify",
		"/magic-link", "/sms", "/2fa", "/totp",
		"/forgot-password", "/reset-password", "/change-password",
		"/send-verification-email", "/verify-email", "/change-email",
		"/email", "/metadata",
	}
	for _, head := range heads {
		if literal == head || strings.HasPrefix(literal, head+"/") || strings.HasPrefix(literal, head+"?") {
			return true
		}
	}
	return false
}

// TestServedAssetsSpeakTheCurrentWire pins the shapes the assets send and read.
// Each of these is something the pre-0.2.0 assets got wrong.
func TestServedAssetsSpeakTheCurrentWire(t *testing.T) {
	banned := []struct {
		pattern *regexp.Regexp
		why     string
	}{
		{regexp.MustCompile(`\btenant_id\b`), "request fields are camelCase: tenantId"},
		{regexp.MustCompile(`\buser_id\b`), "request fields are camelCase: userId"},
		{regexp.MustCompile(`\bnew_password\b`), "reset-password takes `password`; change-password takes `newPassword`"},
		{regexp.MustCompile(`\bcurrent_password\b`), "request fields are camelCase: currentPassword"},
		{regexp.MustCompile(`\brefresh_token\b`), "request fields are camelCase: refreshToken"},
		{regexp.MustCompile(`\baccess_token\b`), "response fields are camelCase: accessToken"},
		{regexp.MustCompile(`\bnew_email\b`), "request fields are camelCase: newEmail"},
		{regexp.MustCompile(`\bexpires_in\b`), "the token response carries no lifetime; read exp from the JWT"},
		{regexp.MustCompile(`\.tokens\b`), "there is no `tokens` object: bearer callers get top-level accessToken/refreshToken"},
	}

	for _, asset := range []string{"ui/auth.js", "ui/auth.html", "ui/admin.html"} {
		t.Run(asset, func(t *testing.T) {
			source := assetSource(t, asset)
			for _, b := range banned {
				if loc := b.pattern.FindStringIndex(source); loc != nil {
					t.Errorf("%s still uses %q — %s", asset, source[loc[0]:loc[1]], b.why)
				}
			}
		})
	}
}

// TestAuthJSHonoursTheCookieContract pins the three things that make the SDK a
// working cookie client: it sends credentials, it mirrors the CSRF cookie into
// the header, and it reads that cookie with the family's name priority.
func TestAuthJSHonoursTheCookieContract(t *testing.T) {
	source := assetSource(t, "ui/auth.js")

	for _, required := range []string{
		"'include'",
		"credentials",
		CSRFHeaderName,
		hostCookiePrefix + CSRFTokenCookieName,
		secureCookiePrefix + CSRFTokenCookieName,
		AuthStrategyHeader,
		CodeSessionRevoked,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("auth.js does not mention %q", required)
		}
	}

	// The bearer opt-in has to send the header value the server compares
	// literally; "Bearer" would silently select cookie delivery instead.
	if !strings.Contains(source, "'"+AuthStrategyBearer+"'") {
		t.Errorf("auth.js must send the exact strategy value %q", AuthStrategyBearer)
	}
}
