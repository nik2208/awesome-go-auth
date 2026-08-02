package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// csrfTokenBytes is the reference's token size: 16 random bytes rendered as 32
// hex characters.
const csrfTokenBytes = 16

// randomHex renders byteLen random bytes as hex. The CSRF token uses it rather
// than randomToken because the family clients are pinned to a hex token.
func randomHex(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random hex: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CSRFConfig configures the cookie+header double-submit CSRF protection. The
// cookie attributes come from HTTPConfig.Cookies so that the CSRF cookie is
// serialised by the same matrix as the token cookies.
type CSRFConfig struct {
	// Enabled gates both enforcement and cookie distribution, mirroring the
	// reference's config.csrf.enabled.
	Enabled    bool
	CookieName string
	HeaderName string
}

// DefaultCSRFConfig returns defaults compatible with browser cookie auth flows.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		Enabled:    true,
		CookieName: CSRFTokenCookieName,
		HeaderName: CSRFHeaderName,
	}
}

// csrfExemptPaths are the routes the reference mounts without its auth
// middleware. CSRF is enforced inside that middleware, so these routes are
// never checked — including /logout, which the reference deliberately leaves
// unprotected so that a client with a stale CSRF cookie can still log out.
//
// This table is the contract for every route added later: a mutating route that
// is absent from it is CSRF-checked, so leaving an unauthenticated route out
// breaks it and putting an authenticated one in silently unprotects it. It is
// pinned literal-by-literal by TestCSRFExemptionsMatchTheReference.
//
// Three entries are not simply "routes without the auth middleware":
//   - /2fa/verify is a pre-login step-up call with no auth gate, so the
//     reference never CSRF-checks it (wire-contract §3, "CSRF does not apply
//     to: … /2fa/verify").
//   - /change-email/confirm has no auth gate either: the emailed token is the
//     credential, so the link has to work from a browser with no session and no
//     CSRF cookie at all (auth.router.ts:1040-1067).
//   - /link-request is deliberately NOT here. It has no auth middleware but the
//     reference performs its own manual double-submit check inside the handler
//     (auth.router.ts:1489-1495), so it is the one unauthenticated route that
//     is CSRF-protected.
var csrfExemptPaths = map[string]bool{
	"/login":                true,
	"/register":             true,
	"/refresh":              true,
	"/logout":               true,
	"/forgot-password":      true,
	"/reset-password":       true,
	"/verify-email":         true,
	"/change-email/confirm": true,
	"/magic-link/send":      true,
	"/magic-link/verify":    true,
	"/sms/send":             true,
	"/sms/verify":           true,
	"/2fa/verify":           true,
	"/link-verify":          true,
	"/sessions/cleanup":     true,
}

// CSRFMiddleware distributes and enforces the double-submit token.
//
// Distribution mirrors the reference's router-level auto-init: a request that
// arrives without a readable CSRF cookie gets a fresh one. Enforcement follows
// the reference matrix — only cookie-authenticated unsafe methods on routes
// that sit behind the auth middleware are checked; safe methods, bearer
// requests and the unauthenticated routes above are exempt.
func CSRFMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	cfg = cfg.resolve(0, 0)
	prefix := cfg.Prefix()
	cookieName := cfg.CSRF.CookieName
	headerName := cfg.CSRF.HeaderName

	return func(next http.Handler) http.Handler {
		if !cfg.CSRF.Enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A bearer caller is not a cookie client: it cannot be driven by a
			// cross-site form post, and it never reads the CSRF cookie. Skipping
			// it here is what makes "bearer requests set no cookies" true of the
			// whole response and not just of the token delivery.
			if isBearerClient(r) {
				next.ServeHTTP(w, r)
				return
			}
			token := CookieValue(r, cookieName)
			if token == "" {
				fresh, err := randomHex(csrfTokenBytes)
				if err != nil {
					WriteHTTPError(w, HTTPErrInternal)
					return
				}
				token = fresh
				cfg.Cookies.SetCSRFTokenCookie(w, token)
			}

			if !csrfEnforced(r, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			headerToken := strings.TrimSpace(r.Header.Get(headerName))
			if headerToken == "" || !secureEqual(headerToken, token) {
				WriteHTTPError(w, HTTPErrCSRFInvalid)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isBearerClient reports whether the caller authenticates with a bearer token
// or asked for bearer delivery.
func isBearerClient(r *http.Request) bool {
	return IsBearerRequest(r) || BearerToken(r.Header.Get("Authorization")) != ""
}

func csrfEnforced(r *http.Request, prefix string) bool {
	if !isMutatingMethod(r.Method) {
		return false
	}
	rel, mounted := csrfRelativePath(r.URL.Path, prefix)
	if !mounted {
		return false
	}
	return !csrfExemptPaths[rel]
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// csrfRelativePath locates the mount prefix inside a request path and returns
// the route below it.
//
// The prefix has to land on a segment boundary — "/authenticate/login" is not
// "/auth" plus "enticate/login" — and it may sit after a base path, because a
// host app that mounts the adapter on a gin/echo group or a chi Route serves
// <base><prefix>/<route> while the middleware only ever knows <prefix>. Matching
// on the head of the path alone would leave every group-mounted deployment with
// enforcement silently switched off.
func csrfRelativePath(path, prefix string) (string, bool) {
	if prefix == "" || prefix == "/" {
		return strings.TrimSuffix(path, "/"), true
	}
	for i := 0; i+len(prefix) <= len(path); i++ {
		offset := strings.Index(path[i:], prefix)
		if offset < 0 {
			return "", false
		}
		i += offset
		rest := path[i+len(prefix):]
		if rest == "" || strings.HasPrefix(rest, "/") {
			return strings.TrimSuffix(rest, "/"), true
		}
	}
	return "", false
}
