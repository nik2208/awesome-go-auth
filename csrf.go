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
var csrfExemptPaths = map[string]bool{
	"/login":             true,
	"/register":          true,
	"/refresh":           true,
	"/logout":            true,
	"/forgot-password":   true,
	"/reset-password":    true,
	"/verify-email":      true,
	"/magic-link/send":   true,
	"/magic-link/verify": true,
	"/sms/send":          true,
	"/sms/verify":        true,
	"/link-request":      true,
	"/link-verify":       true,
	"/sessions/cleanup":  true,
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
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	return !csrfExemptPaths[csrfRelativePath(r.URL.Path, prefix)]
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func csrfRelativePath(path, prefix string) string {
	rel := strings.TrimPrefix(path, prefix)
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return strings.TrimSuffix(rel, "/")
}
