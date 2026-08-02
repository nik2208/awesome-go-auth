package auth

import (
	"net/http"
	"strings"
)

// CSRFConfig configures cookie+header double-submit CSRF protection.
type CSRFConfig struct {
	APIPrefix      string
	CookieName     string
	HeaderName     string
	CookieSecure   bool
	CookieSameSite http.SameSite
}

// DefaultCSRFConfig returns defaults compatible with browser cookie auth flows.
func DefaultCSRFConfig(apiPrefix string) CSRFConfig {
	return CSRFConfig{
		APIPrefix:      apiPrefix,
		CookieName:     "csrf-token",
		HeaderName:     "X-CSRF-Token",
		CookieSecure:   true,
		CookieSameSite: http.SameSiteLaxMode,
	}
}

// CSRFMiddleware validates mutating browser requests using the double-submit pattern.
func CSRFMiddleware(cfg CSRFConfig) func(http.Handler) http.Handler {
	prefix := strings.TrimSpace(cfg.APIPrefix)
	if prefix == "" {
		prefix = "/auth"
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		cookieName = "csrf-token"
	}
	headerName := strings.TrimSpace(cfg.HeaderName)
	if headerName == "" {
		headerName = "X-CSRF-Token"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if c, err := r.Cookie(cookieName); err == nil {
				token = strings.TrimSpace(c.Value)
			}
			if token == "" {
				var err error
				token, err = randomToken(24)
				if err != nil {
					http.Error(w, "csrf token generation failed", http.StatusInternalServerError)
					return
				}
			}

			http.SetCookie(w, &http.Cookie{
				Name:  cookieName,
				Value: token,
				Path:  "/",
				// Not HttpOnly by design: browser JS must read it and mirror in X-CSRF-Token.
				// In production keep CookieSecure=true to avoid leakage over plain HTTP.
				HttpOnly: false,
				Secure:   cfg.CookieSecure,
				SameSite: cfg.CookieSameSite,
			})

			if !strings.HasPrefix(r.URL.Path, prefix) || !isMutatingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if shouldSkipCSRFFlow(r.URL.Path, prefix) || csrfBearerToken(r.Header.Get("Authorization")) != "" {
				next.ServeHTTP(w, r)
				return
			}
			headerToken := strings.TrimSpace(r.Header.Get(headerName))
			if headerToken == "" || !csrfTokenEqual(headerToken, token) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func csrfBearerToken(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func csrfTokenEqual(a, b string) bool {
	return secureEqual(a, b)
}

func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func shouldSkipCSRFFlow(path, prefix string) bool {
	rel := strings.TrimPrefix(path, prefix)
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	switch rel {
	case "/login",
		"/register",
		"/refresh",
		"/forgot-password",
		"/reset-password",
		"/magic-link/send",
		"/magic-link/verify",
		"/sms/send",
		"/sms/verify",
		"/link-request",
		"/link-verify":
		return true
	default:
		return strings.HasPrefix(rel, "/oauth/")
	}
}
