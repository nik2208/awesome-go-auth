package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

type userContextKey struct{}

// UserFromContext reads authenticated user data from context.
func UserFromContext(ctx context.Context) (auth.User, bool) {
	user, ok := ctx.Value(userContextKey{}).(auth.User)
	return user, ok
}

// Adapter exposes standard net/http handlers and middleware.
type Adapter struct {
	auth *auth.Auth
}

// New returns a net/http adapter for the provided auth instance.
func New(a *auth.Auth) *Adapter {
	return &Adapter{auth: a}
}

// Middleware validates access tokens and injects the authenticated user in context.
func Middleware(a *auth.Auth) func(http.Handler) http.Handler {
	adapter := New(a)
	return adapter.Middleware()
}

// Mount attaches auth endpoints to the provided mux.
func Mount(mux *http.ServeMux, a *auth.Auth) {
	adapter := New(a)
	adapter.Mount(mux)
}

// Middleware validates access tokens and injects user context.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken := accessTokenFromRequest(r)
			if accessToken == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			user, err := a.auth.Me(r.Context(), accessToken)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userContextKey{}, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Mount attaches auth endpoints.
func (a *Adapter) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/register", a.Register)
	mux.HandleFunc("POST /auth/login", a.Login)
	mux.HandleFunc("POST /auth/refresh", a.Refresh)
	mux.HandleFunc("POST /auth/logout", a.Logout)
	mux.Handle("GET /auth/me", a.Middleware()(http.HandlerFunc(a.Me)))
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenantId"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenantId"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Register handles POST /auth/register.
func (a *Adapter) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, tokens, err := a.auth.Register(r.Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		writeError(w, err)
		return
	}
	setAuthCookies(w, tokens)
	writeJSON(w, http.StatusCreated, map[string]any{"user": auth.NewPublicUser(user), "tokens": tokens})
}

// Login handles POST /auth/login.
func (a *Adapter) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, tokens, err := a.auth.Login(r.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		writeError(w, err)
		return
	}
	setAuthCookies(w, tokens)
	writeJSON(w, http.StatusOK, map[string]any{"user": auth.NewPublicUser(user), "tokens": tokens})
}

// Refresh handles POST /auth/refresh.
func (a *Adapter) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if refreshToken == "" {
		var req refreshRequest
		if decodeJSON(w, r, &req) {
			refreshToken = strings.TrimSpace(req.RefreshToken)
		}
	}
	if refreshToken == "" {
		http.Error(w, "missing refresh token", http.StatusBadRequest)
		return
	}
	tokens, err := a.auth.Refresh(r.Context(), refreshToken)
	if err != nil {
		writeError(w, err)
		return
	}
	setAuthCookies(w, tokens)
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// Logout handles POST /auth/logout.
func (a *Adapter) Logout(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if refreshToken == "" {
		var req refreshRequest
		if decodeJSON(w, r, &req) {
			refreshToken = strings.TrimSpace(req.RefreshToken)
		}
	}
	if refreshToken == "" {
		http.Error(w, "missing refresh token", http.StatusBadRequest)
		return
	}
	if err := a.auth.Logout(r.Context(), refreshToken); err != nil {
		writeError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Me handles GET /auth/me.
func (a *Adapter) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": auth.NewPublicUser(user)})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return false
	}
	return true
}

func setAuthCookies(w http.ResponseWriter, tokens auth.AuthTokens) {
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: tokens.AccessToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(tokens.ExpiresIn)})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: tokens.RefreshToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func accessTokenFromRequest(r *http.Request) string {
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	if c, err := r.Cookie("access_token"); err == nil {
		return strings.TrimSpace(c.Value)
	}
	return ""
}

func refreshTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie("refresh_token"); err == nil {
		return strings.TrimSpace(c.Value)
	}
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	return ""
}

func bearerToken(authHeader string) string {
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

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInvalidToken), errors.Is(err, auth.ErrSessionNotFound), errors.Is(err, auth.ErrSessionRevoked), errors.Is(err, auth.ErrEmailNotVerified), errors.Is(err, auth.ErrInvalidCode), errors.Is(err, auth.ErrTwoFactorRequired):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrAlreadyExists):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, auth.ErrWeakPassword):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
