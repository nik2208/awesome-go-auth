package nethttp

import (
	"context"
	"encoding/json"
	"net/http"

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
	cfg  auth.HTTPConfig
}

// New returns a net/http adapter using the default wire conventions.
func New(a *auth.Auth) *Adapter {
	return NewWithConfig(a, auth.DefaultHTTPConfig())
}

// NewWithConfig returns a net/http adapter using the supplied wire conventions.
func NewWithConfig(a *auth.Auth, cfg auth.HTTPConfig) *Adapter {
	return &Adapter{auth: a, cfg: a.ResolveHTTPConfig(cfg)}
}

// Config reports the resolved wire conventions this adapter serves.
func (a *Adapter) Config() auth.HTTPConfig { return a.cfg }

// Middleware validates access tokens and injects the authenticated user in context.
func Middleware(a *auth.Auth) func(http.Handler) http.Handler {
	return New(a).Middleware()
}

// Mount attaches auth endpoints to the provided mux.
func Mount(mux *http.ServeMux, a *auth.Auth) {
	New(a).Mount(mux)
}

// MountWithConfig attaches auth endpoints using the supplied wire conventions.
func MountWithConfig(mux *http.ServeMux, a *auth.Auth, cfg auth.HTTPConfig) {
	NewWithConfig(a, cfg).Mount(mux)
}

// Middleware validates access tokens and injects user context.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken := auth.AccessTokenFromRequest(r)
			if accessToken == "" {
				auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
				return
			}
			user, err := a.auth.Me(r.Context(), accessToken)
			if err != nil {
				auth.WriteHTTPError(w, auth.AccessHTTPError(err))
				return
			}
			ctx := context.WithValue(r.Context(), userContextKey{}, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Mount attaches auth endpoints.
func (a *Adapter) Mount(mux *http.ServeMux) {
	prefix := a.cfg.Prefix()
	mux.Handle("POST "+prefix+"/register", a.guard(http.HandlerFunc(a.Register)))
	mux.Handle("POST "+prefix+"/login", a.guard(http.HandlerFunc(a.Login)))
	mux.Handle("POST "+prefix+"/refresh", a.guard(http.HandlerFunc(a.Refresh)))
	mux.Handle("POST "+prefix+"/logout", a.guard(http.HandlerFunc(a.Logout)))
	mux.Handle("GET "+prefix+"/me", a.guard(a.Middleware()(http.HandlerFunc(a.Me))))
	mux.Handle("GET "+prefix+"/sessions", a.guard(a.Middleware()(http.HandlerFunc(a.Sessions))))
	mux.Handle("DELETE "+prefix+"/sessions/{handle}", a.guard(a.Middleware()(http.HandlerFunc(a.RevokeSession))))
	mux.Handle("POST "+prefix+"/sessions/cleanup", a.guard(http.HandlerFunc(a.CleanupSessions)))
	mux.Handle("PATCH "+prefix+"/profile", a.guard(a.Middleware()(http.HandlerFunc(a.UpdateProfile))))
	mux.Handle("POST "+prefix+"/add-phone", a.guard(a.Middleware()(http.HandlerFunc(a.AddPhone))))
	mux.Handle("DELETE "+prefix+"/account", a.guard(a.Middleware()(http.HandlerFunc(a.DeleteAccount))))
	// OAuth and account linking; handlers in oauth.go.
	mux.Handle("GET "+prefix+"/oauth/{provider}", a.OAuthAuthorizeHandler())
	mux.Handle("GET "+prefix+"/oauth/{provider}/callback", a.OAuthCallbackHandler())
	mux.Handle("GET "+prefix+"/linked-accounts", a.LinkedAccountsHandler())
	mux.Handle("DELETE "+prefix+"/linked-accounts/{provider}/{providerAccountId}", a.UnlinkAccountHandler())
	mux.Handle("POST "+prefix+"/link-request", a.LinkRequestHandler())
	mux.Handle("POST "+prefix+"/link-verify", a.LinkVerifyHandler())

	// Passwordless and 2FA (passwordless.go). The four send/verify routes are
	// unauthenticated by contract; the three enrolment routes sit behind the
	// access-token middleware and are therefore the only ones CSRF-checked.
	mux.Handle("POST "+prefix+"/magic-link/send", a.guard(http.HandlerFunc(a.MagicLinkSend)))
	mux.Handle("POST "+prefix+"/magic-link/verify", a.guard(http.HandlerFunc(a.MagicLinkVerify)))
	mux.Handle("POST "+prefix+"/sms/send", a.guard(http.HandlerFunc(a.SMSSend)))
	mux.Handle("POST "+prefix+"/sms/verify", a.guard(http.HandlerFunc(a.SMSVerify)))
	mux.Handle("POST "+prefix+"/2fa/setup", a.guard(a.Middleware()(http.HandlerFunc(a.TwoFactorSetup))))
	mux.Handle("POST "+prefix+"/2fa/verify-setup", a.guard(a.Middleware()(http.HandlerFunc(a.TwoFactorVerifySetup))))
	mux.Handle("POST "+prefix+"/2fa/verify", a.guard(http.HandlerFunc(a.TwoFactorVerify)))
	mux.Handle("POST "+prefix+"/2fa/disable", a.guard(a.Middleware()(http.HandlerFunc(a.TwoFactorDisable))))
	// Password management and email verification (wire-contract §2). Handlers in
	// password_email.go.
	mux.Handle("POST "+prefix+"/forgot-password", a.guard(http.HandlerFunc(a.ForgotPassword)))
	mux.Handle("POST "+prefix+"/reset-password", a.guard(http.HandlerFunc(a.ResetPassword)))
	mux.Handle("POST "+prefix+"/change-password", a.guard(a.Middleware()(http.HandlerFunc(a.ChangePassword))))
	mux.Handle("POST "+prefix+"/send-verification-email", a.guard(a.Middleware()(http.HandlerFunc(a.SendVerificationEmail))))
	mux.Handle("GET "+prefix+"/verify-email", a.guard(http.HandlerFunc(a.VerifyEmail)))
	mux.Handle("POST "+prefix+"/change-email/request", a.guard(a.Middleware()(http.HandlerFunc(a.ChangeEmailRequest))))
	mux.Handle("POST "+prefix+"/change-email/confirm", a.guard(http.HandlerFunc(a.ChangeEmailConfirm)))
}

// guard wraps a mounted route in the CSRF middleware, which also distributes
// the CSRF cookie the browser clients read.
func (a *Adapter) guard(h http.Handler) http.Handler {
	return auth.CSRFMiddleware(a.cfg)(h)
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

// Register handles POST <prefix>/register.
func (a *Adapter) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, tokens, err := a.auth.Register(r.Context(), auth.RegisterInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusCreated, tokens, map[string]any{"userId": user.ID})
}

// Login handles POST <prefix>/login.
func (a *Adapter) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, tokens, err := a.auth.Login(r.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, tokens, nil)
}

// Refresh handles POST <prefix>/refresh.
func (a *Adapter) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := auth.RefreshTokenFromRequest(r)
	if refreshToken == "" {
		auth.WriteHTTPError(w, auth.HTTPErrNoRefreshToken)
		return
	}
	tokens, err := a.auth.Refresh(r.Context(), refreshToken)
	if err != nil {
		auth.WriteHTTPError(w, auth.RefreshHTTPError(err))
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, tokens, nil)
}

// Logout handles POST <prefix>/logout.
func (a *Adapter) Logout(w http.ResponseWriter, r *http.Request) {
	// Best effort, as in the reference: an absent or already-unusable token must
	// still leave the caller logged out rather than stranded with live cookies.
	a.auth.LogoutRequest(r.Context(), r)
	a.cfg.Cookies.ClearAuthCookies(w, a.cfg.CSRF.Enabled)
	auth.WriteSuccess(w, http.StatusOK, nil)
}

// Me handles GET <prefix>/me. The user object is the whole body: the family
// clients read it unwrapped.
func (a *Adapter) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
		return
	}
	auth.WriteJSON(w, http.StatusOK, auth.NewPublicUser(user))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		auth.WriteHTTPError(w, auth.HTTPErrInvalidBody)
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		auth.WriteHTTPError(w, auth.HTTPErrInvalidBody)
		return false
	}
	return true
}
