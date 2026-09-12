package nethttp

import (
	"context"
	"encoding/json"
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// UserFromContext reads authenticated user data from context.
//
// The key belongs to the root package (auth.ContextWithUser), so a middleware
// written there — auth.ResourceServerMiddleware — hands its principal to a
// handler mounted here without either side knowing about the other.
func UserFromContext(ctx context.Context) (auth.User, bool) {
	return auth.UserFromContext(ctx)
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
//
// It authenticates through Auth.Authenticate, not Auth.Me: the user in context
// carries the stores' enrichment (metadata, roles, permissions, tenants) but
// not CustomClaims, because Config.BuildTokenClaims is a mint-time hook — with
// a ClaimsWebhook behind it, one network round trip per protected request if
// the middleware ran it. GET /me is the one route that does; see Me.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessToken := auth.AccessTokenFromRequest(r)
			if accessToken == "" {
				auth.WriteHTTPError(w, auth.HTTPErrNoAccessToken)
				return
			}
			user, err := a.auth.Authenticate(r.Context(), accessToken)
			if err != nil {
				auth.WriteHTTPError(w, auth.AccessHTTPError(err))
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.ContextWithUser(r.Context(), user)))
		})
	}
}

// Mount attaches auth endpoints.
//
// Under HTTPConfig.ResourceServer the credential routes are not registered at
// all — see mountCredentialRoutes and auth.ResourceServerGatedRoutes.
func (a *Adapter) Mount(mux *http.ServeMux) {
	prefix := a.cfg.Prefix()
	// IdP mode: the JWKS document, mounted first and bare. The reference
	// registers it before every middleware so that it is always public
	// (auth.router.ts:473-474), spreads no rate limiter onto it (:490), and
	// registers it only when an idProvider block is configured
	// (:473); here that condition is auth.WithIDP. GET only, as there; net/http
	// routes HEAD to a GET pattern itself, which is Express's own fallback from
	// HEAD to the GET handler.
	if idp := a.auth.IDP(); idp != nil {
		mux.Handle("GET "+prefix+idp.JWKSPath(), a.auth.JWKSHandler())
		// And the four OIDC endpoints beside it, from the same condition and on
		// the same terms: public, ahead of the CSRF and auth middleware, for
		// every method — auth.OIDCMounts says why that is the method set. These
		// four have no counterpart in the reference; they are the endpoints
		// (*auth.IDP).RegisterHandlers mounts, at the same paths, now inside the
		// mount the conformance suite exercises. A host that also calls
		// RegisterHandlers on this mux with this prefix registers the identical
		// pattern twice and ServeMux panics; see that method.
		//
		// Two of them — /authorize, which takes a password, and /token, which
		// mints this instance's session pair — carry ResourceServerGated and
		// are skipped under HTTPConfig.ResourceServer, for the same reason the
		// credential routes below are. The mount stays here rather than moving
		// into that block so the two that are not gated keep their place ahead
		// of every middleware.
		for _, mount := range idp.OIDCMounts() {
			if mount.ResourceServerGated && a.cfg.ResourceServer {
				continue
			}
			mux.Handle(prefix+mount.Path, mount.Handler)
		}
	}

	if !a.cfg.ResourceServer {
		a.mountCredentialRoutes(mux, prefix)
	}
	// /me authenticates itself (see Me) rather than sitting behind Middleware,
	// so the token is verified once and the claims hook runs once.
	mux.Handle("GET "+prefix+"/me", a.guard(http.HandlerFunc(a.Me)))
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
}

// mountCredentialRoutes registers the nineteen routes that create, prove,
// deliver or change a credential — auth.ResourceServerGatedRoutes, which is the
// same list and carries the reasoning. HTTPConfig.ResourceServer is the switch
// that skips this call.
func (a *Adapter) mountCredentialRoutes(mux *http.ServeMux, prefix string) {
	mux.Handle("POST "+prefix+"/register", a.guard(http.HandlerFunc(a.Register)))
	mux.Handle("POST "+prefix+"/login", a.guard(http.HandlerFunc(a.Login)))
	mux.Handle("POST "+prefix+"/refresh", a.guard(http.HandlerFunc(a.Refresh)))
	mux.Handle("POST "+prefix+"/logout", a.guard(http.HandlerFunc(a.Logout)))

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

// guard wraps a mounted route in the outer chain every auth route carries: the
// rate-limiter slot, then the CSRF middleware, which also distributes the CSRF
// cookie the browser clients read.
//
// The order is the reference's. It spreads its rate limiter onto each route
// ahead of the auth middleware (auth.router.ts:468, :656), so a refusal is
// answered before any token is verified, any store is read or any double-submit
// pair is compared. HTTPConfig.RateLimiter carries the rest of the reasoning;
// with no limiter configured this is the CSRF middleware alone, unchanged.
//
// It wraps every route of the auth router, which is what the reference spreads
// ...rl onto, and not the JWKS document, which is mounted bare above as it is
// there (:490). The one place the two lines do not coincide is the OAuth pair
// when the provider is not configured: the reference swaps in bare 404 stubs
// carrying no rl (:1361-1362, :1407-1408) where this port keeps the guarded
// handler and decides inside it. See auth.HTTPConfig.RateLimiter.
func (a *Adapter) guard(h http.Handler) http.Handler {
	return auth.RateLimitMiddleware(a.cfg)(auth.CSRFMiddleware(a.cfg)(h))
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
	result, err := a.auth.LoginWithChallenge(r.Context(), auth.LoginInput{Email: req.Email, Password: req.Password, TenantID: req.TenantID})
	if err != nil {
		auth.WriteServiceError(w, err)
		return
	}
	// A second factor is not a failure: the challenge is its own body, carrying the
	// tempToken the step-up routes need. See login_2fa.go.
	if result.Challenge != nil {
		auth.WriteTwoFactorChallenge(w, *result.Challenge)
		return
	}
	a.cfg.WriteTokens(w, r, http.StatusOK, result.Tokens, nil)
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
//
// The handler authenticates itself through Auth.Me — Authenticate plus
// Config.BuildTokenClaims — rather than reading the user Middleware put in
// context, because Middleware deliberately skips the hook and this body is the
// one place its result (customClaims) is rendered. Mounted bare, as Mount does,
// the token is verified once and the hook runs once; mounted behind Middleware
// by a host anyway, the body is the same and the token is verified twice.
func (a *Adapter) Me(w http.ResponseWriter, r *http.Request) {
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
