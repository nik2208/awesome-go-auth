package chi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// Middleware returns a Chi-compatible auth middleware.
func Middleware(a *auth.Auth) func(http.Handler) http.Handler {
	return nethttpadapter.Middleware(a)
}

// Mount mounts auth routes onto a Chi router.
func Mount(r chi.Router, a *auth.Auth) {
	MountWithConfig(r, a, auth.DefaultHTTPConfig())
}

// MountWithConfig mounts auth routes using the supplied wire conventions.
//
// Under HTTPConfig.ResourceServer the credential routes are not registered at
// all — see mountCredentialRoutes and auth.ResourceServerGatedRoutes.
func MountWithConfig(r chi.Router, a *auth.Auth, cfg auth.HTTPConfig) {
	h := nethttpadapter.NewWithConfig(a, cfg)
	resolved := h.Config()
	prefix := resolved.Prefix()
	// guard is the outer chain every auth route below carries, in the
	// reference's order: the rate-limiter slot first, then the CSRF middleware,
	// so a refused request never reaches the double-submit comparison or the
	// auth middleware (auth.router.ts:468, :656). With no limiter configured it
	// is the CSRF middleware alone. See auth.HTTPConfig.RateLimiter.
	limit, csrf := auth.RateLimitMiddleware(resolved), auth.CSRFMiddleware(resolved)
	guard := func(next http.Handler) http.Handler { return limit(csrf(next)) }

	// IdP mode: the JWKS document, mounted first and bare — no limiter, no CSRF,
	// no auth — because the reference registers it ahead of every middleware
	// (auth.router.ts:473-474), spreads no rate limiter onto it (:490), and
	// registers it only when an idProvider block is configured
	// (:473); here that condition is auth.WithIDP. HEAD is registered next to
	// GET because chi, unlike net/http and Express, does not fall back from one
	// to the other.
	if idp := a.IDP(); idp != nil {
		jwks := a.JWKSHandler()
		r.Method(http.MethodGet, prefix+idp.JWKSPath(), jwks)
		r.Method(http.MethodHead, prefix+idp.JWKSPath(), jwks)
		// And the four OIDC endpoints beside it, from the same condition and on
		// the same terms: public, ahead of every middleware. r.Handle, not
		// r.Method, because these are mounted for every method — see
		// auth.OIDCMounts. They are the endpoints (*auth.IDP).RegisterHandlers
		// mounts, at the same paths, served by the same handlers.
		//
		// Two of them — /authorize, which takes a password, and /token, which
		// mints this instance's session pair — carry ResourceServerGated and
		// are skipped under HTTPConfig.ResourceServer, for the same reason
		// mountCredentialRoutes is. The mount stays here rather than moving into
		// that block so the two that are not gated keep their place ahead of
		// every middleware.
		for _, mount := range idp.OIDCMounts() {
			if mount.ResourceServerGated && resolved.ResourceServer {
				continue
			}
			r.Handle(prefix+mount.Path, mount.Handler)
		}
	}

	// The built-in UI, mounted only when it is enabled — the reference gates its
	// whole ui router on config.ui.enabled (auth.router.ts:1639-1648). The
	// handler arrives already wrapped in the CSRF middleware, so it mounts with
	// r.Method rather than r.With(csrf).MethodFunc.
	if resolved.UI.Enabled {
		r.Method(http.MethodGet, prefix+auth.UIConfigRoute, h.UIConfigHandler())
	}

	if !resolved.ResourceServer {
		mountCredentialRoutes(r, h, guard, prefix)
	}
	// /me authenticates itself (nethttp's Me) rather than sitting behind the
	// auth middleware, so the claims hook runs once and the token is verified once.
	r.With(guard).MethodFunc(http.MethodGet, prefix+"/me", h.Me)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodGet, prefix+"/sessions", h.Sessions)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/sessions/{handle}", h.RevokeSession)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sessions/cleanup", h.CleanupSessions)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPatch, prefix+"/profile", h.UpdateProfile)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/add-phone", h.AddPhone)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodDelete, prefix+"/account", h.DeleteAccount)

	// OAuth and account linking. These handlers arrive already wrapped in the
	// same guard — the rate-limiter slot outside the CSRF middleware — and,
	// where the route needs one, the auth middleware, so they mount with
	// r.Method rather than r.With(...).MethodFunc.
	r.Method(http.MethodGet, prefix+"/oauth/{provider}", h.OAuthAuthorizeHandler())
	r.Method(http.MethodGet, prefix+"/oauth/{provider}/callback", h.OAuthCallbackHandler())
	r.Method(http.MethodGet, prefix+"/linked-accounts", h.LinkedAccountsHandler())
	r.Method(http.MethodDelete, prefix+"/linked-accounts/{provider}/{providerAccountId}", h.UnlinkAccountHandler())
	r.Method(http.MethodPost, prefix+"/link-request", h.LinkRequestHandler())
	r.Method(http.MethodPost, prefix+"/link-verify", h.LinkVerifyHandler())
}

// mountCredentialRoutes registers the nineteen routes that create, prove,
// deliver or change a credential — auth.ResourceServerGatedRoutes, which is the
// same list and carries the reasoning. HTTPConfig.ResourceServer is the switch
// that skips this call.
func mountCredentialRoutes(r chi.Router, h *nethttpadapter.Adapter, guard func(http.Handler) http.Handler, prefix string) {
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/register", h.Register)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/login", h.Login)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/refresh", h.Refresh)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/logout", h.Logout)
	// Passwordless and 2FA. Chi serves the net/http handlers unchanged, so the
	// only chi-specific part is the registration.
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/magic-link/send", h.MagicLinkSend)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/magic-link/verify", h.MagicLinkVerify)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sms/send", h.SMSSend)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/sms/verify", h.SMSVerify)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/setup", h.TwoFactorSetup)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/verify-setup", h.TwoFactorVerifySetup)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/2fa/verify", h.TwoFactorVerify)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/2fa/disable", h.TwoFactorDisable)
	// Password management and email verification (wire-contract §2).
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/forgot-password", h.ForgotPassword)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/reset-password", h.ResetPassword)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-password", h.ChangePassword)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/send-verification-email", h.SendVerificationEmail)
	r.With(guard).MethodFunc(http.MethodGet, prefix+"/verify-email", h.VerifyEmail)
	r.With(guard, h.Middleware()).MethodFunc(http.MethodPost, prefix+"/change-email/request", h.ChangeEmailRequest)
	r.With(guard).MethodFunc(http.MethodPost, prefix+"/change-email/confirm", h.ChangeEmailConfirm)
}
