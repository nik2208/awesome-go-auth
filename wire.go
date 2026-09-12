package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// This file holds the HTTP conventions every adapter shares: the response
// envelope, the cookie serialisation matrix, the error catalog and the
// bearer-vs-cookie delivery switch. They live in the root package rather than
// in one adapter so that net/http, chi, gin and echo cannot drift apart, and so
// that routes added later only have to call them.
//
// The shapes are the family wire contract as implemented by awesome-node-auth
// @cc01e997 (the reference the shipped Angular, Flutter and auth.js clients are
// pinned to). Deviations are called out where they exist.

// DefaultAPIPrefix is where the auth routes mount unless told otherwise.
const DefaultAPIPrefix = "/auth"

const (
	// AuthStrategyHeader opts a caller into bearer delivery. The reference reads
	// this header in exactly one place and compares the value exactly, so the
	// match here is case-sensitive on purpose.
	AuthStrategyHeader = "X-Auth-Strategy"
	// AuthStrategyBearer is the only recognised AuthStrategyHeader value.
	AuthStrategyBearer = "bearer"
	// CSRFHeaderName carries the double-submit token.
	CSRFHeaderName = "X-CSRF-Token"
)

// Cookie base names. The prefix a cookie actually carries is resolved by
// CookieOptions.CookieName.
const (
	AccessTokenCookieName  = "accessToken"
	RefreshTokenCookieName = "refreshToken"
	CSRFTokenCookieName    = "csrf-token"

	hostCookiePrefix   = "__Host-"
	secureCookiePrefix = "__Secure-"
)

// IsBearerRequest reports whether the caller asked for token delivery in the
// response body instead of cookies.
func IsBearerRequest(r *http.Request) bool {
	return r != nil && r.Header.Get(AuthStrategyHeader) == AuthStrategyBearer
}

// Error codes emitted by the HTTP layer. The first block is the reference
// catalog; a client keying on any of these keeps working across the family.
const (
	CodeInvalidCredentials  = "INVALID_CREDENTIALS"
	CodeEmailNotVerified    = "EMAIL_NOT_VERIFIED"
	CodeSessionRevoked      = "SESSION_REVOKED"
	CodeInvalidToken        = "INVALID_TOKEN"
	CodeInvalidRefreshToken = "INVALID_REFRESH_TOKEN"
	CodeCSRFInvalid         = "CSRF_INVALID"
	CodeTwoFactorRequired   = "2FA_REQUIRED"
	CodeUserNotFound        = "USER_NOT_FOUND"
	CodeNotImplemented      = "NOT_IMPLEMENTED"
)

// Codes with no counterpart in the reference catalog. The reference delegates
// registration to a host-supplied callback and therefore has no code of its own
// for a duplicate address or a rejected password; these fill that hole. No
// shipped client branches on them.
const (
	CodeUserExists   = "USER_EXISTS"
	CodeWeakPassword = "WEAK_PASSWORD"
	CodeInvalidBody  = "INVALID_BODY"
)

// HTTPError is the family error envelope together with its status code.
//
// The "code" field is omitted when the reference emits no code for that
// failure; clients are documented not to pattern-match on an absent code.
type HTTPError struct {
	Status  int    `json:"-"`
	Message string `json:"error"`
	Code    string `json:"code,omitempty"`
}

func (e HTTPError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

// The error catalog. Messages are the reference's own strings, because a client
// that surfaces the server message must not read differently per implementation.
var (
	// HTTPErrNoAccessToken and HTTPErrInvalidAccessToken are 403 and carry no
	// code. That looks wrong next to the 401s around them, but it is what the
	// reference middleware emits and the clients are built against it.
	HTTPErrNoAccessToken      = HTTPError{Status: http.StatusForbidden, Message: "No access token provided"}
	HTTPErrInvalidAccessToken = HTTPError{Status: http.StatusForbidden, Message: "Invalid or expired access token"}

	// HTTPErrSessionRevoked is the family's fast-logout signal: both browser
	// clients stop refreshing and log out on this exact code, so nothing else
	// may be returned for a revoked session.
	HTTPErrSessionRevoked = HTTPError{Status: http.StatusUnauthorized, Message: "Session has been revoked", Code: CodeSessionRevoked}

	HTTPErrNoRefreshToken      = HTTPError{Status: http.StatusUnauthorized, Message: "No refresh token provided"}
	HTTPErrInvalidRefreshToken = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid refresh token"}
	HTTPErrExpiredRefreshToken = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired refresh token", Code: CodeInvalidRefreshToken}

	HTTPErrInvalidCredentials = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid credentials", Code: CodeInvalidCredentials}
	HTTPErrEmailNotVerified   = HTTPError{Status: http.StatusForbidden, Message: "Email address is not verified", Code: CodeEmailNotVerified}
	HTTPErrTwoFactorRequired  = HTTPError{Status: http.StatusForbidden, Message: "Two-factor authentication required", Code: CodeTwoFactorRequired}
	HTTPErrInvalidToken       = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired token", Code: CodeInvalidToken}
	HTTPErrCSRFInvalid        = HTTPError{Status: http.StatusForbidden, Message: "CSRF token validation failed", Code: CodeCSRFInvalid}
	// HTTPErrUserNotFound carries no code: every reference site that emits the
	// literal "User not found" emits it code-less (GET /me, /change-password,
	// /sms/send, the magic-link 2fa branch). The one coded USER_NOT_FOUND in the
	// reference is a different message ("Target user not found", /link-request),
	// so a route reusing this value must not gain a code by accident.
	HTTPErrUserNotFound   = HTTPError{Status: http.StatusNotFound, Message: "User not found"}
	HTTPErrNotImplemented = HTTPError{Status: http.StatusNotImplemented, Message: "Feature not supported by the configured stores", Code: CodeNotImplemented}

	// HTTPErrInternal deliberately carries neither a code nor the underlying
	// error text: an unexpected failure must not describe itself to the caller.
	HTTPErrInternal = HTTPError{Status: http.StatusInternalServerError, Message: "Internal server error"}

	HTTPErrUserExists   = HTTPError{Status: http.StatusConflict, Message: "User already exists", Code: CodeUserExists}
	HTTPErrWeakPassword = HTTPError{Status: http.StatusBadRequest, Message: "Password is too weak", Code: CodeWeakPassword}
	HTTPErrInvalidBody  = HTTPError{Status: http.StatusBadRequest, Message: "Invalid request body", Code: CodeInvalidBody}
)

// HTTPErrorFor maps a service sentinel onto the envelope. Routes whose failure
// means something more specific than the sentinel says — /refresh and the auth
// middleware both narrow "invalid token" — use their own mapper below.
//
// Anything unmapped becomes a 500, so a sentinel that reaches a route before it
// reaches this switch turns a client-visible failure into an internal error.
// The sentinels deliberately left out are the ones whose reference wire string
// is route-specific and must not be guessed here: ErrInvalidCode is "Invalid or
// expired SMS code" on /sms/verify and "Invalid TOTP code" on /2fa/verify (both
// 401, both code-less), and ErrTenantNotFound / ErrRoleNotFound belong to admin
// routes. A route that can return one of those has to write it itself.
// TestUnmappedSentinelsAreDeliberate keeps that list honest.
func HTTPErrorFor(err error) HTTPError {
	switch {
	case err == nil:
		return HTTPError{}
	case errors.Is(err, ErrSessionRevoked):
		return HTTPErrSessionRevoked
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrInvalidCredentials
	case errors.Is(err, ErrEmailNotVerified):
		return HTTPErrEmailNotVerified
	case errors.Is(err, ErrTwoFactorRequired):
		return HTTPErrTwoFactorRequired
	case errors.Is(err, ErrUserExists), errors.Is(err, ErrAlreadyExists):
		return HTTPErrUserExists
	case errors.Is(err, ErrWeakPassword):
		return HTTPErrWeakPassword
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrNotImplemented
	case errors.Is(err, ErrEmailNotConfigured):
		return HTTPErrEmailNotConfigured
	case errors.Is(err, ErrSMSNotConfigured):
		return HTTPErrSMSNotConfigured
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidToken
	default:
		return HTTPErrInternal
	}
}

// RefreshHTTPError maps a Service.Refresh failure. A revoked session stays
// distinguishable from an unusable token, which is the whole point of the code.
func RefreshHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrSessionRevoked):
		return HTTPErrSessionRevoked
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrExpiredRefreshToken
	case errors.Is(err, ErrSessionNotFound):
		return HTTPErrInvalidRefreshToken
	default:
		return HTTPErrorFor(err)
	}
}

// AccessHTTPError maps an access-token verification failure the way the
// reference auth middleware does.
func AccessHTTPError(err error) HTTPError {
	if errors.Is(err, ErrSessionRevoked) {
		return HTTPErrSessionRevoked
	}
	return HTTPErrInvalidAccessToken
}

// WriteJSON writes payload as the entire response body.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteHTTPError writes the error envelope.
func WriteHTTPError(w http.ResponseWriter, e HTTPError) {
	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if e.Message == "" {
		e.Message = HTTPErrInternal.Message
	}
	WriteJSON(w, status, e)
}

// WriteServiceError maps a service sentinel and writes it.
func WriteServiceError(w http.ResponseWriter, err error) {
	WriteHTTPError(w, HTTPErrorFor(err))
}

// WriteSuccess writes the {"success": true} envelope, merging any extra
// top-level fields a route contributes.
func WriteSuccess(w http.ResponseWriter, status int, extra map[string]any) {
	WriteJSON(w, status, successBody(extra))
}

func successBody(extra map[string]any) map[string]any {
	body := make(map[string]any, len(extra)+1)
	body["success"] = true
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// CookieOptions is the cookie serialisation matrix. Every adapter writes
// cookies through it, so the attributes cannot diverge between frameworks.
type CookieOptions struct {
	Secure   bool
	SameSite http.SameSite
	Path     string
	Domain   string
	// RefreshTokenPath scopes the refresh cookie. Empty resolves to
	// <APIPrefix>/refresh, matching the reference's router-time default.
	RefreshTokenPath   string
	AccessTokenMaxAge  time.Duration
	RefreshTokenMaxAge time.Duration
	CSRFTokenMaxAge    time.Duration
}

// DefaultCookieOptions returns the port's defaults. Secure defaults to true —
// stricter than the reference's false — because every cookie here is either a
// credential or a CSRF token.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		Secure:          true,
		SameSite:        http.SameSiteLaxMode,
		Path:            "/",
		CSRFTokenMaxAge: 15 * time.Minute,
	}
}

// CookieName resolves the prefix a cookie must carry: an insecure cookie stays
// bare, a secure cookie that is host-scoped to "/" earns __Host-, and any other
// secure cookie earns __Secure-. The refresh cookie is resolved from Path, not
// RefreshTokenPath, exactly as the reference does.
func (o CookieOptions) CookieName(base string) string {
	if !o.Secure {
		return base
	}
	if (o.Path == "" || o.Path == "/") && o.Domain == "" {
		return hostCookiePrefix + base
	}
	return secureCookiePrefix + base
}

func (o CookieOptions) refreshPath() string {
	if p := strings.TrimSpace(o.RefreshTokenPath); p != "" {
		return p
	}
	return o.basePath()
}

func (o CookieOptions) basePath() string {
	if p := strings.TrimSpace(o.Path); p != "" {
		return p
	}
	return "/"
}

func (o CookieOptions) cookie(name, value, path string, maxAge time.Duration, httpOnly bool) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   o.Domain,
		HttpOnly: httpOnly,
		Secure:   o.Secure,
		SameSite: o.SameSite,
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if strings.HasPrefix(name, hostCookiePrefix) {
		// Browsers reject a __Host- cookie that carries a Domain, is not
		// Secure, or is not scoped to "/". The reference forces the same three
		// attributes, which is why a __Host-refreshToken loses its /refresh
		// scoping rather than being silently dropped by the browser.
		c.Domain = ""
		c.Path = "/"
		c.Secure = true
	}
	if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	}
	return c
}

// SetAccessTokenCookie writes the access-token cookie.
func (o CookieOptions) SetAccessTokenCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, o.cookie(o.CookieName(AccessTokenCookieName), value, o.basePath(), o.AccessTokenMaxAge, true))
}

// SetRefreshTokenCookie writes the refresh-token cookie.
func (o CookieOptions) SetRefreshTokenCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, o.cookie(o.CookieName(RefreshTokenCookieName), value, o.refreshPath(), o.RefreshTokenMaxAge, true))
}

// SetCSRFTokenCookie writes the CSRF cookie. It is deliberately not HttpOnly:
// double-submit requires the page to read it and mirror it into the header.
func (o CookieOptions) SetCSRFTokenCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, o.cookie(o.CookieName(CSRFTokenCookieName), value, o.basePath(), o.CSRFTokenMaxAge, false))
}

// ClearAuthCookies expires every name variant of the auth cookies. Expiring a
// cookie requires an exact name+path+domain match, so a cookie written under a
// different prefix — by an older release, or before Secure was switched on —
// would otherwise survive logout.
func (o CookieOptions) ClearAuthCookies(w http.ResponseWriter, includeCSRF bool) {
	o.clearVariants(w, AccessTokenCookieName, o.basePath(), true)
	o.clearVariants(w, RefreshTokenCookieName, o.refreshPath(), true)
	if includeCSRF {
		o.clearVariants(w, CSRFTokenCookieName, o.basePath(), false)
	}
}

func (o CookieOptions) clearVariants(w http.ResponseWriter, base, path string, httpOnly bool) {
	seen := make(map[string]bool, 3)
	for _, name := range []string{o.CookieName(base), hostCookiePrefix + base, secureCookiePrefix + base, base} {
		if seen[name] {
			continue
		}
		seen[name] = true
		c := o.cookie(name, "", path, 0, httpOnly)
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
}

// CookieValue reads a cookie honouring the family's __Host- → __Secure- → bare
// priority. Every read site must go through it, otherwise a deployment that
// switches Secure on stops recognising its own cookies.
func CookieValue(r *http.Request, base string) string {
	if r == nil {
		return ""
	}
	for _, name := range []string{hostCookiePrefix + base, secureCookiePrefix + base, base} {
		if c, err := r.Cookie(name); err == nil {
			if v := strings.TrimSpace(c.Value); v != "" {
				return v
			}
		}
	}
	return ""
}

// BearerToken extracts the token from an Authorization header.
func BearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// AccessTokenFromRequest applies the reference's extraction order: the
// Authorization header first, then the access-token cookie.
func AccessTokenFromRequest(r *http.Request) string {
	if token := BearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	return CookieValue(r, AccessTokenCookieName)
}

// HTTPConfig is the wire configuration an adapter mounts with. The four
// adapters take the same value, so a change here reaches all of them.
type HTTPConfig struct {
	APIPrefix string
	Cookies   CookieOptions
	CSRF      CSRFConfig
	// UIEnabled is the reference's config.ui.enabled as far as emailed links are
	// concerned: when set, UILink points a link at <prefix>/ui/<path> — the
	// static UI's page for it — instead of at the bare API route
	// (buildUiLink, auth.router.ts:265-266). It mounts nothing by itself; the
	// deployment that sets it serves the UI under that path.
	UIEnabled bool
	// ResourceServer mounts this instance as a resource server: an API that
	// verifies tokens another instance issued and owns no credentials of its
	// own. The adapters then register none of the routes in
	// ResourceServerGatedRoutes, so a credential route answers with whatever
	// the router returns for an unknown path — 404 on all four — instead of
	// reaching a handler that has no user database behind it.
	//
	// It changes nothing else: the routes that stay are unaffected, and the
	// bearer verification itself is ResourceServerMiddleware, which a host
	// mounts on its own routes. The reference gates six of the nineteen
	// (auth.router.ts:510, :541); gating all of them is the
	// resource-server-gates-all-credential-routes deviation.
	ResourceServer bool
	// RateLimiter is the reference's RouterOptions.rateLimiter
	// (auth.router.ts:46): the slot a host drops its own limiter into. nil —
	// the default — means no limiter, which is the reference's own default:
	// it collapses the slot to an empty middleware list when the option is
	// absent (rl, auth.router.ts:468) and ships no algorithm of its own.
	//
	// The adapters apply it to every route of the auth router, the routes the
	// reference spreads ...rl onto (auth.router.ts:541 onwards), and not to the
	// JWKS document, which is registered ahead of the whole chain and carries
	// no rl (:490).
	//
	// One pair of routes falls inside the slot here that falls outside it
	// there. When an OAuth provider is not configured the reference registers
	// bare 404 stubs in place of the real handlers, with no rl on them
	// (:1361-1362 for Google, :1407-1408 for GitHub); this port mounts one
	// always-guarded handler per OAuth route and decides on the configuration
	// inside it. Behind a limiter at its limit those two requests are therefore
	// answered 429 here and 404 there, and they consume budget here that they
	// do not consume there.
	//
	// Position in the chain is the load-bearing part. The reference puts rl
	// first on each route, ahead of the auth middleware (GET /me,
	// auth.router.ts:656) and therefore ahead of the double-submit check,
	// which the auth middleware performs and which the one route without that
	// middleware repeats by hand inside its handler (:1489-1495). A refusal
	// consequently costs nothing downstream: no token is verified, no store is
	// read, no CSRF comparison is made. The adapters reproduce that order —
	// RateLimiter outermost, then CSRFMiddleware, then the auth middleware.
	//
	// The field is a constructor, not a handler, and each adapter calls it once
	// per route at mount time — some thirty calls for one mount. Whatever the
	// limiter counts with, a bucket or a map or a store handle, therefore has
	// to be created outside this function and captured by it, the way
	// httprate.LimitByIP and the tollbooth wrappers are written. Allocating the
	// counter inside the function gives every route a private budget instead of
	// the single shared one the reference gets from passing one Express handler
	// instance to every route.
	//
	// Note for the admin router when it lands: the family's private development
	// line carries a second, separate slot on its admin router
	// (AdminOptions.rateLimiter, admin.router.ts:211, collapsed to an empty
	// list the same way at :577) and spreads it onto exactly one route, POST
	// /users/:id/promote (:1030); its admin login route (:614) carries none.
	// That path is relative to the admin router's own mount, which the host app
	// chooses and which defaults to /admin (admin.router.ts:190,
	// openapi.ts:674) — not to APIPrefix. These line numbers are in that
	// private tree and do not resolve against ReferenceRevision, which carries
	// no admin rateLimiter at all. No admin route exists here yet, so nothing
	// below implements that half.
	RateLimiter func(http.Handler) http.Handler
}

// RateLimitMiddleware returns the configured rate limiter, or a pass-through
// when HTTPConfig.RateLimiter is nil.
//
// It is the counterpart of CSRFMiddleware and the adapters compose the two in
// that order — this one outermost — so that a refused request never reaches
// either the CSRF comparison or the auth middleware. See HTTPConfig.RateLimiter
// for the reference citations.
func RateLimitMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	limiter := cfg.RateLimiter
	if limiter == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return limiter
}

// DefaultHTTPConfig returns the conventions an adapter uses when the host app
// does not configure them.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		APIPrefix: DefaultAPIPrefix,
		Cookies:   DefaultCookieOptions(),
		CSRF:      DefaultCSRFConfig(),
	}
}

// Prefix returns the normalised mount prefix.
func (c HTTPConfig) Prefix() string {
	prefix := strings.TrimSpace(c.APIPrefix)
	if prefix == "" {
		return DefaultAPIPrefix
	}
	return "/" + strings.Trim(prefix, "/")
}

// resolve fills the values derived from other values: the refresh cookie path
// follows the mount prefix, and cookie lifetimes follow the token lifetimes so
// that a cookie never outlives, or expires before, the token it carries.
func (c HTTPConfig) resolve(accessTTL, refreshTTL time.Duration) HTTPConfig {
	c.APIPrefix = c.Prefix()
	if strings.TrimSpace(c.Cookies.RefreshTokenPath) == "" {
		c.Cookies.RefreshTokenPath = c.APIPrefix + "/refresh"
	}
	if c.Cookies.Path == "" {
		c.Cookies.Path = "/"
	}
	if c.Cookies.AccessTokenMaxAge <= 0 {
		c.Cookies.AccessTokenMaxAge = accessTTL
	}
	if c.Cookies.RefreshTokenMaxAge <= 0 {
		c.Cookies.RefreshTokenMaxAge = refreshTTL
	}
	if c.Cookies.CSRFTokenMaxAge <= 0 {
		c.Cookies.CSRFTokenMaxAge = DefaultCookieOptions().CSRFTokenMaxAge
	}
	if strings.TrimSpace(c.CSRF.CookieName) == "" {
		c.CSRF.CookieName = CSRFTokenCookieName
	}
	if strings.TrimSpace(c.CSRF.HeaderName) == "" {
		c.CSRF.HeaderName = CSRFHeaderName
	}
	return c
}

// ResolveHTTPConfig fills cfg's derived defaults from this instance's token
// lifetimes. Adapters call it once at mount time.
func (a *Auth) ResolveHTTPConfig(cfg HTTPConfig) HTTPConfig {
	access, refresh := a.service.TokenTTLs()
	return cfg.resolve(access, refresh)
}

// ── emailed links ────────────────────────────────────────────────────────────
//
// The reference builds every emailed link per request, from the site URL the
// request came from and the mount prefix (auth.router.ts:785-786, 954-955,
// 1025-1026, 1104/1114). The three pieces of that are below: UILink is its
// buildUiLink, LinkBase is the base the URL builders in delivery.go take, and
// Auth.ResolveSiteURL is its resolveSiteUrl over the allowlist it derives from
// config.email.siteUrl and the CORS origins.

// UILink is the reference's buildUiLink (auth.router.ts:261-271): the link to
// path under siteURL, through the static UI when UIEnabled and straight at the
// API route otherwise.
//
//	<siteURL><prefix>/ui/<path>   when UIEnabled
//	<siteURL><prefix>/<path>      otherwise
//
// prefix is Prefix() — the reference strips one trailing slash from its
// apiPrefix (:263), which Prefix() already does along with the rest of this
// port's normalisation — and one leading slash is dropped from path (:264), so
// UILink("https://app.example.com", "/reset-password?token=t") is
// "https://app.example.com/auth/reset-password?token=t". siteURL is used as
// given: an empty one yields a relative link, exactly as the reference does
// with no siteUrl configured.
func (c HTTPConfig) UILink(siteURL, path string) string {
	prefix := strings.TrimSuffix(c.Prefix(), "/")
	path = strings.TrimPrefix(path, "/")
	if c.UIEnabled {
		return siteURL + prefix + "/ui/" + path
	}
	return siteURL + prefix + "/" + path
}

// LinkBase is the base MagicLinkURL, PasswordResetURL, EmailVerificationURL and
// EmailChangeConfirmURL take, resolved for one site URL: UILink(siteURL, "")
// with the trailing slash removed, which is what the reference does with that
// value on the one route that passes an empty path
// (magic-link.strategy.ts:25-27). "https://app.example.com" becomes
// "https://app.example.com/auth", or "https://app.example.com/auth/ui" under
// UIEnabled. The adapters put it on each delivery as LinkBase.
//
// An empty siteURL yields "" rather than the bare prefix: no site URL is known
// for the request, and a delivery with no LinkBase lets a ready-made mailer fall
// back to its static BaseURL — which a deployment configured before
// Config.SiteURLs existed relies on. The reference has no such static base and
// builds a relative link in that case; the port keeps the link that used to be
// sent.
func (c HTTPConfig) LinkBase(siteURL string) string {
	if siteURL == "" {
		return ""
	}
	return strings.TrimSuffix(c.UILink(siteURL, ""), "/")
}

// ResolveSiteURL is the reference's resolveSiteUrl (auth.router.ts:233-246) for
// one request: the Origin header when it is allowlisted, else the origin of the
// Referer when that is, else the default site URL. The result is always either
// an allowlist entry or the default, which is what keeps a caller from steering
// a link — or an OAuth redirect — at an origin of its choosing.
//
// The allowlist is buildAllowedOrigins (auth.router.ts:213-219): Config.SiteURLs
// followed by OAuthWiring.AllowedOrigins — the port's spelling of the
// reference's cors.origins for this purpose — deduplicated with the first
// occurrence's position kept. With an empty allowlist the headers are not
// consulted at all and the default is returned.
//
// The default is the first Config.SiteURLs entry (getDefaultSiteUrl,
// auth.router.ts:202-206), unless OAuthWiring.SiteURL is set: that field
// predates SiteURLs, is documented as the same first siteUrl entry, and stays
// the override so that a deployment configured through it keeps its links and
// redirects. With neither the default is "".
//
// It shares resolveSiteURL with OAuthBegin and LinkRequest, so an emailed link
// and an OAuth redirect resolve identically for the same request.
func (a *Auth) ResolveSiteURL(r *http.Request) string {
	var origin, referer string
	if r != nil {
		origin, referer = r.Header.Get("Origin"), r.Header.Get("Referer")
	}
	return resolveSiteURL(origin, referer, a.allowedOrigins(), a.defaultSiteURL())
}

// allowedOrigins is the reference's buildAllowedOrigins (auth.router.ts:213-219).
func (a *Auth) allowedOrigins() []string {
	var cors []string
	if a.oauth != nil {
		cors = a.oauth.AllowedOrigins
	}
	return dedupeOrigins(a.service.cfg.SiteURLs, cors)
}

// dedupeOrigins is `[...new Set([...fromSiteUrl, ...fromCors])]`: the lists
// concatenated in order, each value kept where it first appeared.
func dedupeOrigins(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var merged []string
	for _, list := range lists {
		for _, origin := range list {
			if _, dup := seen[origin]; dup {
				continue
			}
			seen[origin] = struct{}{}
			merged = append(merged, origin)
		}
	}
	return merged
}

// defaultSiteURL is the reference's getDefaultSiteUrl (auth.router.ts:202-206)
// with OAuthWiring.SiteURL as the override — see ResolveSiteURL.
func (a *Auth) defaultSiteURL() string {
	if a.oauth != nil && a.oauth.SiteURL != "" {
		return a.oauth.SiteURL
	}
	if urls := a.service.cfg.SiteURLs; len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// TokenTTLs reports the configured access and refresh token lifetimes. The HTTP
// layer needs them to give the auth cookies the same lifetime as the tokens
// they carry.
func (s *Service) TokenTTLs() (access, refresh time.Duration) {
	return s.cfg.AccessTokenTTL, s.cfg.RefreshTokenTTL
}

// WithSessionCheckOn selects when a session's revocation state is re-checked:
// allcalls, refresh (the default) or none. Without allcalls the auth middleware
// cannot report a revoked session, so a client that relies on the
// SESSION_REVOKED signal has to opt in here.
func WithSessionCheckOn(mode string) Option {
	return func(b *authBuilder) error {
		b.cfg.SessionCheckOn = mode
		return nil
	}
}

// WriteTokens delivers an issued token pair. A bearer caller gets the tokens in
// the body and no cookies; a cookie caller gets the cookies and a body that
// never contains a token. extra carries any route-specific top-level fields,
// such as register's userId.
func (c HTTPConfig) WriteTokens(w http.ResponseWriter, r *http.Request, status int, tokens AuthTokens, extra map[string]any) {
	body := successBody(extra)
	if IsBearerRequest(r) {
		body["accessToken"] = tokens.AccessToken
		body["refreshToken"] = tokens.RefreshToken
		WriteJSON(w, status, body)
		return
	}
	cookies := c.Cookies
	if cookies.AccessTokenMaxAge <= 0 && tokens.ExpiresIn > 0 {
		cookies.AccessTokenMaxAge = tokens.ExpiresIn
	}
	cookies.SetAccessTokenCookie(w, tokens.AccessToken)
	cookies.SetRefreshTokenCookie(w, tokens.RefreshToken)
	WriteJSON(w, status, body)
}

// LogoutRequest ends the session the caller presents, best effort, and is the
// single logout revocation path all four adapters call.
//
// The order matters. A refresh token in the body or the refresh cookie revokes
// the whole session, so it is tried first. But the refresh cookie is scoped to
// <prefix>/refresh in every configuration whose name does not resolve to
// __Host- — a Domain, or a non-root cookie Path — and a browser therefore sends
// nothing at all to <prefix>/logout. That is why the reference logout reads the
// *access* token cookie (auth.router.ts:592) and revokes payload.sid: the access
// cookie is scoped to "/" and is always in scope. Without the fallback, logout
// answers 200 {"success":true}, clears the cookies, and leaves the refresh token
// and the session live server-side.
//
// Every failure is swallowed: an absent or already-unusable credential must
// still leave the caller logged out rather than stranded with live cookies.
func (a *Auth) LogoutRequest(ctx context.Context, r *http.Request) {
	if token := RefreshTokenFromRequest(r); token != "" {
		if err := a.Logout(ctx, token); err == nil {
			return
		}
	}
	if token := AccessTokenFromRequest(r); token != "" {
		_ = a.LogoutAccessToken(ctx, token)
	}
}

// LogoutAccessToken revokes the session an access token belongs to. It is the
// revocation path a cookie client's logout takes, since the refresh cookie is
// out of scope for <prefix>/logout whenever it is path-scoped.
func (a *Auth) LogoutAccessToken(ctx context.Context, accessToken string) error {
	return a.service.LogoutAccessToken(ctx, accessToken)
}

// LogoutAccessToken revokes the session named by an access token's sid claim.
func (s *Service) LogoutAccessToken(ctx context.Context, accessToken string) error {
	claims, err := s.parseToken(accessToken, "access")
	if err != nil {
		return err
	}
	if strings.TrimSpace(claims.Sid) == "" {
		return ErrSessionNotFound
	}
	return s.RevokeSessionByID(ctx, claims.Sid)
}

// DecodeOptionalJSONBody decodes r's JSON body into dst, treating an absent or
// zero-length body as the empty object rather than as an error.
//
// The reference runs behind express.json(), which leaves req.body = {} when the
// request carried no body at all; PATCH /profile and POST /add-phone then read
// optional fields off it, so a bodyless call is a 200 no-op there and not a 400
// (§3.5, §3.6). Without a shared decoder the four adapters disagree about
// exactly this: echo's Bind returns nil for a zero-length body, while
// encoding/json and gin's ShouldBindJSON both surface io.EOF as a decode error.
//
// A body that is present but is not valid JSON is still an error: express.json()
// rejects that too, and tolerating it would let a typo'd payload be silently
// applied as "change nothing".
func DecodeOptionalJSONBody(r *http.Request, dst any) error {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("auth: decode json body: %w", err)
	}
	return nil
}

// RefreshTokenFromRequest applies the reference's acceptance order for
// /refresh: a refreshToken in the body wins, otherwise the cookie. A missing or
// empty body is not an error — cookie-mode refresh sends no body at all.
func RefreshTokenFromRequest(r *http.Request) string {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if token := strings.TrimSpace(body.RefreshToken); token != "" {
		return token
	}
	return CookieValue(r, RefreshTokenCookieName)
}
