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
