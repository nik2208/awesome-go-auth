package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This file is the OAuth and account-linking half of the family wire contract
// (wire-contract.md §4): the signed `state` codec, PKCE S256, the redirect
// allowlist, and the flow methods the HTTP adapters call. The adapters stay
// thin glue; everything that decides an outcome lives here so that net/http,
// chi, gin and echo cannot answer differently.
//
// Two places deliberately exceed the reference, both because the reference is
// unsafe there and issue #10 asks for the fix:
//
//   - The reference packs {nonce, origin, path} into `state` as plain base64url
//     and validates only the origin on callback; the nonce is generated and
//     never read (wire-contract.md §4, gap 4). Here the payload is HMAC-signed
//     with the configured secret and verified on callback, and with a
//     PendingLinkStore configured the nonce is single-use as well.
//   - The reference sends no PKCE at all. Here the authorization URL always
//     carries code_challenge/code_challenge_method=S256 and the exchange
//     carries the verifier.
//
// The open-redirect hole the reference has when the allowlist is empty
// (wire-contract.md §4: "any origin embedded in the state is accepted") closes
// as a side effect: only this server can mint a state that verifies, and it
// only ever embeds an origin it resolved itself.

// Error codes for this route group. The first five are the reference's own
// literals; OAUTH_STATE_INVALID has no counterpart because the reference never
// rejects a state.
const (
	CodeOAuthStateInvalid      = "OAUTH_STATE_INVALID"
	CodeOAuthTokenExchangeFail = "OAUTH_TOKEN_EXCHANGE_FAILED"
	CodeOAuthProfileFailed     = "OAUTH_PROFILE_FAILED"
	CodeEmailRequired          = "EMAIL_REQUIRED"
	CodeTokenRequired          = "TOKEN_REQUIRED"
	CodeInvalidLinkToken       = "INVALID_LINK_TOKEN"
	CodeLinkTokenExpired       = "LINK_TOKEN_EXPIRED"
	CodeUnauthorized           = "UNAUTHORIZED"
)

// The error catalog for this group. Messages are the reference's strings where
// the reference has one.
var (
	// HTTPErrOAuthState is the fix for #10. It is a 401 with a code because a
	// browser mid-flow has to be able to tell a tampered state from a provider
	// failure, and because the reference's own choice on this route is a JSON
	// error rather than a redirect (wire-contract.md §4, gap 5).
	HTTPErrOAuthState = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired OAuth state", Code: CodeOAuthStateInvalid}

	HTTPErrEmailRequired      = HTTPError{Status: http.StatusBadRequest, Message: "email is required", Code: CodeEmailRequired}
	HTTPErrTokenRequired      = HTTPError{Status: http.StatusBadRequest, Message: "token is required", Code: CodeTokenRequired}
	HTTPErrInvalidLinkToken   = HTTPError{Status: http.StatusBadRequest, Message: "Invalid account-link token", Code: CodeInvalidLinkToken}
	HTTPErrLinkTokenExpired   = HTTPError{Status: http.StatusBadRequest, Message: "Account-link token has expired", Code: CodeLinkTokenExpired}
	HTTPErrTargetUserNotFound = HTTPError{Status: http.StatusNotFound, Message: "Target user not found", Code: CodeUserNotFound}

	// HTTPErrLinkUnauthorized is the reference's second identity-resolution
	// failure. Its first one ("Authentication required", emitted when no pending
	// link store is configured at all) is unreachable here: this port resolves
	// both the stash and the link-token storage through the same
	// PendingLinkStore, so an absent store answers NOT_IMPLEMENTED before
	// identity resolution is ever attempted.
	HTTPErrLinkUnauthorized = HTTPError{Status: http.StatusUnauthorized, Message: "Authentication required or no pending link found", Code: CodeUnauthorized}
)

// Flow sentinels. They stay unexported: the exported surface a caller needs is
// OAuthHTTPError, and errors.go's sentinel list is pinned by
// TestUnmappedSentinelsAreDeliberate against HTTPErrorFor, which does not and
// must not know about these route-specific literals.
var (
	errOAuthStateInvalid  = errors.New("auth: oauth state is invalid, expired or already used")
	errOAuthTokenExchange = errors.New("auth: oauth token exchange failed")
	errOAuthProfile       = errors.New("auth: oauth profile request failed")
	errStoreNotConfigured = errors.New("auth: required oauth store is not configured")
	errEmailRequired      = errors.New("auth: email is required")
	errTokenRequired      = errors.New("auth: token is required")
	errLinkTokenInvalid   = errors.New("auth: account-link token is invalid")
	errLinkTokenExpired   = errors.New("auth: account-link token has expired")
	errLinkUnauthorized   = errors.New("auth: authentication required or no pending link found")
	errTargetUserNotFound = errors.New("auth: target user not found")
)

// oauthNotConfiguredError names the provider so the 404 stub can carry the
// reference's per-provider message.
type oauthNotConfiguredError struct{ provider string }

func (e oauthNotConfiguredError) Error() string {
	return fmt.Sprintf("auth: oauth provider %q is not configured", e.provider)
}

// OAuthNotConfiguredError is the "<Provider> OAuth not configured" stub as an
// error, so an adapter can answer it without reaching into the flow methods.
func OAuthNotConfiguredError(provider string) error {
	return oauthNotConfiguredError{provider: provider}
}

// providerLabel renders a provider name the way the reference's 404 stubs do.
// Google and GitHub are the two the reference hard-codes; anything else keeps
// the registered name.
func providerLabel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	default:
		return provider
	}
}

// OAuthHTTPError maps a flow failure from this file onto the wire envelope.
// Routes call it instead of WriteServiceError because every literal here is
// route-specific: HTTPErrorFor would turn each of them into a 500.
func OAuthHTTPError(err error) HTTPError {
	var notConfigured oauthNotConfiguredError
	switch {
	case err == nil:
		return HTTPError{}
	case errors.As(err, &notConfigured):
		// 404 with no code, as the reference's absent-strategy stubs emit.
		return HTTPError{Status: http.StatusNotFound, Message: providerLabel(notConfigured.provider) + " OAuth not configured"}
	case errors.Is(err, errOAuthStateInvalid):
		return HTTPErrOAuthState
	case errors.Is(err, errOAuthTokenExchange):
		return HTTPError{Status: http.StatusUnauthorized, Message: "OAuth token exchange failed", Code: CodeOAuthTokenExchangeFail}
	case errors.Is(err, errOAuthProfile):
		return HTTPError{Status: http.StatusUnauthorized, Message: "Failed to get OAuth user profile", Code: CodeOAuthProfileFailed}
	case errors.Is(err, errStoreNotConfigured):
		return HTTPErrNotImplemented
	case errors.Is(err, errEmailRequired):
		return HTTPErrEmailRequired
	case errors.Is(err, errTokenRequired):
		return HTTPErrTokenRequired
	case errors.Is(err, errLinkTokenInvalid):
		return HTTPErrInvalidLinkToken
	case errors.Is(err, errLinkTokenExpired):
		return HTTPErrLinkTokenExpired
	case errors.Is(err, errLinkUnauthorized):
		return HTTPErrLinkUnauthorized
	case errors.Is(err, errTargetUserNotFound):
		return HTTPErrTargetUserNotFound
	default:
		return HTTPErrorFor(err)
	}
}

// ── wiring ───────────────────────────────────────────────────────────────────

// OAuthWiring is everything the OAuth and account-linking routes need beyond
// the core service. The reference gates each route on the presence of the
// corresponding option; the equivalent here is that an absent member turns its
// routes into NOT_IMPLEMENTED rather than leaving them unmounted, because a
// single dynamic /oauth/{provider} route cannot be registered per provider.
type OAuthWiring struct {
	// Service resolves providers, builds authorization URLs and exchanges codes.
	Service *OAuthService
	// LinkedAccounts persists the provider ↔ user associations the
	// /linked-accounts routes read and write.
	LinkedAccounts LinkedAccountStore
	// PendingLinks is the stash. It carries two kinds of entry, both keyed by an
	// opaque string and both single-use: the in-flight OAuth state (so a nonce
	// cannot be replayed) and the account-link token issued by /link-request.
	PendingLinks PendingLinkStore
	// AllowedOrigins is the redirect allowlist. An empty allowlist accepts the
	// origin embedded in the state, matching the reference — safe here only
	// because the state is signed.
	AllowedOrigins []string
	// SiteURL is the fallback redirect target, the reference's first
	// config.email.siteUrl entry.
	SiteURL string
	// TenantID scopes users created or resolved by the callback.
	TenantID string
	// StateTTL bounds how long a signed state stays acceptable. Default 10m.
	StateTTL time.Duration
	// LinkTokenTTL bounds the /link-request token. Default 1h, as the reference.
	LinkTokenTTL time.Duration
	// DeliverLinkToken hands the /link-request verification link to the host's
	// mail transport. The route answers success either way, as the reference
	// does when no transport is configured.
	DeliverLinkToken func(ctx context.Context, delivery LinkTokenDelivery) error
}

// LinkTokenDelivery is the payload handed to OAuthWiring.DeliverLinkToken.
type LinkTokenDelivery struct {
	Email    string
	Provider string
	Token    string
	URL      string
}

func (w *OAuthWiring) stateTTL() time.Duration {
	if w.StateTTL > 0 {
		return w.StateTTL
	}
	return 10 * time.Minute
}

func (w *OAuthWiring) linkTokenTTL() time.Duration {
	if w.LinkTokenTTL > 0 {
		return w.LinkTokenTTL
	}
	return time.Hour
}

// WithOAuth wires the OAuth service and the linking stores.
func WithOAuth(wiring OAuthWiring) Option {
	return func(b *authBuilder) error {
		clone := wiring
		b.oauth = &clone
		return nil
	}
}

// OAuthConfigured reports whether the OAuth routes have anything to serve. The
// adapters mount the routes unconditionally, so they need this to answer the
// reference's "not configured" stub.
func (a *Auth) OAuthConfigured() bool {
	return a.oauth != nil && a.oauth.Service != nil
}

// Has reports whether a provider is registered.
func (s *OAuthService) Has(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.providers[name]
	return ok
}

func (a *Auth) requireProvider(provider string) (*OAuthWiring, error) {
	if !a.OAuthConfigured() || !a.oauth.Service.Has(provider) {
		return nil, oauthNotConfiguredError{provider: provider}
	}
	return a.oauth, nil
}

// ── signed state ─────────────────────────────────────────────────────────────

// oauthState is the reference's state payload ({n, o, p}) plus an issued-at.
// The field names are the reference's so that a client or proxy that already
// decodes the payload keeps working; the signature is appended after a dot,
// which a base64url payload can never contain.
type oauthState struct {
	N string `json:"n"`
	O string `json:"o,omitempty"`
	P string `json:"p,omitempty"`
	T int64  `json:"t"`
}

func encodeOAuthState(state oauthState, secret string) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("auth: encode oauth state: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + sign(encoded, secret), nil
}

// decodeOAuthState verifies the signature before it parses anything, so a
// forged payload never reaches the JSON decoder.
func decodeOAuthState(raw, secret string, ttl time.Duration) (oauthState, error) {
	encoded, signature, found := strings.Cut(strings.TrimSpace(raw), ".")
	if !found || encoded == "" || signature == "" {
		return oauthState{}, errOAuthStateInvalid
	}
	if !secureEqual(signature, sign(encoded, secret)) {
		return oauthState{}, errOAuthStateInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return oauthState{}, errOAuthStateInvalid
	}
	var state oauthState
	if err := json.Unmarshal(payload, &state); err != nil || state.N == "" {
		return oauthState{}, errOAuthStateInvalid
	}
	if ttl > 0 {
		issued := time.Unix(state.T, 0)
		if state.T == 0 || time.Since(issued) > ttl || time.Until(issued) > time.Minute {
			return oauthState{}, errOAuthStateInvalid
		}
	}
	return state, nil
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

// pkceVerifier derives the RFC 7636 code_verifier from the state nonce instead
// of storing it. The derivation needs the signing secret, so an attacker who
// intercepts the authorization request — which carries the nonce and the
// challenge, both public by design — still cannot produce the verifier. That
// keeps PKCE working for embedders who configure no PendingLinkStore.
//
// 32 HMAC bytes render as 43 base64url characters, exactly the RFC minimum.
func pkceVerifier(secret, nonce string) string {
	return sign("pkce\x00"+nonce, secret)
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ── redirect resolution ──────────────────────────────────────────────────────

// resolveSiteURL is the reference's initiation-time origin resolution: match
// the Origin header against the allowlist, then the origin of the Referer,
// otherwise fall back to the configured site URL.
func resolveSiteURL(origin, referer string, allowed []string, siteURL string) string {
	if len(allowed) > 0 {
		if candidate := strings.TrimSpace(origin); originAllowed(candidate, allowed) {
			return candidate
		}
		if u, err := url.Parse(strings.TrimSpace(referer)); err == nil && u.Scheme != "" && u.Host != "" {
			if candidate := u.Scheme + "://" + u.Host; originAllowed(candidate, allowed) {
				return candidate
			}
		}
	}
	return siteURL
}

// resolveOAuthRedirect is the reference's resolveOAuthRedirect: honour the
// state's origin when the allowlist permits it (an empty allowlist permits
// everything), append the return path with base-path de-duplication, and fall
// back to the configured site URL.
func resolveOAuthRedirect(state oauthState, allowed []string, siteURL string) string {
	origin := strings.TrimSpace(state.O)
	if origin == "" || !originAllowed(origin, allowed) {
		origin = siteURL
	}
	if origin == "" {
		return ""
	}
	origin = strings.TrimSuffix(origin, "/")
	path := strings.TrimSpace(state.P)
	if path == "" {
		return origin
	}
	path = "/" + strings.TrimPrefix(path, "/")
	// The reference de-duplicates when the origin itself carries a base path and
	// the return path repeats it, so https://ex.com/app + /app/dash stays
	// https://ex.com/app/dash rather than doubling the segment.
	if u, err := url.Parse(origin); err == nil {
		if base := strings.TrimSuffix(u.Path, "/"); base != "" {
			if path == base || strings.HasPrefix(path, base+"/") {
				path = strings.TrimPrefix(path, base)
			}
		}
	}
	return origin + path
}

// originAllowed mirrors the reference: an empty allowlist allows everything.
func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return false
	}
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.TrimSuffix(candidate, "/") == strings.TrimSuffix(origin, "/") {
			return true
		}
	}
	return false
}

// ── stash keys ───────────────────────────────────────────────────────────────

// oauthStateKey namespaces the in-flight state entries. The nonce is the key
// material and is not secret, but keeping the two entry kinds in disjoint
// namespaces stops a link token from ever being read as a state.
func oauthStateKey(nonce string) string { return "oauth-state:" + nonce }

// linkTokenKey stores the hash, never the token: the stash must not hold a
// credential that would let its reader complete somebody else's link.
func linkTokenKey(token string) string { return "link-token:" + hashToken(token) }

// pendingLinkKey is the reference's conflict stash key — (email, provider).
func pendingLinkKey(email, provider string) string {
	return "pending-link:" + normalizeEmail(email) + "|" + strings.ToLower(strings.TrimSpace(provider))
}

// ── begin ────────────────────────────────────────────────────────────────────

// OAuthBeginInput is GET <prefix>/oauth/{provider}.
type OAuthBeginInput struct {
	Provider   string
	ReturnPath string
	Origin     string
	Referer    string
	// LinkUserID links the provider to an existing account instead of resolving
	// or creating one. The route fills it when the initiating request already
	// carries a usable access token.
	LinkUserID string
}

// OAuthBeginResult is what the route redirects to.
type OAuthBeginResult struct {
	AuthorizationURL string
	State            string
}

// OAuthBegin mints a signed state, derives the PKCE challenge and builds the
// provider authorization URL.
func (a *Auth) OAuthBegin(ctx context.Context, in OAuthBeginInput) (OAuthBeginResult, error) {
	wiring, err := a.requireProvider(in.Provider)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	// 16 random bytes as 32 hex characters, the reference's nonce size.
	nonce, err := randomHex(16)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	secret := a.service.cfg.Secret
	origin := resolveSiteURL(in.Origin, in.Referer, wiring.AllowedOrigins, wiring.SiteURL)
	state, err := encodeOAuthState(oauthState{
		N: nonce,
		O: origin,
		P: in.ReturnPath,
		T: time.Now().Unix(),
	}, secret)
	if err != nil {
		return OAuthBeginResult{}, err
	}
	authorizationURL, err := wiring.Service.AuthorizeURLPKCE(in.Provider, state, pkceChallengeS256(pkceVerifier(secret, nonce)))
	if err != nil {
		return OAuthBeginResult{}, err
	}
	if wiring.PendingLinks != nil {
		// Recording the nonce is what makes it single-use on callback. Without a
		// stash the state is still signed and time-bounded, just replayable
		// inside its TTL.
		if err := wiring.PendingLinks.Save(ctx, oauthStateKey(nonce), OAuthPendingMeta{
			Provider:    in.Provider,
			RedirectURL: origin,
			TenantID:    wiring.TenantID,
			UserID:      in.LinkUserID,
			ExpiresAt:   time.Now().Add(wiring.stateTTL()),
		}, wiring.stateTTL()); err != nil {
			return OAuthBeginResult{}, err
		}
	}
	return OAuthBeginResult{AuthorizationURL: authorizationURL, State: state}, nil
}

// ── complete ─────────────────────────────────────────────────────────────────

// OAuthCompleteInput is GET <prefix>/oauth/{provider}/callback.
type OAuthCompleteInput struct {
	Provider string
	Code     string
	State    string
}

// OAuthCompleteResult carries the issued session and where to send the browser.
type OAuthCompleteResult struct {
	User       User
	Tokens     AuthTokens
	RedirectTo string
}

// OAuthComplete verifies the state, exchanges the code with the PKCE verifier
// and resolves the user.
func (a *Auth) OAuthComplete(ctx context.Context, in OAuthCompleteInput) (OAuthCompleteResult, error) {
	wiring, err := a.requireProvider(in.Provider)
	if err != nil {
		return OAuthCompleteResult{}, err
	}
	if wiring.LinkedAccounts == nil {
		return OAuthCompleteResult{}, errStoreNotConfigured
	}
	secret := a.service.cfg.Secret
	state, err := decodeOAuthState(in.State, secret, wiring.stateTTL())
	if err != nil {
		return OAuthCompleteResult{}, err
	}

	meta := OAuthPendingMeta{TenantID: wiring.TenantID}
	if wiring.PendingLinks != nil {
		stashed, err := wiring.PendingLinks.Get(ctx, oauthStateKey(state.N))
		if err != nil {
			// Unknown or already-consumed nonce. This is the replay defence the
			// reference does not have.
			return OAuthCompleteResult{}, errOAuthStateInvalid
		}
		if stashed.Provider != "" && stashed.Provider != in.Provider {
			// A state minted for one provider must not complete another.
			return OAuthCompleteResult{}, errOAuthStateInvalid
		}
		_ = wiring.PendingLinks.Delete(ctx, oauthStateKey(state.N))
		meta = stashed
		if meta.TenantID == "" {
			meta.TenantID = wiring.TenantID
		}
	}

	redirectTo := resolveOAuthRedirect(state, wiring.AllowedOrigins, wiring.SiteURL)
	info, err := wiring.Service.ExchangeCodePKCE(ctx, in.Provider, in.Code, pkceVerifier(secret, state.N))
	if err != nil {
		return OAuthCompleteResult{RedirectTo: redirectTo}, err
	}
	user, tokens, err := wiring.Service.HandleCallback(ctx, a.service, wiring.LinkedAccounts, info, meta.TenantID, meta.UserID)
	if err != nil {
		return OAuthCompleteResult{RedirectTo: redirectTo}, err
	}
	return OAuthCompleteResult{User: user, Tokens: tokens, RedirectTo: redirectTo}, nil
}

// ── linked accounts ──────────────────────────────────────────────────────────

// PublicLinkedAccount is the wire projection of a linked account. The field
// names are the reference's LinkedAccount interface, which is what the Angular
// client and the served auth.js read.
type PublicLinkedAccount struct {
	Provider          string    `json:"provider"`
	ProviderAccountID string    `json:"providerAccountId"`
	Email             string    `json:"email,omitempty"`
	LinkedAt          time.Time `json:"linkedAt"`
}

// ListLinkedAccounts returns a user's provider associations, always as a
// non-nil slice so the JSON is [] rather than null.
func (a *Auth) ListLinkedAccounts(ctx context.Context, userID string) ([]PublicLinkedAccount, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		return nil, errStoreNotConfigured
	}
	links, err := a.oauth.LinkedAccounts.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]PublicLinkedAccount, 0, len(links))
	for _, link := range links {
		out = append(out, PublicLinkedAccount{
			Provider:          link.Provider,
			ProviderAccountID: link.ProviderID,
			LinkedAt:          link.CreatedAt,
		})
	}
	return out, nil
}

// UnlinkAccount removes one provider association.
//
// The reference performs no existence check and answers success unconditionally
// (wire-contract.md §4, DELETE /linked-accounts). This keeps that, and adds the
// ownership check the reference gets for free by passing the user id into its
// store: a link that belongs to somebody else is left alone.
func (a *Auth) UnlinkAccount(ctx context.Context, userID, provider, providerAccountID string) error {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil {
		return errStoreNotConfigured
	}
	link, err := a.oauth.LinkedAccounts.FindByProvider(ctx, provider, providerAccountID)
	if err != nil || link.UserID != userID {
		return nil
	}
	return a.oauth.LinkedAccounts.Delete(ctx, link.ID)
}

// ── link-request / link-verify ───────────────────────────────────────────────

// LinkRequestInput is POST <prefix>/link-request.
type LinkRequestInput struct {
	Email       string
	Provider    string
	AccessToken string
	// APIPrefix is the mount prefix, needed to build the verification link.
	APIPrefix string
}

// LinkRequestResult reports what was issued. The token never reaches the HTTP
// response; it is returned so an embedder driving the service directly can send
// it themselves.
type LinkRequestResult struct {
	Token string
	URL   string
}

// LinkRequest issues a single-use account-link token and hands the verification
// link to the configured delivery hook.
func (a *Auth) LinkRequest(ctx context.Context, in LinkRequestInput) (LinkRequestResult, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil || a.oauth.PendingLinks == nil {
		return LinkRequestResult{}, errStoreNotConfigured
	}
	wiring := a.oauth
	email := normalizeEmail(in.Email)
	if email == "" {
		return LinkRequestResult{}, errEmailRequired
	}
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = "email"
	}

	// Identity resolution, in the reference's order: a usable access token wins,
	// an unusable one is silently ignored, and the conflict stash is the
	// fallback.
	var (
		userID            string
		tenantID          = wiring.TenantID
		providerAccountID string
	)
	if token := strings.TrimSpace(in.AccessToken); token != "" {
		if user, err := a.service.Me(ctx, token); err == nil {
			userID = user.ID
			tenantID = user.TenantID
		}
	}
	if userID == "" {
		stashed, err := wiring.PendingLinks.Get(ctx, pendingLinkKey(email, provider))
		if err != nil {
			return LinkRequestResult{}, errLinkUnauthorized
		}
		providerAccountID = stashed.ProviderAccountID
		if stashed.TenantID != "" {
			tenantID = stashed.TenantID
		}
		user, err := a.service.users.GetUserByEmail(ctx, email, tenantID)
		if err != nil {
			return LinkRequestResult{}, errTargetUserNotFound
		}
		userID = user.ID
	}

	// 32 random bytes as 64 hex characters, the reference's token size.
	token, err := randomHex(32)
	if err != nil {
		return LinkRequestResult{}, err
	}
	ttl := wiring.linkTokenTTL()
	if err := wiring.PendingLinks.Save(ctx, linkTokenKey(token), OAuthPendingMeta{
		Provider:          provider,
		TenantID:          tenantID,
		UserID:            userID,
		Email:             email,
		ProviderAccountID: providerAccountID,
		ExpiresAt:         time.Now().Add(ttl),
	}, ttl); err != nil {
		return LinkRequestResult{}, err
	}

	prefix := strings.TrimSuffix(strings.TrimSpace(in.APIPrefix), "/")
	link := wiring.SiteURL + prefix + "/link-verify?token=" + url.QueryEscape(token)
	result := LinkRequestResult{Token: token, URL: link}
	if wiring.DeliverLinkToken != nil {
		// Delivery failures do not fail the route: the reference answers success
		// even when no mail transport is configured at all.
		if err := wiring.DeliverLinkToken(ctx, LinkTokenDelivery{
			Email:    email,
			Provider: provider,
			Token:    token,
			URL:      link,
		}); err != nil {
			a.service.logf("auth: link token delivery failed for %q: %v", email, err)
		}
	}
	return result, nil
}

// LinkVerifyInput is POST <prefix>/link-verify.
type LinkVerifyInput struct {
	Token             string
	LoginAfterLinking bool
}

// LinkVerifyResult carries the tokens when loginAfterLinking was asked for.
type LinkVerifyResult struct {
	User     User
	Tokens   AuthTokens
	LoggedIn bool
}

// LinkVerify consumes an account-link token and writes the association.
func (a *Auth) LinkVerify(ctx context.Context, in LinkVerifyInput) (LinkVerifyResult, error) {
	if a.oauth == nil || a.oauth.LinkedAccounts == nil || a.oauth.PendingLinks == nil {
		return LinkVerifyResult{}, errStoreNotConfigured
	}
	wiring := a.oauth
	token := strings.TrimSpace(in.Token)
	if token == "" {
		return LinkVerifyResult{}, errTokenRequired
	}
	key := linkTokenKey(token)
	meta, err := wiring.PendingLinks.Get(ctx, key)
	if err != nil {
		return LinkVerifyResult{}, errLinkTokenInvalid
	}
	// Expiry is carried in the entry, not left to the store: a PendingLinkStore
	// that ignores the ttl argument must not turn into an unbounded token.
	if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
		_ = wiring.PendingLinks.Delete(ctx, key)
		return LinkVerifyResult{}, errLinkTokenExpired
	}

	// The reference defaults providerAccountId to the email and overrides it
	// with the stashed OAuth account id when the conflict flow produced one.
	providerAccountID := meta.ProviderAccountID
	if providerAccountID == "" {
		providerAccountID = meta.Email
	}
	linkID, err := newID("lnk")
	if err != nil {
		return LinkVerifyResult{}, err
	}
	if err := wiring.LinkedAccounts.Save(ctx, OAuthLinkedAccount{
		ID:         linkID,
		UserID:     meta.UserID,
		Provider:   meta.Provider,
		ProviderID: providerAccountID,
		CreatedAt:  time.Now(),
	}); err != nil {
		return LinkVerifyResult{}, err
	}
	// Single use: the token dies with the link it created.
	_ = wiring.PendingLinks.Delete(ctx, key)
	_ = wiring.PendingLinks.Delete(ctx, pendingLinkKey(meta.Email, meta.Provider))

	if !in.LoginAfterLinking {
		return LinkVerifyResult{}, nil
	}
	user, tokens, err := a.service.IssueTokensForUser(ctx, meta.UserID, meta.TenantID)
	if err != nil {
		return LinkVerifyResult{}, err
	}
	return LinkVerifyResult{User: user, Tokens: tokens, LoggedIn: true}, nil
}

// IssueTokensForUser starts a session for an identity that has already been
// proven by something other than a password — here, an emailed account-link
// token. It is the one service method this route group needed and the core did
// not have: every other issuance path (Register, Login, VerifyMagicLink,
// VerifySMSCode, VerifyTOTP) reaches newSessionTokens through a credential
// check that does not apply.
func (s *Service) IssueTokensForUser(ctx context.Context, userID, tenantID string) (User, AuthTokens, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return User{}, AuthTokens{}, ErrInvalidCredentials
	}
	tokens, err := s.newSessionTokens(ctx, user)
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	return user, tokens, nil
}

// IssueTokensForUser delegates to Service.IssueTokensForUser.
func (a *Auth) IssueTokensForUser(ctx context.Context, userID, tenantID string) (User, AuthTokens, error) {
	return a.service.IssueTokensForUser(ctx, userID, tenantID)
}

// ── in-memory stash ──────────────────────────────────────────────────────────

// MemoryPendingLinks is an in-memory PendingLinkStore, the counterpart of
// MemoryLinkedAccounts. It enforces the ttl, which is what makes an OAuth state
// nonce single-use and an account-link token expire.
type MemoryPendingLinks struct {
	mu      sync.Mutex
	entries map[string]memoryPendingEntry
	now     func() time.Time
}

type memoryPendingEntry struct {
	meta      OAuthPendingMeta
	expiresAt time.Time
}

// NewMemoryPendingLinks creates an in-memory PendingLinkStore.
func NewMemoryPendingLinks() *MemoryPendingLinks {
	return &MemoryPendingLinks{entries: make(map[string]memoryPendingEntry), now: time.Now}
}

func (m *MemoryPendingLinks) Save(_ context.Context, key string, meta OAuthPendingMeta, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := memoryPendingEntry{meta: meta}
	if ttl > 0 {
		entry.expiresAt = m.now().Add(ttl)
	}
	m.entries[key] = entry
	return nil
}

func (m *MemoryPendingLinks) Get(_ context.Context, key string) (OAuthPendingMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok {
		return OAuthPendingMeta{}, errors.New("auth: pending link not found")
	}
	if !entry.expiresAt.IsZero() && m.now().After(entry.expiresAt) {
		delete(m.entries, key)
		return OAuthPendingMeta{}, errors.New("auth: pending link expired")
	}
	return entry.meta, nil
}

func (m *MemoryPendingLinks) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}
