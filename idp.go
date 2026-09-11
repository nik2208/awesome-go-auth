package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultAuthCodeTTL is how long an authorization code stays redeemable when
// IDPConfig.CodeTTL is unset. Five minutes is the value the process-local map
// hardcoded before the store seam existed, so existing callers see no change.
const defaultAuthCodeTTL = 5 * time.Minute

// DefaultIDPKeyID is the kid the IdP signs with and publishes when
// IDPConfig.KeyID is empty: the constant the reference hardcodes for every
// IdP-issued token and for the JWKS document (token.service.ts:78,
// jwks.service.ts:184).
const DefaultIDPKeyID = "provisioner-key-1"

// The lifetimes of the IdP token pair when IDPConfig leaves them zero: the
// reference's tokenExpiry default of 30d and refreshTokenExpiry default of 90d
// (token.service.ts:80 and :91).
const (
	defaultIDPAccessTokenTTL  = 30 * 24 * time.Hour
	defaultIDPRefreshTokenTTL = 90 * 24 * time.Hour
)

// idpEphemeralKeyWarning is what NewIDP logs, once, when no Signer was
// configured. The sentences are the reference's (token.service.ts:52-57); only
// the two names are this port's.
const idpEphemeralKeyWarning = "auth: IdP mode: no Signer configured — auto-generating an ephemeral RSA keypair. All tokens will be invalidated on restart. Set IDPConfig.Signer in production."

// IDPConfig configures the OIDC Identity Provider.
type IDPConfig struct {
	// Issuer is the iss claim of the ID token and the base of the discovery
	// document. For IssueIdPTokenPair it is optional, as the reference's
	// idProvider.issuer is: left empty, the pair carries no iss claim
	// (token.service.ts:74-77).
	Issuer string
	// AccessTokenTTL is the lifetime of the access token IssueIdPTokenPair
	// mints; zero resolves to 30 days, the reference's tokenExpiry default
	// (token.service.ts:80). It governs only that pair: the OIDC /token
	// endpoint returns the HS256 session access token and reports that
	// token's lifetime, Config.AccessTokenTTL, as expires_in.
	AccessTokenTTL time.Duration
	// IDTokenTTL is the lifetime of the ID token; zero resolves to one hour.
	IDTokenTTL time.Duration

	// Signer signs every RS256 token the IDP issues and is the key the JWKS
	// document publishes first. It must be an RSA key — RS256 is RSASSA-PKCS1
	// v1.5 over SHA-256 (RFC 7518 section 3.3) — and NewIDP refuses a signer
	// whose Public is not an *rsa.PublicKey. An *rsa.PrivateKey qualifies, so
	// the reference's PEM configuration is ParseRSAPrivateKeyPEM(pem) here
	// (idProvider.privateKey, token.service.ts:47); the public key the
	// reference derives when none is given (:67-69) is Signer.Public. A signer
	// that keeps the private key elsewhere — a KMS, an HSM — plugs in the same
	// way; BuildRS256JWT says what it is asked to do.
	//
	// Nil generates an ephemeral RSA-2048 key in NewIDP and logs the
	// reference's warning once (token.service.ts:50-66, auth.router.ts:480-483):
	// every token becomes unverifiable on restart, and two processes never
	// share a key. Development only.
	Signer crypto.Signer
	// KeyID is the kid written into the header of every signed token and
	// published with Signer's key in the JWKS document. Empty resolves to
	// DefaultIDPKeyID, the reference's constant.
	KeyID string
	// PublicKeys are further keys the JWKS document publishes after Signer's,
	// unchanged: the previous key during a rotation, so that the tokens it
	// signed stay verifiable until they expire, or a sibling issuer's. Nothing
	// in the IDP signs with them or checks them; NewRSAJWK builds one from an
	// *rsa.PublicKey. The reference publishes exactly one key
	// (jwks.service.ts:184-186); this is the structural room a rotation needs.
	PublicKeys []JWK
	// RefreshTokenTTL is the lifetime of the refresh token IssueIdPTokenPair
	// mints; zero resolves to 90 days (token.service.ts:91). The reference
	// consults its session refresh lifetime in between (idProvider.refreshTokenExpiry,
	// then refreshTokenExpiresIn, then 90d); that middle step is not
	// reproduced, because Config.RefreshTokenTTL is never unset here —
	// DefaultConfig fills it and validate requires it — so honouring it would
	// make the 90-day default unreachable and tie the IdP pair silently to the
	// session lifetime.
	RefreshTokenTTL time.Duration
	// Logger receives the IDP's diagnostics, today only the ephemeral-key
	// warning. Nil falls back to the Config.Logger of the Service NewIDP was
	// given, and to silence when there is none.
	Logger func(format string, args ...any)

	// Codes holds authorization codes between /authorize and /token. Nil
	// selects NewMemoryAuthCodeStore, which is correct only while both
	// endpoints are served by the same process: a serverless runtime or any
	// deployment with more than one instance must supply a shared
	// implementation, or /token will answer invalid_grant for every code
	// minted by a sibling process. See AuthCodeStore for the contract.
	Codes AuthCodeStore

	// CodeTTL bounds how long a code issued by /authorize can be redeemed at
	// /token. Zero (or negative) resolves to defaultAuthCodeTTL, five minutes.
	CodeTTL time.Duration
}

// IDPClient represents a registered OIDC client application.
type IDPClient struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Name         string
}

// IDP is an OIDC Identity Provider.
type IDP struct {
	cfg     IDPConfig
	authSvc *Service
	// signer is cfg.Signer with the nil default resolved; keyID is cfg.KeyID
	// with the reference's constant as the default; signerJWK is the signer's
	// Public under keyID, checked once at construction to be RSA and built
	// once, the entry JWKS publishes first.
	signer    crypto.Signer
	signerJWK JWK
	keyID     string
	clients   map[string]IDPClient
	// codes is cfg.Codes with the nil default resolved. Every code handed to a
	// client is looked up here by hashToken(code); nothing in the IDP holds a
	// code or its record after the handler returns, which is what lets
	// /authorize and /token run on different processes.
	codes AuthCodeStore
	now   func() time.Time
}

// NewIDP creates a new OIDC IDP backed by the given auth service.
//
// A nil cfg.Signer falls back to an ephemeral RSA-2048 key and logs
// idpEphemeralKeyWarning once; a signer that is not RSA is refused. A nil
// cfg.Codes falls back to an in-process MemoryAuthCodeStore; see
// IDPConfig.Codes for when that is not enough.
func NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error) {
	idp := &IDP{cfg: cfg, authSvc: authSvc, now: time.Now}
	signer := cfg.Signer
	if signer == nil {
		// The reference warns on the first call that finds no privateKey and
		// generates once per process (token.service.ts:50-66); here the key is
		// generated once per IDP, at construction, so the warning goes with it.
		idp.logf(idpEphemeralKeyWarning)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("auth: idp key generation: %w", err)
		}
		signer = key
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil {
		return nil, fmt.Errorf("auth: idp: signer public key is %T, want *rsa.PublicKey (RS256 is RSA)", signer.Public())
	}
	idp.signer = signer
	idp.keyID = cfg.KeyID
	if idp.keyID == "" {
		idp.keyID = DefaultIDPKeyID
	}
	signerJWK, err := NewRSAJWK(pub, idp.keyID)
	if err != nil {
		return nil, err
	}
	idp.signerJWK = signerJWK
	idp.clients = make(map[string]IDPClient, len(clients))
	for _, c := range clients {
		idp.clients[c.ClientID] = c
	}
	idp.codes = cfg.Codes
	if idp.codes == nil {
		idp.codes = NewMemoryAuthCodeStore()
	}
	return idp, nil
}

// logf writes through IDPConfig.Logger, else through the Service's logger.
func (idp *IDP) logf(format string, args ...any) {
	switch {
	case idp.cfg.Logger != nil:
		idp.cfg.Logger(format, args...)
	case idp.authSvc != nil:
		idp.authSvc.logf(format, args...)
	}
}

// codeTTL resolves IDPConfig.CodeTTL, applying the five-minute default.
func (idp *IDP) codeTTL() time.Duration {
	if idp.cfg.CodeTTL <= 0 {
		return defaultAuthCodeTTL
	}
	return idp.cfg.CodeTTL
}

// accessTokenTTL resolves IDPConfig.AccessTokenTTL for the IdP pair.
func (idp *IDP) accessTokenTTL() time.Duration {
	if idp.cfg.AccessTokenTTL <= 0 {
		return defaultIDPAccessTokenTTL
	}
	return idp.cfg.AccessTokenTTL
}

// refreshTokenTTL resolves IDPConfig.RefreshTokenTTL for the IdP pair.
func (idp *IDP) refreshTokenTTL() time.Duration {
	if idp.cfg.RefreshTokenTTL <= 0 {
		return defaultIDPRefreshTokenTTL
	}
	return idp.cfg.RefreshTokenTTL
}

// JWKS is the document the JWKS endpoint serves: the signer's public key under
// KeyID first, then IDPConfig.PublicKeys in the order given. The reference
// builds the same document from its one key (jwks.service.ts:184-186); the
// extra entries are what a rotation publishes so that tokens signed by the
// previous key stay verifiable until they expire.
func (idp *IDP) JWKS() JWKS {
	keys := make([]JWK, 0, 1+len(idp.cfg.PublicKeys))
	keys = append(keys, idp.signerJWK)
	keys = append(keys, idp.cfg.PublicKeys...)
	return JWKS{Keys: keys}
}

// IssueIdPTokenPair mints the reference's RS256 token pair for user: the
// transcription of generateIdProviderTokenPair (token.service.ts:73-95).
//
// The payload is the reference's buildPayload (auth.router.ts:378-384): the
// six base claims sub, email, role, loginProvider, isEmailVerified and
// isTotpEnabled with Config.BuildTokenClaims spread over them, the same object
// the session tokens start from. iat, exp and kid are then dropped from it
// (:73) — the first two are set below, kid is a header parameter — and iss is
// set from IDPConfig.Issuer when that is configured, else left as the hook
// left it (:74-77). Both tokens carry that payload plus iat and exp, both are
// RS256 under KeyID (:81-93); they differ only in lifetime — AccessTokenTTL,
// 30 days by default, and RefreshTokenTTL, 90 days by default. ExpiresIn is
// the access lifetime.
//
// No session is created and no sid, jti or typ claim is written: the reference
// pair has none either, so the refresh token is a longer-lived copy of the
// access token that nothing here can revoke. This is a host-level API exactly
// as in the reference, where nothing in src/ calls generateIdProviderTokenPair
// (reference-issues N35): /login, /refresh and the OIDC /token keep issuing
// the HS256 session pair, and enabling the IDP changes nothing about them.
//
// It lives on IDP rather than Service because everything it needs beyond the
// user is the IDP's — the signer, the kid, the two lifetimes, the issuer — and
// the IDP already holds the Service for the claims hook, while a Service knows
// nothing of any IDP. In the reference all of that is the config.idProvider
// block, which is IDPConfig here.
func (idp *IDP) IssueIdPTokenPair(ctx context.Context, user User) (AuthTokens, error) {
	claims, err := idp.payloadClaims(ctx, user)
	if err != nil {
		return AuthTokens{}, err
	}
	delete(claims, "iat")
	delete(claims, "exp")
	delete(claims, "kid")
	if idp.cfg.Issuer != "" {
		claims["iss"] = idp.cfg.Issuer
	}
	now := idp.now()
	accessTTL := idp.accessTokenTTL()
	accessToken, err := idp.signWithLifetime(claims, now, accessTTL)
	if err != nil {
		return AuthTokens{}, err
	}
	refreshToken, err := idp.signWithLifetime(claims, now, idp.refreshTokenTTL())
	if err != nil {
		return AuthTokens{}, err
	}
	return AuthTokens{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: accessTTL}, nil
}

// payloadClaims is the reference's buildPayload (auth.router.ts:378-384) for
// the IdP pair; issueToken in token.go assembles the same object inline for the
// session pair, and TestIssueIdPTokenPairBaseClaimsMatchSessionTokens keeps
// the two in step. The hook is the Service's, so an IDP built without one
// mints the base claims alone.
func (idp *IDP) payloadClaims(ctx context.Context, user User) (map[string]any, error) {
	claims := map[string]any{
		"sub":             user.ID,
		"email":           user.Email,
		"role":            user.Role,
		"loginProvider":   user.loginProviderOrLocal(),
		"isEmailVerified": user.IsEmailVerified,
		"isTotpEnabled":   user.IsTOTPEnabled,
	}
	if idp.authSvc != nil && idp.authSvc.cfg.BuildTokenClaims != nil {
		custom, err := idp.authSvc.cfg.BuildTokenClaims(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("auth: build token claims: %w", err)
		}
		for key, value := range custom {
			claims[key] = value
		}
	}
	return claims, nil
}

// signWithLifetime signs a copy of claims with iat = now and exp = now + ttl,
// the two members jsonwebtoken manages for the reference (token.service.ts:72).
func (idp *IDP) signWithLifetime(claims map[string]any, now time.Time, ttl time.Duration) (string, error) {
	payload := make(map[string]any, len(claims)+2)
	for key, value := range claims {
		payload[key] = value
	}
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(ttl).Unix()
	return BuildRS256JWT(idp.signer, idp.keyID, payload)
}

// RegisterHandlers mounts OIDC endpoints on the given mux.
func (idp *IDP) RegisterHandlers(mux *http.ServeMux, basePath string) {
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	mux.HandleFunc(basePath+".well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc(basePath+"jwks", idp.handleJWKS)
	mux.HandleFunc(basePath+"authorize", idp.handleAuthorize)
	mux.HandleFunc(basePath+"token", idp.handleToken)
	mux.HandleFunc(basePath+"userinfo", idp.handleUserInfo)
}

func (idp *IDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimSuffix(idp.cfg.Issuer, "/")
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"claims_supported":                      []string{"sub", "email", "name", "iat", "exp", "iss", "aud", "nonce"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc) //nolint:errcheck
}

func (idp *IDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(idp.JWKS()) //nolint:errcheck
}

func (idp *IDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")

	client, ok := idp.clients[clientID]
	if !ok {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	// Look up the canonical (server-controlled) redirect URI from the registered allowlist.
	canonicalRedirect := idpMatchedRedirect(client.RedirectURIs, redirectURI)
	if canonicalRedirect == "" {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		email := r.FormValue("email")
		password := r.FormValue("password")
		tenantID := r.FormValue("tenant_id")
		user, _, err := idp.authSvc.Login(r.Context(), LoginInput{Email: email, Password: password, TenantID: tenantID})
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		code, err := randomToken(24)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The client gets the random code; the store gets only its hash, so
		// a leaked store dump cannot be redeemed at /token. The PKCE and
		// scope parameters are recorded as data for a later PR to verify.
		err = idp.codes.SaveCode(r.Context(), AuthCode{
			CodeHash:            hashToken(code),
			UserID:              user.ID,
			TenantID:            user.TenantID,
			ClientID:            clientID,
			Nonce:               nonce,
			RedirectURI:         canonicalRedirect,
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			Scope:               q.Get("scope"),
			ExpiresAt:           idp.now().Add(idp.codeTTL()),
		})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Use the canonical (server-controlled) URI, not the raw user input.
		redir, err := url.Parse(canonicalRedirect)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rq := redir.Query()
		rq.Set("code", code)
		if state != "" {
			rq.Set("state", state)
		}
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
		return
	}

	// GET: return a minimal login form
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<form method="POST">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<input name="tenant_id" placeholder="Tenant ID" value="">
<button type="submit">Sign In</button>
</form></body></html>`)
}

func (idp *IDP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	client, ok := idp.clients[clientID]
	if !ok || client.ClientSecret != clientSecret {
		http.Error(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	// ConsumeCode is destructive: whichever request reaches the store first
	// gets the record and every later one, on any process, gets ErrInvalidCode.
	// That is the whole single-use guarantee, so nothing is cached here. The
	// expiry re-check is belt and braces against a store that does not honour
	// the "expired is absent" clause of the AuthCodeStore contract.
	meta, err := idp.codes.ConsumeCode(r.Context(), hashToken(code))
	if err != nil || idp.now().After(meta.ExpiresAt) {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	// RFC 6749 §4.1.3: the code must have been issued to the client now
	// redeeming it. The map never checked this; the record carries ClientID
	// precisely so the store can be asked.
	if meta.ClientID != clientID {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	user, err := idp.authSvc.users.GetUserByID(r.Context(), meta.UserID, meta.TenantID)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	// The session pair, HS256. Which pair /token returns is decision D-15 of
	// the upstream plan and is not settled here; IssueIdPTokenPair exists for
	// a host that wants the RS256 pair now. expires_in below is this pair's
	// access lifetime, Config.AccessTokenTTL: the lifetime of the token in the
	// body, not IDPConfig.AccessTokenTTL, which governs only the IdP pair.
	tokens, err := idp.authSvc.newSessionTokens(r.Context(), user)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	idTok, err := idp.buildIDToken(user, clientID, meta.Nonce)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"id_token":      idTok,
		"token_type":    "Bearer",
		"expires_in":    int(tokens.ExpiresIn.Seconds()),
	})
}

func (idp *IDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	// Authenticate, not Me: the body below is sub, email and name, none of
	// which Config.BuildTokenClaims contributes, so running the hook here would
	// cost a relying party a claims round trip per userinfo call for nothing.
	user, err := idp.authSvc.Authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"sub":   user.ID,
		"email": user.Email,
		"name":  strings.TrimSpace(user.FirstName + " " + user.LastName),
	})
}

func (idp *IDP) buildIDToken(user User, audience, nonce string) (string, error) {
	now := idp.now()
	ttl := idp.cfg.IDTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	claims := map[string]any{
		"iss":   idp.cfg.Issuer,
		"sub":   user.ID,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"email": user.Email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return BuildRS256JWT(idp.signer, idp.keyID, claims)
}

// idpMatchedRedirect returns the canonical redirect URI from the allowlist that
// exactly matches the requested URI. This ensures the redirect target is always
// a server-controlled value, not a raw user-supplied string.
func idpMatchedRedirect(allowed []string, requested string) string {
	for _, u := range allowed {
		if u == requested {
			return u
		}
	}
	return ""
}
