package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultAuthCodeTTL is how long an authorization code stays redeemable when
// IDPConfig.CodeTTL is unset. Five minutes is the value the process-local map
// hardcoded before the store seam existed, so existing callers see no change.
const defaultAuthCodeTTL = 5 * time.Minute

// IDPConfig configures the OIDC Identity Provider.
type IDPConfig struct {
	Issuer         string
	AccessTokenTTL time.Duration
	IDTokenTTL     time.Duration

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
	cfg        IDPConfig
	authSvc    *Service
	privateKey *rsa.PrivateKey
	keyID      string
	clients    map[string]IDPClient
	// codes is cfg.Codes with the nil default resolved. Every code handed to a
	// client is looked up here by hashToken(code); nothing in the IDP holds a
	// code or its record after the handler returns, which is what lets
	// /authorize and /token run on different processes.
	codes AuthCodeStore
}

// NewIDP creates a new OIDC IDP backed by the given auth service.
//
// A nil cfg.Codes falls back to an in-process MemoryAuthCodeStore; see
// IDPConfig.Codes for when that is not enough.
func NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("auth: idp key generation: %w", err)
	}
	kid, err := randomToken(8)
	if err != nil {
		return nil, err
	}
	cm := make(map[string]IDPClient, len(clients))
	for _, c := range clients {
		cm[c.ClientID] = c
	}
	codes := cfg.Codes
	if codes == nil {
		codes = NewMemoryAuthCodeStore()
	}
	return &IDP{cfg: cfg, authSvc: authSvc, privateKey: key, keyID: kid, clients: cm, codes: codes}, nil
}

// codeTTL resolves IDPConfig.CodeTTL, applying the five-minute default.
func (idp *IDP) codeTTL() time.Duration {
	if idp.cfg.CodeTTL <= 0 {
		return defaultAuthCodeTTL
	}
	return idp.cfg.CodeTTL
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
	pub := &idp.privateKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256",
			"kid": idp.keyID, "n": n, "e": e,
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks) //nolint:errcheck
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
			ExpiresAt:           time.Now().Add(idp.codeTTL()),
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
	if err != nil || time.Now().After(meta.ExpiresAt) {
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
		"expires_in":    int(idp.cfg.AccessTokenTTL.Seconds()),
	})
}

func (idp *IDP) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	user, err := idp.authSvc.Me(r.Context(), token)
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
	now := time.Now()
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
	return buildRS256JWT(idp.privateKey, idp.keyID, claims)
}

// buildRS256JWT creates a signed RS256 JWT using only standard library packages.
func buildRS256JWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", fmt.Errorf("auth: idp jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: idp jwt payload: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := header + "." + payload

	digest := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("auth: idp rsa sign: %w", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
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
