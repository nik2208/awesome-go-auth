package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuthProvider holds configuration for a single OAuth 2.0 provider. It is the
// reference's GenericOAuthProviderConfig (generic-oauth.strategy.ts:39-78) with
// the two hard-coded strategies, Google and GitHub, expressed as presets.
type OAuthProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	// AdditionalAuthParams are extra query parameters for the authorization
	// URL — provider-specific knobs such as Google's access_type or prompt. They
	// are the reference's additionalAuthParams (generic-oauth.strategy.ts:63) and
	// keep its precedence exactly (:113-120): an entry overrides client_id,
	// redirect_uri, response_type and scope, and state overrides an entry. The
	// PKCE pair this port adds (code_challenge, code_challenge_method) is written
	// after them as well, so a configuration cannot weaken the code binding.
	AdditionalAuthParams map[string]string
	// GitHubEmailsURL is the endpoint the "github" provider consults when the
	// user profile carries no email — a GitHub account whose address is private
	// (github.strategy.ts:54-68). Empty means UserInfoURL + "/emails", which is
	// https://api.github.com/user/emails for the preset; a test points it at a
	// fake. Only the "github" provider reads it.
	GitHubEmailsURL string
}

// OAuthUserInfo is the normalized profile returned after token exchange — the
// reference's {id, email, emailVerified?, name?, picture?}
// (generic-oauth.strategy.ts:143, :154-160), plus the provider name and the raw
// document.
type OAuthUserInfo struct {
	ProviderID string
	Provider   string
	Email      string
	Name       string
	AvatarURL  string
	// EmailVerified is the provider's email_verified claim, or for GitHub the
	// verified flag of the address picked from /user/emails. nil means the
	// provider said nothing, the reference's `emailVerified: undefined`; the
	// callback's provisioning does not read it yet.
	EmailVerified *bool
	Raw           map[string]any
}

// PendingLinkStore holds temporary OAuth link state.
type PendingLinkStore interface {
	Save(ctx context.Context, state string, meta OAuthPendingMeta, ttl time.Duration) error
	Get(ctx context.Context, state string) (OAuthPendingMeta, error)
	Delete(ctx context.Context, state string) error
}

// OAuthPendingMeta is the metadata stored during OAuth flow.
type OAuthPendingMeta struct {
	Provider    string
	RedirectURL string
	TenantID    string
	UserID      string // non-empty when linking to existing account
	// Email and ProviderAccountID carry the account-linking stash: the address
	// a /link-request token was issued for, and the provider account a callback
	// conflict parked for it.
	Email             string
	ProviderAccountID string
	// ExpiresAt lets a consumer enforce the deadline itself rather than trusting
	// the store to have honoured the ttl argument.
	ExpiresAt time.Time
}

// OAuthLinkedAccount stores a linked provider<->user association.
//
// Email, Name and Picture are the reference's optional LinkedAccount profile
// columns (linked-accounts-store.interface.ts:9-14). GET /linked-accounts
// projects all three, and clients render them: the family admin UI falls back
// through `a.name || a.email || a.providerAccountId`. The library fills Email at
// every link it writes, as the reference's linkAccount calls do; Name and Picture
// are left for a host store that wants to keep them, again as in the reference.
type OAuthLinkedAccount struct {
	ID         string
	UserID     string
	Provider   string
	ProviderID string
	Email      string
	Name       string
	Picture    string
	CreatedAt  time.Time
}

// LinkedAccountStore persists OAuth provider associations per user.
type LinkedAccountStore interface {
	Save(ctx context.Context, link OAuthLinkedAccount) error
	FindByProvider(ctx context.Context, provider, providerID string) (OAuthLinkedAccount, error)
	ListForUser(ctx context.Context, userID string) ([]OAuthLinkedAccount, error)
	Delete(ctx context.Context, id string) error
}

// OAuthService handles OAuth 2.0 authorization code flow.
type OAuthService struct {
	providers map[string]OAuthProvider
	client    *http.Client
}

// NewOAuthService creates an OAuthService for the given providers.
func NewOAuthService(providers ...OAuthProvider) *OAuthService {
	m := make(map[string]OAuthProvider, len(providers))
	for _, p := range providers {
		m[p.Name] = p
	}
	return &OAuthService{providers: m, client: &http.Client{Timeout: 10 * time.Second}}
}

// GoogleProvider builds a pre-configured Google OAuth2 provider — the
// reference's GoogleStrategy (google.strategy.ts:23-33, :53). The authorization
// request carries access_type=offline (:29), the one extra parameter that
// strategy sends; it sends no prompt.
func GoogleProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:                 "google",
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		RedirectURL:          redirectURL,
		AuthURL:              "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:             "https://oauth2.googleapis.com/token",
		UserInfoURL:          "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:               []string{"openid", "email", "profile"},
		AdditionalAuthParams: map[string]string{"access_type": "offline"},
	}
}

// GitHubProvider builds a pre-configured GitHub OAuth2 provider — the
// reference's GithubStrategy (github.strategy.ts:23-31, :49-70), including the
// /user/emails fallback for accounts with a private address.
func GitHubProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:            "github",
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		RedirectURL:     redirectURL,
		AuthURL:         "https://github.com/login/oauth/authorize",
		TokenURL:        "https://github.com/login/oauth/access_token",
		UserInfoURL:     "https://api.github.com/user",
		Scopes:          []string{"user:email"},
		GitHubEmailsURL: "https://api.github.com/user/emails",
	}
}

// AuthorizeURL builds the redirect URL for the given provider and state token.
func (s *OAuthService) AuthorizeURL(providerName, state string) (string, error) {
	return s.AuthorizeURLPKCE(providerName, state, "")
}

// AuthorizeURLPKCE builds the redirect URL and, when codeChallenge is non-empty,
// binds the exchange to it with the S256 method (RFC 7636). The HTTP routes
// always pass a challenge; the plain AuthorizeURL stays for embedders driving
// the service themselves.
func (s *OAuthService) AuthorizeURLPKCE(providerName, state, codeChallenge string) (string, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return "", fmt.Errorf("auth: unknown oauth provider %q", providerName)
	}
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.Scopes, " "))
	// The reference spreads additionalAuthParams over the four standard
	// parameters and then state over it (generic-oauth.strategy.ts:113-120):
	// later keys win, so an entry can replace scope or redirect_uri but never
	// state. The PKCE pair has no reference counterpart and is written last for
	// the same reason.
	for key, value := range p.AdditionalAuthParams {
		q.Set(key, value)
	}
	q.Set("state", state)
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for user info.
func (s *OAuthService) ExchangeCode(ctx context.Context, providerName, code string) (OAuthUserInfo, error) {
	return s.ExchangeCodePKCE(ctx, providerName, code, "")
}

// ExchangeCodePKCE exchanges an authorization code, sending the PKCE verifier
// when one was used to build the authorization URL.
func (s *OAuthService) ExchangeCodePKCE(ctx context.Context, providerName, code, codeVerifier string) (OAuthUserInfo, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return OAuthUserInfo{}, fmt.Errorf("auth: unknown oauth provider %q", providerName)
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.RedirectURL)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return OAuthUserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthTokenExchange, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthTokenExchange, err)
	}
	if resp.StatusCode >= 400 {
		return OAuthUserInfo{}, fmt.Errorf("%w: status %d", errOAuthTokenExchange, resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: parse token response: %v", errOAuthTokenExchange, err)
	}
	if tok.Error != "" || tok.AccessToken == "" {
		return OAuthUserInfo{}, fmt.Errorf("%w: %s", errOAuthTokenExchange, tok.Error)
	}

	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return OAuthUserInfo{}, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uReq.Header.Set("Accept", "application/json")

	uResp, err := s.client.Do(uReq)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	defer uResp.Body.Close()
	uBody, err := io.ReadAll(uResp.Body)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}
	// The status check is new: without it a provider's 401 JSON parsed cleanly
	// into an empty profile and the callback went on to create a user with no
	// email and no provider id.
	if uResp.StatusCode >= 400 {
		return OAuthUserInfo{}, fmt.Errorf("%w: status %d", errOAuthProfile, uResp.StatusCode)
	}
	var raw map[string]any
	if err := json.Unmarshal(uBody, &raw); err != nil {
		return OAuthUserInfo{}, fmt.Errorf("%w: %v", errOAuthProfile, err)
	}

	info := OAuthUserInfo{Provider: providerName, Raw: raw}
	switch providerName {
	case "google":
		// GoogleStrategy.getUserProfile (google.strategy.ts:57-58): sub, email,
		// email_verified, name, picture.
		info.ProviderID, _ = raw["sub"].(string)
		info.Email, _ = raw["email"].(string)
		info.EmailVerified = optionalBool(raw["email_verified"])
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["picture"].(string)
	case "github":
		// GithubStrategy.getUserProfile (github.strategy.ts:59-69): String(id),
		// email, name ?? login, avatar_url. emailVerified is only ever known when
		// the address came from /user/emails, which is consulted when the profile
		// has none (:60-68).
		info.ProviderID = subjectID(raw["id"])
		info.Email, _ = raw["email"].(string)
		if info.Name, _ = raw["name"].(string); info.Name == "" {
			info.Name, _ = raw["login"].(string)
		}
		info.AvatarURL, _ = raw["avatar_url"].(string)
		if info.Email == "" {
			info.Email, info.EmailVerified = s.githubEmailFallback(ctx, p, tok.AccessToken)
		}
	default:
		// The reference's default mapping, id ?? sub (generic-oauth.strategy.ts:
		// 154-160). user_id is this port's extra last resort, kept because
		// providers registered against earlier versions may rely on it; it only
		// widens what is accepted.
		for _, k := range []string{"id", "sub", "user_id"} {
			if v := subjectID(raw[k]); v != "" {
				info.ProviderID = v
				break
			}
		}
		info.Email, _ = raw["email"].(string)
		info.EmailVerified = optionalBool(raw["email_verified"])
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["avatar_url"].(string)
	}
	return info, nil
}

// subjectID renders a provider's subject the way the reference's
// String(raw.id ?? raw.sub ?? "") does: a string as-is, a JSON number without
// a trailing ".0" (GitHub's id is a number), anything else as "". An empty
// string reads as absent so the next candidate is tried — the one place this is
// looser than the reference, which would keep the empty id.
func subjectID(v any) string {
	switch id := v.(type) {
	case string:
		return id
	case float64:
		return strconv.FormatFloat(id, 'f', -1, 64)
	default:
		return ""
	}
}

// optionalBool reads a JSON boolean claim as the reference's `as boolean |
// undefined` cast does: a boolean is taken, anything else — absent, null, a
// string "true" — is nil.
func optionalBool(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// githubEmailsURL is the endpoint githubEmailFallback calls: the configured
// override, else UserInfoURL + "/emails", which for the real API is
// https://api.github.com/user/emails.
func githubEmailsURL(p OAuthProvider) string {
	if p.GitHubEmailsURL != "" {
		return p.GitHubEmailsURL
	}
	return strings.TrimSuffix(p.UserInfoURL, "/") + "/emails"
}

// githubEmailFallback is github.strategy.ts:54-68 for a profile with no email:
// GET /user/emails with the reference's `Authorization: token` scheme and
// `Accept: application/vnd.github.v3+json` (:55), pick the entry that is both
// primary and verified, else the first one, and report its verified flag. A
// failed call is not an error — the reference gates on `emailRes.ok` and
// otherwise leaves the email empty — so a transport error, a non-2xx or an
// unparsable body all answer ("", nil).
func (s *OAuthService) githubEmailFallback(ctx context.Context, p OAuthProvider, accessToken string) (string, *bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailsURL(p), nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode >= 400 {
		return "", nil
	}
	var entries []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) == 0 {
		return "", nil
	}
	chosen := entries[0]
	for _, entry := range entries {
		if entry.Primary && entry.Verified {
			chosen = entry
			break
		}
	}
	verified := chosen.Verified
	return chosen.Email, &verified
}

// HandleCallback resolves/creates a user after OAuth callback.
// If linkToUserID is non-empty the provider is linked to that existing account.
func (s *OAuthService) HandleCallback(
	ctx context.Context,
	authSvc *Service,
	linkedAccounts LinkedAccountStore,
	info OAuthUserInfo,
	tenantID string,
	linkToUserID string,
) (User, AuthTokens, error) {
	if linkToUserID != "" {
		linkID, err := newID("lnk")
		if err != nil {
			return User{}, AuthTokens{}, err
		}
		link := OAuthLinkedAccount{
			ID:         linkID,
			UserID:     linkToUserID,
			Provider:   info.Provider,
			ProviderID: info.ProviderID,
			Email:      info.Email,
			CreatedAt:  time.Now(),
		}
		if err := linkedAccounts.Save(ctx, link); err != nil {
			return User{}, AuthTokens{}, fmt.Errorf("auth: link account: %w", err)
		}
		user, err := authSvc.users.GetUserByID(ctx, linkToUserID, tenantID)
		if err != nil {
			return User{}, AuthTokens{}, ErrInvalidCredentials
		}
		tokens, err := authSvc.newSessionTokens(ctx, user)
		return user, tokens, err
	}

	// Try existing link
	link, err := linkedAccounts.FindByProvider(ctx, info.Provider, info.ProviderID)
	if err == nil {
		user, err := authSvc.users.GetUserByID(ctx, link.UserID, tenantID)
		if err != nil {
			return User{}, AuthTokens{}, ErrInvalidCredentials
		}
		tokens, err := authSvc.newSessionTokens(ctx, user)
		return user, tokens, err
	}

	// Try by email
	if info.Email != "" {
		user, err := authSvc.users.GetUserByEmail(ctx, info.Email, tenantID)
		if err == nil {
			linkID, _ := newID("lnk")
			// The reference's linkAccount always carries the callback profile's
			// email (auth.router.ts:1336-1343), which is what GET /linked-accounts
			// renders.
			_ = linkedAccounts.Save(ctx, OAuthLinkedAccount{
				ID: linkID, UserID: user.ID,
				Provider: info.Provider, ProviderID: info.ProviderID,
				Email:     info.Email,
				CreatedAt: time.Now(),
			})
			tokens, err := authSvc.newSessionTokens(ctx, user)
			return user, tokens, err
		}
	}

	// Create new user
	userID, err := newID("usr")
	if err != nil {
		return User{}, AuthTokens{}, err
	}
	now := time.Now()
	// LoginProvider records which provider created the account, the way the
	// reference's strategy documents creating one
	// (`userStore.create({ email, loginProvider: 'microsoft' })`,
	// generic-oauth.strategy.ts:92; user.model.ts:15). An account the callback
	// only links — found above by provider id or by email — keeps the provider
	// it was created with, as the reference's linkAccount changes no user row.
	newUser, err := authSvc.users.CreateUser(ctx, User{
		ID:              userID,
		Email:           info.Email,
		TenantID:        tenantID,
		LoginProvider:   info.Provider,
		IsEmailVerified: true,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if err != nil {
		return User{}, AuthTokens{}, fmt.Errorf("auth: create oauth user: %w", err)
	}
	linkID, _ := newID("lnk")
	_ = linkedAccounts.Save(ctx, OAuthLinkedAccount{
		ID: linkID, UserID: newUser.ID,
		Provider: info.Provider, ProviderID: info.ProviderID,
		Email:     info.Email,
		CreatedAt: now,
	})
	tokens, err := authSvc.newSessionTokens(ctx, newUser)
	return newUser, tokens, err
}

// MemoryLinkedAccounts is an in-memory implementation of LinkedAccountStore,
// suitable for development, testing, and embedded deployments.
type MemoryLinkedAccounts struct {
	mu    sync.RWMutex
	byID  map[string]OAuthLinkedAccount            // id -> link
	byPrv map[string]map[string]OAuthLinkedAccount // provider -> providerID -> link
	byUsr map[string][]OAuthLinkedAccount          // userID -> links
}

// NewMemoryLinkedAccounts creates an in-memory LinkedAccountStore.
func NewMemoryLinkedAccounts() *MemoryLinkedAccounts {
	return &MemoryLinkedAccounts{
		byID:  make(map[string]OAuthLinkedAccount),
		byPrv: make(map[string]map[string]OAuthLinkedAccount),
		byUsr: make(map[string][]OAuthLinkedAccount),
	}
}

func (m *MemoryLinkedAccounts) Save(_ context.Context, link OAuthLinkedAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[link.ID] = link
	if m.byPrv[link.Provider] == nil {
		m.byPrv[link.Provider] = make(map[string]OAuthLinkedAccount)
	}
	m.byPrv[link.Provider][link.ProviderID] = link
	// Replace existing entry for the same ID to prevent duplicates.
	links := m.byUsr[link.UserID]
	for i, l := range links {
		if l.ID == link.ID {
			links[i] = link
			m.byUsr[link.UserID] = links
			return nil
		}
	}
	m.byUsr[link.UserID] = append(links, link)
	return nil
}

func (m *MemoryLinkedAccounts) FindByProvider(_ context.Context, provider, providerID string) (OAuthLinkedAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if prv, ok := m.byPrv[provider]; ok {
		if link, ok := prv[providerID]; ok {
			return link, nil
		}
	}
	return OAuthLinkedAccount{}, fmt.Errorf("auth: linked account not found")
}

func (m *MemoryLinkedAccounts) ListForUser(_ context.Context, userID string) ([]OAuthLinkedAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]OAuthLinkedAccount, len(m.byUsr[userID]))
	copy(out, m.byUsr[userID])
	return out, nil
}

func (m *MemoryLinkedAccounts) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	link, ok := m.byID[id]
	if !ok {
		return nil
	}
	delete(m.byID, id)
	if prv, ok := m.byPrv[link.Provider]; ok {
		delete(prv, link.ProviderID)
	}
	links := m.byUsr[link.UserID]
	out := links[:0]
	for _, l := range links {
		if l.ID != id {
			out = append(out, l)
		}
	}
	m.byUsr[link.UserID] = out
	return nil
}
