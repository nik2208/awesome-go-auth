package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuthProvider holds configuration for a single OAuth 2.0 provider.
type OAuthProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
}

// OAuthUserInfo is the normalized profile returned after token exchange.
type OAuthUserInfo struct {
	ProviderID string
	Provider   string
	Email      string
	Name       string
	AvatarURL  string
	Raw        map[string]any
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
}

// OAuthLinkedAccount stores a linked provider<->user association.
type OAuthLinkedAccount struct {
	ID         string
	UserID     string
	Provider   string
	ProviderID string
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

// GoogleProvider builds a pre-configured Google OAuth2 provider.
func GoogleProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:         "google",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
	}
}

// GitHubProvider builds a pre-configured GitHub OAuth2 provider.
func GitHubProvider(clientID, clientSecret, redirectURL string) OAuthProvider {
	return OAuthProvider{
		Name:         "github",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		Scopes:       []string{"user:email"},
	}
}

// AuthorizeURL builds the redirect URL for the given provider and state token.
func (s *OAuthService) AuthorizeURL(providerName, state string) (string, error) {
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
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for user info.
func (s *OAuthService) ExchangeCode(ctx context.Context, providerName, code string) (OAuthUserInfo, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return OAuthUserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("auth: oauth token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return OAuthUserInfo{}, err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return OAuthUserInfo{}, fmt.Errorf("auth: parse token response: %w", err)
	}
	if tok.Error != "" || tok.AccessToken == "" {
		return OAuthUserInfo{}, fmt.Errorf("auth: oauth token error: %s", tok.Error)
	}

	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	if err != nil {
		return OAuthUserInfo{}, err
	}
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uReq.Header.Set("Accept", "application/json")

	uResp, err := s.client.Do(uReq)
	if err != nil {
		return OAuthUserInfo{}, fmt.Errorf("auth: oauth userinfo: %w", err)
	}
	defer uResp.Body.Close()
	uBody, err := io.ReadAll(uResp.Body)
	if err != nil {
		return OAuthUserInfo{}, err
	}
	var raw map[string]any
	if err := json.Unmarshal(uBody, &raw); err != nil {
		return OAuthUserInfo{}, err
	}

	info := OAuthUserInfo{Provider: providerName, Raw: raw}
	switch providerName {
	case "google":
		info.ProviderID, _ = raw["sub"].(string)
		info.Email, _ = raw["email"].(string)
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["picture"].(string)
	case "github":
		if id, ok := raw["id"].(float64); ok {
			info.ProviderID = fmt.Sprintf("%.0f", id)
		}
		info.Email, _ = raw["email"].(string)
		info.Name, _ = raw["login"].(string)
		info.AvatarURL, _ = raw["avatar_url"].(string)
	default:
		for _, k := range []string{"sub", "id", "user_id"} {
			if v, ok := raw[k].(string); ok && v != "" {
				info.ProviderID = v
				break
			}
		}
		info.Email, _ = raw["email"].(string)
		info.Name, _ = raw["name"].(string)
		info.AvatarURL, _ = raw["avatar_url"].(string)
	}
	return info, nil
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
			_ = linkedAccounts.Save(ctx, OAuthLinkedAccount{
				ID: linkID, UserID: user.ID,
				Provider: info.Provider, ProviderID: info.ProviderID,
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
	newUser, err := authSvc.users.CreateUser(ctx, User{
		ID:              userID,
		Email:           info.Email,
		TenantID:        tenantID,
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
		CreatedAt: now,
	})
	tokens, err := authSvc.newSessionTokens(ctx, newUser)
	return newUser, tokens, err
}

// MemoryLinkedAccounts is an in-memory implementation of LinkedAccountStore,
// suitable for development, testing, and embedded deployments.
type MemoryLinkedAccounts struct {
mu    sync.RWMutex
byID  map[string]OAuthLinkedAccount         // id -> link
byPrv map[string]map[string]OAuthLinkedAccount // provider -> providerID -> link
byUsr map[string][]OAuthLinkedAccount         // userID -> links
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
m.byUsr[link.UserID] = append(m.byUsr[link.UserID], link)
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
