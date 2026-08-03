package wiretest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the OAuth and account-linking group
// (wire-contract.md §4). Everything asserted here is an exact value: a status,
// a literal error message and code, a cookie attribute set, or the exact set of
// top-level body keys. "Non-empty" is only ever used for values the server
// generates at random, and even those get a length or a derivation check.

const testProvider = "acme"

// RunOAuthLinking executes the OAuth and account-linking suite.
func RunOAuthLinking(t *testing.T, mount Mounter) {
	t.Run("OAuthAuthorize", func(t *testing.T) { testOAuthAuthorize(t, mount) })
	t.Run("OAuthCallback", func(t *testing.T) { testOAuthCallback(t, mount) })
	t.Run("OAuthStateVerification", func(t *testing.T) { testOAuthStateVerification(t, mount) })
	t.Run("LinkedAccountsList", func(t *testing.T) { testLinkedAccountsList(t, mount) })
	t.Run("LinkedAccountsDelete", func(t *testing.T) { testLinkedAccountsDelete(t, mount) })
	t.Run("LinkRequest", func(t *testing.T) { testLinkRequest(t, mount) })
	t.Run("LinkVerify", func(t *testing.T) { testLinkVerify(t, mount) })
}

// ── fixture ──────────────────────────────────────────────────────────────────

// fakeOAuthProvider stands in for the identity provider's token and userinfo
// endpoints. It records the token-exchange form so the PKCE assertions can
// check what actually went over the wire.
type fakeOAuthProvider struct {
	server *httptest.Server

	mu            sync.Mutex
	tokenForm     url.Values
	profileStatus int
}

func newFakeOAuthProvider(t *testing.T) *fakeOAuthProvider {
	t.Helper()
	p := &fakeOAuthProvider{profileStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.tokenForm = r.PostForm
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"provider-access-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		status := p.profileStatus
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{"sub":"acme-1","email":"oauth@example.com","name":"OAuth User"}`))
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeOAuthProvider) form() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenForm
}

func (p *fakeOAuthProvider) failProfile() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.profileStatus = http.StatusUnauthorized
}

// oauthFixture is an Env with the OAuth wiring attached.
type oauthFixture struct {
	*Env
	provider *fakeOAuthProvider
	links    *auth.MemoryLinkedAccounts
	pending  *auth.MemoryPendingLinks

	mu        sync.Mutex
	delivered []auth.LinkTokenDelivery
}

type fixtureOptions struct {
	// omitStores drops the linking stores, the port's analogue of the
	// reference's "route not mounted without linkedAccountsStore".
	omitStores bool
	// omitPending drops only the stash, which is what turns the state nonce from
	// single-use back into merely signed.
	omitPending bool
	allowed     []string
}

const fixtureSiteURL = "https://app.example.com"

func newOAuthFixture(t *testing.T, mount Mounter, opts fixtureOptions) *oauthFixture {
	t.Helper()
	provider := newFakeOAuthProvider(t)
	fixture := &oauthFixture{
		provider: provider,
		links:    auth.NewMemoryLinkedAccounts(),
		pending:  auth.NewMemoryPendingLinks(),
	}
	wiring := auth.OAuthWiring{
		Service: auth.NewOAuthService(auth.OAuthProvider{
			Name:         testProvider,
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://api.example.com/auth/oauth/acme/callback",
			AuthURL:      "https://provider.example.com/authorize",
			TokenURL:     provider.server.URL + "/token",
			UserInfoURL:  provider.server.URL + "/userinfo",
			Scopes:       []string{"openid", "email"},
		}),
		LinkedAccounts: fixture.links,
		PendingLinks:   fixture.pending,
		AllowedOrigins: opts.allowed,
		SiteURL:        fixtureSiteURL,
		TenantID:       "t1",
		DeliverLinkToken: func(_ context.Context, delivery auth.LinkTokenDelivery) error {
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			fixture.delivered = append(fixture.delivered, delivery)
			return nil
		},
	}
	if opts.omitStores {
		wiring.LinkedAccounts = nil
		wiring.PendingLinks = nil
	}
	if opts.omitPending {
		wiring.PendingLinks = nil
	}
	fixture.Env = NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithOAuth(wiring))
	return fixture
}

func (f *oauthFixture) lastDelivery(t *testing.T) auth.LinkTokenDelivery {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.delivered) == 0 {
		t.Fatal("no account-link token was delivered")
	}
	return f.delivered[len(f.delivered)-1]
}

// begin drives GET <prefix>/oauth/<provider> and returns the parsed redirect.
func (f *oauthFixture) begin(t *testing.T, query string, headers map[string]string) *url.URL {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/oauth/"+testProvider+query, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := f.Do(req)
	AssertStatus(t, rec, http.StatusFound)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	return location
}

func (f *oauthFixture) callback(t *testing.T, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	target := f.Config.Prefix() + "/oauth/" + testProvider + "/callback?code=" + url.QueryEscape(code)
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}
	return f.Do(httptest.NewRequest(http.MethodGet, target, nil))
}

// decodeStatePayload splits the signed state and decodes the payload half.
func decodeStatePayload(t *testing.T, state string) map[string]any {
	t.Helper()
	encoded, signature, found := strings.Cut(state, ".")
	if !found {
		t.Fatalf("state %q is not signed: expected <payload>.<signature>", state)
	}
	if signature == "" {
		t.Fatalf("state %q carries an empty signature", state)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("state payload is not base64url: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("state payload is not JSON: %v", err)
	}
	return payload
}

// ── GET /oauth/{provider} ────────────────────────────────────────────────────

func testOAuthAuthorize(t *testing.T, mount Mounter) {
	t.Run("redirects to the provider with a signed state and an S256 challenge", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})

		if got := location.Scheme + "://" + location.Host + location.Path; got != "https://provider.example.com/authorize" {
			t.Fatalf("authorization endpoint = %q", got)
		}
		query := location.Query()
		for key, want := range map[string]string{
			"client_id":             "test-client-id",
			"redirect_uri":          "https://api.example.com/auth/oauth/acme/callback",
			"response_type":         "code",
			"scope":                 "openid email",
			"code_challenge_method": "S256",
		} {
			if got := query.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		// 32 bytes of SHA-256 render as 43 base64url characters.
		if challenge := query.Get("code_challenge"); len(challenge) != 43 {
			t.Errorf("code_challenge = %q, want 43 base64url characters", challenge)
		}

		payload := decodeStatePayload(t, query.Get("state"))
		if nonce, _ := payload["n"].(string); len(nonce) != 32 {
			t.Errorf("state nonce = %v, want 32 hex characters", payload["n"])
		}
		if payload["o"] != fixtureSiteURL {
			t.Errorf("state origin = %v, want %q", payload["o"], fixtureSiteURL)
		}
		if payload["p"] != "/dashboard" {
			t.Errorf("state return path = %v, want %q", payload["p"], "/dashboard")
		}
		if issued, _ := payload["t"].(float64); issued <= 0 {
			t.Errorf("state issued-at = %v, want a unix timestamp", payload["t"])
		}
	})

	t.Run("an origin outside the allowlist falls back to the site url", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": "https://evil.example.net"})
		payload := decodeStatePayload(t, location.Query().Get("state"))
		if payload["o"] != fixtureSiteURL {
			t.Fatalf("state origin = %v, want the configured site url %q", payload["o"], fixtureSiteURL)
		}
	})

	// The reference registers a JSON stub only for google and github and lets
	// every other unregistered name fall through to Express's HTML 404. One
	// dynamic route cannot do that, so every unregistered name gets the stub —
	// with the reference's per-provider wording for the two it names.
	t.Run("unregistered provider", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		for name, want := range map[string]string{
			"google": "Google OAuth not configured",
			"github": "GitHub OAuth not configured",
			"nope":   "nope OAuth not configured",
		} {
			rec := f.Do(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/oauth/"+name, nil))
			AssertError(t, rec, http.StatusNotFound, want, "")
		}
	})
}

// ── GET /oauth/{provider}/callback ───────────────────────────────────────────

func testOAuthCallback(t *testing.T, mount Mounter) {
	t.Run("issues cookies and redirects to the state origin", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "?return_path=/dashboard", map[string]string{"Origin": fixtureSiteURL})
		challenge := location.Query().Get("code_challenge")

		rec := f.callback(t, "auth-code", location.Query().Get("state"))
		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL+"/dashboard" {
			t.Fatalf("Location = %q, want %q", got, fixtureSiteURL+"/dashboard")
		}
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())

		// PKCE actually reached the provider, and the verifier matches the
		// challenge the authorization request advertised.
		form := f.provider.form()
		if got := form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := form.Get("code"); got != "auth-code" {
			t.Errorf("code = %q, want %q", got, "auth-code")
		}
		verifier := form.Get("code_verifier")
		if len(verifier) < 43 || len(verifier) > 128 {
			t.Fatalf("code_verifier = %q, want 43..128 characters (RFC 7636)", verifier)
		}
		sum := sha256.Sum256([]byte(verifier))
		if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
			t.Fatalf("S256(code_verifier) = %q, want the advertised challenge %q", got, challenge)
		}
	})

	// The reference ignores X-Auth-Strategy on redirect flows: issueTokens with
	// a redirectTo always takes the cookie branch.
	t.Run("the bearer header does not change a redirect flow", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		target := f.Config.Prefix() + "/oauth/" + testProvider + "/callback?code=c&state=" + url.QueryEscape(location.Query().Get("state"))
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusFound)
		if got := rec.Header().Get("Location"); got != fixtureSiteURL {
			t.Fatalf("Location = %q, want %q", got, fixtureSiteURL)
		}
		Cookie(t, rec, hostAccess)
		if body := rec.Body.String(); strings.Contains(body, "accessToken") {
			t.Fatalf("redirect body leaked a token: %s", body)
		}
	})

	t.Run("the callback links the provider account to the resolved user", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		AssertStatus(t, f.callback(t, "c", location.Query().Get("state")), http.StatusFound)

		link, err := f.links.FindByProvider(context.Background(), testProvider, "acme-1")
		if err != nil {
			t.Fatalf("provider account was not linked: %v", err)
		}
		if link.Provider != testProvider || link.ProviderID != "acme-1" {
			t.Fatalf("link = %+v", link)
		}
	})

	// A provider that answers the userinfo call with an error must not produce a
	// user with an empty email. The reference emits OAUTH_PROFILE_FAILED here.
	t.Run("profile failure", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		location := f.begin(t, "", map[string]string{"Origin": fixtureSiteURL})
		f.provider.failProfile()
		rec := f.callback(t, "c", location.Query().Get("state"))
		AssertError(t, rec, http.StatusUnauthorized, "Failed to get OAuth user profile", auth.CodeOAuthProfileFailed)
	})
}

// ── the #10 fix ──────────────────────────────────────────────────────────────

// testOAuthStateVerification is the security half of this group. The reference
// generates a state nonce and never reads it (wire-contract.md §4, gap 4);
// every case here fails against that behaviour.
func testOAuthStateVerification(t *testing.T, mount Mounter) {
	newState := func(t *testing.T, f *oauthFixture) string {
		t.Helper()
		return f.begin(t, "", map[string]string{"Origin": fixtureSiteURL}).Query().Get("state")
	}

	t.Run("a missing state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		AssertError(t, f.callback(t, "c", ""), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// The nonce is kept intact so the stash lookup would succeed: only the
	// signature can reject this, which is what makes the case a test of the
	// signature rather than of the replay defence behind it.
	t.Run("a tampered payload is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		payload, signature, _ := strings.Cut(state, ".")
		nonce, _ := decodeStatePayload(t, state)["n"].(string)
		// Re-point the redirect origin at an attacker while keeping the original
		// nonce and signature: the classic open redirect through the state.
		forged := base64.RawURLEncoding.EncodeToString([]byte(
			`{"n":"` + nonce + `","o":"https://evil.example.net","t":` + nowUnixString() + `}`))
		if forged == payload {
			t.Fatal("forged payload accidentally equals the real one")
		}
		rec := f.callback(t, "c", forged+"."+signature)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
		if location := rec.Header().Get("Location"); location != "" {
			t.Fatalf("tampered state produced a redirect to %q", location)
		}
	})

	// This is the shape the reference emits: plain base64url JSON, no signature.
	// Again the real nonce is reused, so the stash cannot be what rejects it.
	t.Run("an unsigned reference-style state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		nonce, _ := decodeStatePayload(t, newState(t, f))["n"].(string)
		unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"n":"` + nonce + `","o":"` + fixtureSiteURL + `"}`))
		rec := f.callback(t, "c", unsigned)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	t.Run("a signature over a different payload is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		first := newState(t, f)
		second := newState(t, f)
		payload, _, _ := strings.Cut(first, ".")
		_, signature, _ := strings.Cut(second, ".")
		rec := f.callback(t, "c", payload+"."+signature)
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// Single use. With the stash configured the nonce is consumed by the first
	// callback, so an intercepted state cannot be replayed inside its TTL.
	t.Run("a replayed state is rejected", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)
		AssertError(t, f.callback(t, "c", state), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})

	// Without a stash the state stays signed and time-bounded but replayable —
	// pinned so the degradation is a documented property, not a surprise.
	t.Run("without a pending-link store the state is signed but replayable", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitPending: true, allowed: []string{fixtureSiteURL}})
		state := newState(t, f)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)
		AssertStatus(t, f.callback(t, "c", state), http.StatusFound)

		forged := base64.RawURLEncoding.EncodeToString([]byte(`{"n":"x","o":"https://evil.example.net"}`))
		AssertError(t, f.callback(t, "c", forged), http.StatusUnauthorized, "Invalid or expired OAuth state", auth.CodeOAuthStateInvalid)
	})
}

func nowUnixString() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// ── GET /linked-accounts ─────────────────────────────────────────────────────

func testLinkedAccountsList(t *testing.T, mount Mounter) {
	linkedAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	// The object wrapper is a client-pinned invariant: Angular reads
	// res.linkedAccounts and the served auth.js expects the same. Flutter's
	// helper only accepts a bare array and therefore reads [] here — a known
	// CLIENT bug (wire-contract.md §4, mismatch 1), not a reason to unwrap.
	t.Run("returns the wrapped object", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, tokens := f.Seed("linked@example.com")
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_1", UserID: user.ID, Provider: "acme", ProviderID: "acme-1", CreatedAt: linkedAt,
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "linkedAccounts")
		accounts, ok := body["linkedAccounts"].([]any)
		if !ok || len(accounts) != 1 {
			t.Fatalf("linkedAccounts = %v, want one entry", body["linkedAccounts"])
		}
		entry, _ := accounts[0].(map[string]any)
		AssertKeys(t, entry, "provider", "providerAccountId", "linkedAt")
		if entry["provider"] != "acme" {
			t.Errorf("provider = %v, want %q", entry["provider"], "acme")
		}
		if entry["providerAccountId"] != "acme-1" {
			t.Errorf("providerAccountId = %v, want %q", entry["providerAccountId"], "acme-1")
		}
		if entry["linkedAt"] != linkedAt.Format(time.RFC3339Nano) {
			t.Errorf("linkedAt = %v, want %q", entry["linkedAt"], linkedAt.Format(time.RFC3339Nano))
		}
	})

	// [] and not null: a client that iterates the value must not have to
	// null-check it.
	t.Run("no links is an empty array", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("nolinks@example.com")
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		if got := strings.TrimSpace(rec.Body.String()); got != `{"linkedAccounts":[]}` {
			t.Fatalf("body = %s, want {\"linkedAccounts\":[]}", got)
		}
	})

	// 403 with no code, as the reference's auth middleware emits.
	t.Run("no token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	t.Run("unusable token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		AssertError(t, f.Do(req), http.StatusForbidden, "Invalid or expired access token", "")
	})

	// The reference leaves the route unmounted without a linkedAccountsStore, so
	// a caller gets Express's HTML 404. This port answers the family's
	// NOT_IMPLEMENTED envelope instead.
	t.Run("without a linked-accounts store", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		_, tokens := f.Seed("nostore@example.com")
		req := httptest.NewRequest(http.MethodGet, f.Config.Prefix()+"/linked-accounts", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})
}

// ── DELETE /linked-accounts/{provider}/{providerAccountId} ───────────────────

func testLinkedAccountsDelete(t *testing.T, mount Mounter) {
	seedLink := func(t *testing.T, f *oauthFixture, userID string) {
		t.Helper()
		if err := f.links.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "lnk_" + userID, UserID: userID, Provider: "acme", ProviderID: "acme-1", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}
	}
	del := func(f *oauthFixture, token, provider, accountID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/"+provider+"/"+accountID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return f.Do(req)
	}

	t.Run("removes the link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, tokens := f.Seed("unlink@example.com")
		seedLink(t, f, user.ID)

		rec := del(f, tokens.AccessToken, "acme", "acme-1")
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err == nil {
			t.Fatal("link survived the unlink")
		}
	})

	// No existence check in the reference: an unknown pair still answers success.
	t.Run("an unknown pair still succeeds", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("unlinkmissing@example.com")
		rec := del(f, tokens.AccessToken, "acme", "does-not-exist")
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	// Succeeds like every other unlink, but must not touch a link it does not
	// own — the reference scopes the store call by user id.
	t.Run("another user's link is left alone", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		owner, _ := f.Seed("owner@example.com")
		_, intruderTokens := f.Seed("intruder@example.com")
		seedLink(t, f, owner.ID)

		AssertStatus(t, del(f, intruderTokens.AccessToken, "acme", "acme-1"), http.StatusOK)
		if _, err := f.links.FindByProvider(context.Background(), "acme", "acme-1"); err != nil {
			t.Fatal("another user's link was deleted")
		}
	})

	// Unsafe method, cookie-authenticated: double-submit applies.
	t.Run("cookie mode without the CSRF header", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/acme/acme-1", nil)
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, f.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	t.Run("no token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := httptest.NewRequest(http.MethodDelete, f.Config.Prefix()+"/linked-accounts/acme/acme-1", nil)
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		AssertError(t, f.Do(req), http.StatusForbidden, "No access token provided", "")
	})
}

// ── POST /link-request ───────────────────────────────────────────────────────

func testLinkRequest(t *testing.T, mount Mounter) {
	t.Run("an authenticated caller gets a verification link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("linkreq@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "linkreq@example.com", "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		delivery := f.lastDelivery(t)
		if delivery.Email != "linkreq@example.com" || delivery.Provider != "acme" {
			t.Errorf("delivery = %+v", delivery)
		}
		// 32 random bytes as 64 hex characters, the reference's token size.
		if len(delivery.Token) != 64 {
			t.Errorf("token = %q, want 64 hex characters", delivery.Token)
		}
		wantURL := fixtureSiteURL + f.Config.Prefix() + "/link-verify?token=" + delivery.Token
		if delivery.URL != wantURL {
			t.Errorf("link = %q, want %q", delivery.URL, wantURL)
		}
		// The credential must never appear in the HTTP response.
		if strings.Contains(rec.Body.String(), delivery.Token) {
			t.Errorf("response leaked the account-link token: %s", rec.Body.String())
		}
	})

	t.Run("missing email", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, tokens := f.Seed("noemail@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusBadRequest, "email is required", auth.CodeEmailRequired)
	})

	// Unauthenticated and nothing stashed: the conflict flow has nothing to
	// resolve an identity from.
	t.Run("unauthenticated with no pending link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("nopending@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "nopending@example.com"})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		AssertError(t, f.Do(req), http.StatusUnauthorized, "Authentication required or no pending link found", auth.CodeUnauthorized)
	})

	// The conflict path: a stashed pending link stands in for authentication.
	t.Run("unauthenticated with a stashed pending link", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		f.Seed("conflict@example.com")
		if err := f.pending.Save(context.Background(), "pending-link:conflict@example.com|acme", auth.OAuthPendingMeta{
			Provider: "acme", Email: "conflict@example.com", ProviderAccountID: "acme-9", TenantID: "t1",
		}, time.Hour); err != nil {
			t.Fatalf("stash: %v", err)
		}
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "conflict@example.com", "provider": "acme"})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := f.Do(req)
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	t.Run("a stashed link for an unknown address", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		if err := f.pending.Save(context.Background(), "pending-link:ghost@example.com|email", auth.OAuthPendingMeta{
			Provider: "email", Email: "ghost@example.com", ProviderAccountID: "g-1",
		}, time.Hour); err != nil {
			t.Fatalf("stash: %v", err)
		}
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "ghost@example.com"})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		AssertError(t, f.Do(req), http.StatusNotFound, "Target user not found", auth.CodeUserNotFound)
	})

	t.Run("without the linking stores", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		_, tokens := f.Seed("nostorelink@example.com")
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "nostorelink@example.com"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertError(t, f.Do(req), http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})

	// Unsafe method with no auth middleware, but the reference CSRF-checks this
	// one by hand, so the exemption table must not list it.
	t.Run("cookie mode without the CSRF header", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": "csrf@example.com"})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertError(t, f.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})
}

// ── POST /link-verify ────────────────────────────────────────────────────────

func testLinkVerify(t *testing.T, mount Mounter) {
	// issueToken drives /link-request and returns the delivered token.
	issueToken := func(t *testing.T, f *oauthFixture, email string) (auth.User, string) {
		t.Helper()
		user, tokens := f.Seed(email)
		req := f.Request(http.MethodPost, "/link-request", map[string]any{"email": email, "provider": "acme"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		AssertStatus(t, f.Do(req), http.StatusOK)
		return user, f.lastDelivery(t).Token
	}

	t.Run("links the account and issues no session", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		user, token := issueToken(t, f, "verify@example.com")
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)

		links, err := f.links.ListForUser(context.Background(), user.ID)
		if err != nil || len(links) != 1 {
			t.Fatalf("links = %v (%v), want exactly one", links, err)
		}
		if links[0].Provider != "acme" {
			t.Errorf("provider = %q, want %q", links[0].Provider, "acme")
		}
		// With nothing stashed by a conflict, the reference defaults the provider
		// account id to the address.
		if links[0].ProviderID != "verify@example.com" {
			t.Errorf("providerAccountId = %q, want the email", links[0].ProviderID)
		}
	})

	t.Run("the token is single use", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "single@example.com")
		AssertStatus(t, f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})), http.StatusOK)
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid account-link token", auth.CodeInvalidLinkToken)
	})

	t.Run("missing token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{}))
		AssertError(t, rec, http.StatusBadRequest, "token is required", auth.CodeTokenRequired)
	})

	t.Run("unknown token", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": "nope"}))
		AssertError(t, rec, http.StatusBadRequest, "Invalid account-link token", auth.CodeInvalidLinkToken)
	})

	t.Run("loginAfterLinking in cookie mode", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "login-after@example.com")
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token, "loginAfterLinking": true}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	// The one route in this group where X-Auth-Strategy matters: it answers with
	// a body, so sendTokens applies.
	t.Run("loginAfterLinking in bearer mode", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "login-bearer@example.com")
		req := f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token, "loginAfterLinking": true})
		req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
		rec := f.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	// Asymmetric with /link-request on purpose: the reference performs no CSRF
	// check here at all, so the emailed link works from a browser with no
	// session and no CSRF cookie.
	t.Run("no CSRF check", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{})
		_, token := issueToken(t, f, "nocsrf@example.com")
		req := f.Request(http.MethodPost, "/link-verify", map[string]any{"token": token})
		req.AddCookie(&http.Cookie{Name: hostCSRF, Value: "not-mirrored-in-the-header"})
		AssertStatus(t, f.Do(req), http.StatusOK)
	})

	t.Run("without the linking stores", func(t *testing.T) {
		f := newOAuthFixture(t, mount, fixtureOptions{omitStores: true})
		rec := f.Do(f.Request(http.MethodPost, "/link-verify", map[string]any{"token": "anything"}))
		AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})
}
