package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ AuthCodeStore = (*MemoryAuthCodeStore)(nil)

func sampleAuthCode(code string, ttl time.Duration) AuthCode {
	return AuthCode{
		CodeHash:            hashToken(code),
		UserID:              "usr_1",
		TenantID:            "t1",
		ClientID:            "app",
		Nonce:               "n-1",
		RedirectURI:         "https://app.example.com/cb",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Scope:               "openid email",
		ExpiresAt:           time.Now().Add(ttl),
	}
}

// TestMemoryAuthCodeStoreConsumesOnce pins the single-use contract: the record
// comes back exactly once, intact, and every call after that — like a call
// before any save — answers ErrInvalidCode.
func TestMemoryAuthCodeStoreConsumesOnce(t *testing.T) {
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()
	want := sampleAuthCode("code-1", time.Minute)

	if _, err := store.ConsumeCode(ctx, want.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("consume before save = %v, want ErrInvalidCode", err)
	}
	if err := store.SaveCode(ctx, want); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	got, err := store.ConsumeCode(ctx, want.CodeHash)
	if err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	if got != want {
		t.Fatalf("ConsumeCode = %+v, want %+v", got, want)
	}
	if _, err := store.ConsumeCode(ctx, want.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second ConsumeCode = %v, want ErrInvalidCode", err)
	}
}

// TestMemoryAuthCodeStoreExpiredIsAbsent: an expired record is indistinguishable
// from one that was never saved, is dropped on the attempt, and is swept by the
// next SaveCode so an abandoned flow does not pin memory.
func TestMemoryAuthCodeStoreExpiredIsAbsent(t *testing.T) {
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()

	stale := sampleAuthCode("stale", -time.Second)
	if err := store.SaveCode(ctx, stale); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, stale.CodeHash); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("consume expired = %v, want ErrInvalidCode", err)
	}
	if n := len(store.codes); n != 0 {
		t.Fatalf("expired record still stored after consume: %d entries", n)
	}

	if err := store.SaveCode(ctx, sampleAuthCode("stale-2", -time.Second)); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	fresh := sampleAuthCode("fresh", time.Minute)
	if err := store.SaveCode(ctx, fresh); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if n := len(store.codes); n != 1 {
		t.Fatalf("SaveCode did not sweep the expired record: %d entries, want 1", n)
	}
	if _, err := store.ConsumeCode(ctx, fresh.CodeHash); err != nil {
		t.Fatalf("fresh record lost to the sweep: %v", err)
	}
}

// TestMemoryAuthCodeStoreConcurrentConsumersHaveOneWinner is the race the
// process-local map never had to face at scale: 32 redemptions of one code at
// once must produce exactly one record and 31 ErrInvalidCode.
func TestMemoryAuthCodeStoreConcurrentConsumersHaveOneWinner(t *testing.T) {
	const workers = 32
	store := NewMemoryAuthCodeStore()
	ctx := context.Background()
	code := sampleAuthCode("contended", time.Minute)
	if err := store.SaveCode(ctx, code); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	var wins, losses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := store.ConsumeCode(ctx, code.CodeHash)
			switch {
			case err == nil:
				wins.Add(1)
				if got != code {
					t.Errorf("winner got %+v, want %+v", got, code)
				}
			case errors.Is(err, ErrInvalidCode):
				losses.Add(1)
			default:
				t.Errorf("ConsumeCode = %v, want nil or ErrInvalidCode", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins.Load() != 1 || losses.Load() != workers-1 {
		t.Fatalf("wins=%d losses=%d, want 1 and %d", wins.Load(), losses.Load(), workers-1)
	}
}

// TestNewIDPDefaultsCodesAndTTL keeps the pre-seam behaviour for callers that
// never set the new fields: an in-process store and a five-minute code.
func TestNewIDPDefaultsCodesAndTTL(t *testing.T) {
	idp, err := NewIDP(IDPConfig{Issuer: "https://idp.example.com"}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if _, ok := idp.codes.(*MemoryAuthCodeStore); !ok {
		t.Fatalf("nil Codes resolved to %T, want *MemoryAuthCodeStore", idp.codes)
	}
	if got := idp.codeTTL(); got != 5*time.Minute {
		t.Fatalf("default codeTTL = %v, want 5m", got)
	}

	custom := NewMemoryAuthCodeStore()
	idp, err = NewIDP(IDPConfig{Issuer: "https://idp.example.com", Codes: custom, CodeTTL: 90 * time.Second}, nil)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	if idp.codes != AuthCodeStore(custom) {
		t.Fatal("IDPConfig.Codes was not the store the IDP uses")
	}
	if got := idp.codeTTL(); got != 90*time.Second {
		t.Fatalf("codeTTL = %v, want 90s", got)
	}
}

// recordingAuthCodeStore is the injected fake for the end-to-end test. It
// delegates the semantics to MemoryAuthCodeStore and records every call, which
// is what proves the handlers reach the interface rather than a private map.
type recordingAuthCodeStore struct {
	mu       sync.Mutex
	inner    *MemoryAuthCodeStore
	saved    []AuthCode
	consumed []string
}

func (s *recordingAuthCodeStore) SaveCode(ctx context.Context, code AuthCode) error {
	s.mu.Lock()
	s.saved = append(s.saved, code)
	s.mu.Unlock()
	return s.inner.SaveCode(ctx, code)
}

func (s *recordingAuthCodeStore) ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error) {
	s.mu.Lock()
	s.consumed = append(s.consumed, codeHash)
	s.mu.Unlock()
	return s.inner.ConsumeCode(ctx, codeHash)
}

func (s *recordingAuthCodeStore) snapshot() ([]AuthCode, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuthCode(nil), s.saved...), append([]string(nil), s.consumed...)
}

const (
	idpTestIssuer   = "https://idp.example.com"
	idpTestEmail    = "idp@example.com"
	idpTestPassword = "supersecure"
	idpTestTenant   = "t1"
	idpTestCodeTTL  = 90 * time.Second
)

var (
	idpTestClient = IDPClient{
		ClientID: "app", ClientSecret: "app-secret",
		RedirectURIs: []string{"https://app.example.com/cb"}, Name: "App",
	}
	idpTestOtherClient = IDPClient{
		ClientID: "other", ClientSecret: "other-secret",
		RedirectURIs: []string{"https://other.example.com/cb"}, Name: "Other",
	}
)

type idpFixture struct {
	srv    *httptest.Server
	client *http.Client
	store  *recordingAuthCodeStore
	user   User
}

// newIDPFixture mounts the IDP on an httptest server over a memory-backed
// Service with one registered, verified user, and an injected AuthCodeStore.
func newIDPFixture(t *testing.T) *idpFixture {
	t.Helper()
	svc, err := NewService(testConfig("01234567890123456789012345678901"), NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user, _, err := svc.Register(context.Background(), RegisterInput{Email: idpTestEmail, Password: idpTestPassword, TenantID: idpTestTenant})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := &recordingAuthCodeStore{inner: NewMemoryAuthCodeStore()}
	idp, err := NewIDP(IDPConfig{
		Issuer:         idpTestIssuer,
		AccessTokenTTL: 15 * time.Minute,
		Codes:          store,
		CodeTTL:        idpTestCodeTTL,
	}, svc, idpTestClient, idpTestOtherClient)
	if err != nil {
		t.Fatalf("NewIDP: %v", err)
	}
	mux := http.NewServeMux()
	idp.RegisterHandlers(mux, "/oidc")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// The authorize redirect points at the relying party, which does not
	// exist here; stop at the 302 and read Location.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &idpFixture{srv: srv, client: client, store: store, user: user}
}

// authorize logs the fixture user in through POST /authorize for the given
// client and returns the code from the redirect.
func (f *idpFixture) authorize(t *testing.T, client IDPClient, extra url.Values) string {
	t.Helper()
	q := url.Values{
		"client_id":    {client.ClientID},
		"redirect_uri": {client.RedirectURIs[0]},
		"state":        {"st-1"},
		"nonce":        {"n-1"},
	}
	for k, v := range extra {
		q[k] = v
	}
	form := url.Values{"email": {idpTestEmail}, "password": {idpTestPassword}, "tenant_id": {idpTestTenant}}
	resp, err := f.client.PostForm(f.srv.URL+"/oidc/authorize?"+q.Encode(), form)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != client.RedirectURIs[0] {
		t.Fatalf("redirected to %s, want %s", got, client.RedirectURIs[0])
	}
	if loc.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %q", loc.RawQuery)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", loc.RawQuery)
	}
	return code
}

// token redeems code at POST /token as the given client.
func (f *idpFixture) token(t *testing.T, code string, client IDPClient) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
	}
	resp, err := f.client.PostForm(f.srv.URL+"/oidc/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode /token body: %v", err)
		}
	}
	return resp.StatusCode, body
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	_, payload, _, err := splitToken(token)
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// TestIDPAuthorizeTokenUserInfoThroughStore walks the whole code flow over
// httptest with an injected store: /authorize saves a hashed record carrying
// the request's parameters, /token consumes it by the same hash and mints
// tokens, /userinfo honours the access token, and a replay of the code fails.
func TestIDPAuthorizeTokenUserInfoThroughStore(t *testing.T) {
	f := newIDPFixture(t)
	before := time.Now()
	code := f.authorize(t, idpTestClient, url.Values{
		"scope":                 {"openid email"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	})

	saved, consumed := f.store.snapshot()
	if len(saved) != 1 || len(consumed) != 0 {
		t.Fatalf("after /authorize: %d saves, %d consumes; want 1 and 0", len(saved), len(consumed))
	}
	rec := saved[0]
	if rec.CodeHash != hashToken(code) {
		t.Fatalf("stored CodeHash = %q, want hashToken(code) = %q", rec.CodeHash, hashToken(code))
	}
	if rec.CodeHash == code {
		t.Fatal("the clear-text code reached the store")
	}
	want := AuthCode{
		CodeHash: rec.CodeHash, UserID: f.user.ID, TenantID: idpTestTenant, ClientID: idpTestClient.ClientID,
		Nonce: "n-1", RedirectURI: idpTestClient.RedirectURIs[0],
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Scope: "openid email",
		ExpiresAt: rec.ExpiresAt,
	}
	if rec != want {
		t.Fatalf("stored record = %+v, want %+v", rec, want)
	}
	if ttl := rec.ExpiresAt.Sub(before); ttl < idpTestCodeTTL-5*time.Second || ttl > idpTestCodeTTL+5*time.Second {
		t.Fatalf("ExpiresAt is %v out, want about IDPConfig.CodeTTL = %v", ttl, idpTestCodeTTL)
	}

	status, body := f.token(t, code, idpTestClient)
	if status != http.StatusOK {
		t.Fatalf("POST /token = %d, want 200", status)
	}
	_, consumed = f.store.snapshot()
	if len(consumed) != 1 || consumed[0] != hashToken(code) {
		t.Fatalf("/token consumed %v, want [%s]", consumed, hashToken(code))
	}
	accessToken, _ := body["access_token"].(string)
	idToken, _ := body["id_token"].(string)
	if accessToken == "" || idToken == "" || body["refresh_token"] == "" {
		t.Fatalf("/token body missing tokens: %v", body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] != float64(900) {
		t.Fatalf("/token body = %v, want Bearer / 900", body)
	}
	claims := decodeJWTPayload(t, idToken)
	if claims["iss"] != idpTestIssuer || claims["sub"] != f.user.ID || claims["aud"] != idpTestClient.ClientID || claims["nonce"] != "n-1" {
		t.Fatalf("id_token claims = %v", claims)
	}

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /userinfo = %d, want 200", resp.StatusCode)
	}
	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("decode /userinfo: %v", err)
	}
	if info["sub"] != f.user.ID || info["email"] != idpTestEmail {
		t.Fatalf("/userinfo = %v", info)
	}

	// Single use: the same code again is refused, and the refusal came from
	// the store, not from anything the handler remembered.
	if status, _ := f.token(t, code, idpTestClient); status != http.StatusBadRequest {
		t.Fatalf("replayed code: POST /token = %d, want 400", status)
	}
	if _, consumed = f.store.snapshot(); len(consumed) != 2 {
		t.Fatalf("replay did not reach the store: %d consumes", len(consumed))
	}
}

// TestIDPTokenRejectsCodeIssuedToAnotherClient: a code minted for one client
// cannot be redeemed with another client's credentials (RFC 6749 §4.1.3), and
// the attempt burns the code.
func TestIDPTokenRejectsCodeIssuedToAnotherClient(t *testing.T) {
	f := newIDPFixture(t)
	code := f.authorize(t, idpTestClient, nil)

	if status, _ := f.token(t, code, idpTestOtherClient); status != http.StatusBadRequest {
		t.Fatalf("cross-client redemption: POST /token = %d, want 400", status)
	}
	if status, _ := f.token(t, code, idpTestClient); status != http.StatusBadRequest {
		t.Fatalf("code survived a cross-client attempt: POST /token = %d, want 400", status)
	}
}

// TestIDPTokenUnknownCode: a code the store never saw is invalid_grant, and the
// handler asked the store rather than short-circuiting.
func TestIDPTokenUnknownCode(t *testing.T) {
	f := newIDPFixture(t)
	status, _ := f.token(t, "never-issued", idpTestClient)
	if status != http.StatusBadRequest {
		t.Fatalf("POST /token = %d, want 400", status)
	}
	if _, consumed := f.store.snapshot(); len(consumed) != 1 || consumed[0] != hashToken("never-issued") {
		t.Fatalf("store consumed %v, want [hashToken(never-issued)]", consumed)
	}
}
