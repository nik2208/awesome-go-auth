package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// memAPIKeyStore is a simple in-memory APIKeyStore for tests.
type memAPIKeyStore struct {
	keys     map[string]APIKeyRecord
	lastUsed map[string]time.Time
}

func newMemAPIKeyStore() *memAPIKeyStore {
	return &memAPIKeyStore{keys: make(map[string]APIKeyRecord), lastUsed: make(map[string]time.Time)}
}

func (s *memAPIKeyStore) Save(_ context.Context, key APIKeyRecord) error {
	s.keys[key.Prefix] = key
	return nil
}

func (s *memAPIKeyStore) FindByPrefix(_ context.Context, prefix string) (APIKeyRecord, error) {
	k, ok := s.keys[prefix]
	if !ok {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	return k, nil
}

func (s *memAPIKeyStore) Revoke(_ context.Context, id string) error {
	for prefix, k := range s.keys {
		if k.ID == id {
			k.IsActive = false
			s.keys[prefix] = k
			return nil
		}
	}
	return nil
}

func (s *memAPIKeyStore) UpdateLastUsed(_ context.Context, id string, when time.Time) error {
	s.lastUsed[id] = when
	return nil
}

func TestAPIKeyService_Create(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, record, err := svc.Create(ctx, store, "mykey", "svc1", []string{"read"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(rawKey) < 11 || rawKey[:3] != "ak_" {
		t.Fatalf("key should start with ak_: %s", rawKey)
	}
	if record.ID == "" {
		t.Fatal("record ID should not be empty")
	}
	if record.Prefix == "" {
		t.Fatal("record prefix should not be empty")
	}
	if record.Name != "mykey" {
		t.Fatalf("unexpected name: %s", record.Name)
	}
	if !record.IsActive {
		t.Fatal("new key should be active")
	}
}

func TestAPIKeyService_Create_NilStore(t *testing.T) {
	svc := NewAPIKeyService()
	ctx := context.Background()
	_, _, err := svc.Create(ctx, nil, "k", "s", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestAPIKeyService_Create_Persists(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, record, err := svc.Create(ctx, store, "k", "s", nil, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	found, err := store.FindByPrefix(ctx, record.Prefix)
	if err != nil {
		t.Fatalf("FindByPrefix after create: %v", err)
	}
	if found.ID != record.ID {
		t.Fatalf("unexpected record ID: %s vs %s", found.ID, record.ID)
	}
	_ = rawKey
}

func TestAPIKeyService_Verify_Valid(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", []string{"read", "write"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "", []string{"read"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAPIKeyService_Verify_InvalidPrefix(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	_, err := svc.Verify(ctx, store, "bad_key", "", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAPIKeyService_Verify_TooShort(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	_, err := svc.Verify(ctx, store, "ak_x", "", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAPIKeyService_Verify_WrongPassword(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, record, err := svc.Create(ctx, store, "k", "s", nil, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Tamper: replace body keeping prefix
	tampered := record.Prefix + rawKey[len(record.Prefix):]
	// Swap one character in the body
	b := []byte(tampered)
	if b[15] == 'a' {
		b[15] = 'b'
	} else {
		b[15] = 'a'
	}
	_, err = svc.Verify(ctx, store, string(b), "", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for tampered key, got %v", err)
	}
}

func TestAPIKeyService_Verify_Inactive(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, record, err := svc.Create(ctx, store, "k", "s", nil, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = store.Revoke(ctx, record.ID)
	_, err = svc.Verify(ctx, store, rawKey, "", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for inactive key, got %v", err)
	}
}

func TestAPIKeyService_Verify_Expired(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour)
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, nil, &past)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for expired key, got %v", err)
	}
}

func TestAPIKeyService_Verify_NotExpired(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	future := time.Now().Add(1 * time.Hour)
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, nil, &future)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "", nil)
	if err != nil {
		t.Fatalf("non-expired key should verify: %v", err)
	}
}

func TestAPIKeyService_Verify_MissingScope(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", []string{"read"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "", []string{"write"})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for missing scope, got %v", err)
	}
}

func TestAPIKeyService_Verify_NoRequiredScopes(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", []string{"read"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "", nil)
	if err != nil {
		t.Fatalf("no required scopes should always pass: %v", err)
	}
}

func TestAPIKeyService_Verify_IPBlocked(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, []string{"10.0.0.1"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "192.168.1.1", nil)
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for blocked IP, got %v", err)
	}
}

func TestAPIKeyService_Verify_IPAllowed(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, []string{"192.168.1.1"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("allowed IP should pass: %v", err)
	}
}

func TestAPIKeyService_Verify_IPAllowed_CIDR(t *testing.T) {
	svc := NewAPIKeyService()
	store := newMemAPIKeyStore()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, []string{"192.168.1.0/24"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = svc.Verify(ctx, store, rawKey, "192.168.1.42", nil)
	if err != nil {
		t.Fatalf("IP in CIDR should pass: %v", err)
	}
}

func TestHasScopes_EmptyRequired(t *testing.T) {
	if !hasScopes([]string{"read"}, nil) {
		t.Fatal("empty required scopes should always pass")
	}
}

func TestHasScopes_AllPresent(t *testing.T) {
	if !hasScopes([]string{"read", "write"}, []string{"read", "write"}) {
		t.Fatal("all scopes present should pass")
	}
}

func TestHasScopes_Missing(t *testing.T) {
	if hasScopes([]string{"read"}, []string{"write"}) {
		t.Fatal("missing scope should fail")
	}
}

func TestHasScopes_SupersetOK(t *testing.T) {
	if !hasScopes([]string{"read", "write", "admin"}, []string{"read"}) {
		t.Fatal("key with superset of scopes should pass")
	}
}

func TestIPAllowed_EmptyList(t *testing.T) {
	if !ipAllowed("1.2.3.4", nil) {
		t.Fatal("empty allow list should allow all IPs")
	}
}

func TestIPAllowed_ExactMatch(t *testing.T) {
	if !ipAllowed("1.2.3.4", []string{"1.2.3.4"}) {
		t.Fatal("exact IP match should be allowed")
	}
}

func TestIPAllowed_NoMatch(t *testing.T) {
	if ipAllowed("1.2.3.4", []string{"5.6.7.8"}) {
		t.Fatal("non-matching IP should be blocked")
	}
}

func TestIPAllowed_CIDR(t *testing.T) {
	if !ipAllowed("10.0.0.5", []string{"10.0.0.0/24"}) {
		t.Fatal("IP in CIDR range should be allowed")
	}
}

func TestIPAllowed_OutsideCIDR(t *testing.T) {
	if ipAllowed("10.0.1.1", []string{"10.0.0.0/24"}) {
		t.Fatal("IP outside CIDR range should be blocked")
	}
}

func TestIPAllowed_InvalidIP(t *testing.T) {
	if ipAllowed("not-an-ip", []string{"10.0.0.0/24"}) {
		t.Fatal("invalid IP should be blocked")
	}
}

func TestExtractAPIKey_XApiKey(t *testing.T) {
	h := http.Header{}
	h.Set("X-Api-Key", "ak_testkey123")
	key := extractAPIKey(h)
	if key != "ak_testkey123" {
		t.Fatalf("unexpected key: %s", key)
	}
}

func TestExtractAPIKey_Authorization_ApiKey(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "ApiKey ak_testkey456")
	key := extractAPIKey(h)
	if key != "ak_testkey456" {
		t.Fatalf("unexpected key: %s", key)
	}
}

func TestExtractAPIKey_Empty(t *testing.T) {
	h := http.Header{}
	key := extractAPIKey(h)
	if key != "" {
		t.Fatalf("expected empty key, got %s", key)
	}
}

func TestExtractAPIKey_WrongAuthScheme(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sometoken")
	key := extractAPIKey(h)
	if key != "" {
		t.Fatalf("Bearer token should not be extracted as API key, got %s", key)
	}
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	store := newMemAPIKeyStore()
	svc := NewAPIKeyService()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	middleware := APIKeyMiddleware(store, nil)
	handled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", rawKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !handled {
		t.Fatal("handler should have been called with valid key")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_MissingKey(t *testing.T) {
	store := newMemAPIKeyStore()
	middleware := APIKeyMiddleware(store, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	store := newMemAPIKeyStore()
	middleware := APIKeyMiddleware(store, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", "ak_notavalidkey1234567890123456789012345678901234")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_AllowedIP(t *testing.T) {
	store := newMemAPIKeyStore()
	svc := NewAPIKeyService()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, []string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	middleware := APIKeyMiddleware(store, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", rawKey)
	req.RemoteAddr = "127.0.0.1:54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for allowed IP, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_BlockedIP(t *testing.T) {
	store := newMemAPIKeyStore()
	svc := NewAPIKeyService()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", nil, []string{"10.10.10.10"}, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	middleware := APIKeyMiddleware(store, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", rawKey)
	req.RemoteAddr = "127.0.0.1:54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for blocked IP, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_RequiredScopes_Pass(t *testing.T) {
	store := newMemAPIKeyStore()
	svc := NewAPIKeyService()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", []string{"read", "write"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	middleware := APIKeyMiddleware(store, []string{"read"})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", rawKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAPIKeyMiddleware_RequiredScopes_Fail(t *testing.T) {
	store := newMemAPIKeyStore()
	svc := NewAPIKeyService()
	ctx := context.Background()
	rawKey, _, err := svc.Create(ctx, store, "k", "s", []string{"read"}, nil, nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	middleware := APIKeyMiddleware(store, []string{"admin"})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Api-Key", rawKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing required scope, got %d", rr.Code)
	}
}
