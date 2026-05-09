package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// APIKeyRecord stores hashed key material and policy constraints.
type APIKeyRecord struct {
	ID         string
	Prefix     string
	Name       string
	ServiceID  string
	KeyHash    string
	Scopes     []string
	AllowedIPs []string
	IsActive   bool
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

// APIKeyStore persists and resolves API keys.
type APIKeyStore interface {
	Save(ctx context.Context, key APIKeyRecord) error
	FindByPrefix(ctx context.Context, prefix string) (APIKeyRecord, error)
	Revoke(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string, when time.Time) error
}

type APIKeyService struct{}

func NewAPIKeyService() *APIKeyService { return &APIKeyService{} }

var apiKeyBodySanitizer = regexp.MustCompile(`[^a-zA-Z0-9]`)

func (s *APIKeyService) Create(ctx context.Context, store APIKeyStore, name, serviceID string, scopes, allowedIPs []string, expiresAt *time.Time) (rawKey string, record APIKeyRecord, err error) {
	if store == nil {
		return "", APIKeyRecord{}, errors.New("auth: api key store is required")
	}
	rawBody, err := randomToken(36)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	rawBody = apiKeyBodySanitizer.ReplaceAllString(rawBody, "")
	if len(rawBody) < 48 {
		fallback, ferr := randomToken(40)
		if ferr != nil {
			return "", APIKeyRecord{}, ferr
		}
		rawBody = apiKeyBodySanitizer.ReplaceAllString(fallback, "")
	}
	if len(rawBody) < 48 {
		return "", APIKeyRecord{}, errors.New("auth: api key entropy generation failed")
	}
	rawKey = "ak_" + rawBody[:48]
	if len(rawKey) < 11 {
		return "", APIKeyRecord{}, errors.New("auth: generated api key too short")
	}
	keyID, err := newID("key")
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	prefix := rawKey[:11]
	h, err := hashPassword(rawKey)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	record = APIKeyRecord{
		ID:         keyID,
		Prefix:     prefix,
		Name:       name,
		ServiceID:  serviceID,
		KeyHash:    h,
		Scopes:     append([]string(nil), scopes...),
		AllowedIPs: append([]string(nil), allowedIPs...),
		IsActive:   true,
		ExpiresAt:  expiresAt,
	}
	if err := store.Save(ctx, record); err != nil {
		return "", APIKeyRecord{}, err
	}
	return rawKey, record, nil
}

func (s *APIKeyService) Verify(ctx context.Context, store APIKeyStore, rawKey string, ip string, requiredScopes []string) (APIKeyRecord, error) {
	if !strings.HasPrefix(rawKey, "ak_") || len(rawKey) < 11 {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	record, err := store.FindByPrefix(ctx, rawKey[:11])
	if err != nil || !verifyPassword(rawKey, record.KeyHash) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !record.IsActive {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !ipAllowed(ip, record.AllowedIPs) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !hasScopes(record.Scopes, requiredScopes) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	_ = store.UpdateLastUsed(ctx, record.ID, time.Now())
	return record, nil
}

func APIKeyMiddleware(store APIKeyStore, requiredScopes []string) func(http.Handler) http.Handler {
	svc := NewAPIKeyService()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractAPIKey(r.Header)
			if raw == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if _, err := svc.Verify(r.Context(), store, raw, ip, requiredScopes); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractAPIKey(h http.Header) string {
	if v := strings.TrimSpace(h.Get("X-Api-Key")); v != "" {
		return v
	}
	auth := strings.TrimSpace(h.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "ApiKey") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func hasScopes(got, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(got))
	for _, s := range got {
		set[s] = struct{}{}
	}
	for _, s := range required {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func ipAllowed(ip string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, v := range allowed {
		if strings.Contains(v, "/") {
			_, n, err := net.ParseCIDR(v)
			if err == nil && n.Contains(parsed) {
				return true
			}
			continue
		}
		if parsed.Equal(net.ParseIP(v)) {
			return true
		}
	}
	return false
}
