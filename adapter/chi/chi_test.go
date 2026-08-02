package chi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	chiadapter "github.com/nik2208/awesome-go-auth/adapter/chi"
)

func newAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := auth.New()
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func TestMount_Register(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"email": "chi@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMount_Register_WeakPassword(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"email": "chi2@example.com", "password": "short", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d", rr.Code)
	}
}

func TestMount_Login(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "chilogin@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"email": "chilogin@example.com", "password": "password1", "tenantId": "t1"})
	hreq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["tokens"] == nil {
		t.Fatal("expected tokens in response")
	}
}

func TestMount_Login_WrongPassword(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "chiloginbad@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"email": "chiloginbad@example.com", "password": "wrongpass", "tenantId": "t1"})
	hreq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Refresh(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "chirefresh@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	hreq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMount_Refresh_InvalidToken(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"refreshToken": "bad"})
	hreq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Logout(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "chilogout@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	hreq := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
	hreq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMount_Me_Authenticated(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "chime@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	hreq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	hreq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	assertNoCredentialMaterial(t, rr.Body.Bytes())
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["user"] == nil {
		t.Fatal("expected user in /auth/me response")
	}
	user, ok := resp["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user object, got %T", resp["user"])
	}
	if user["email"] != "chime@example.com" {
		t.Fatalf("expected camelCase email in /auth/me response, got %v", resp["user"])
	}
	if _, ok := user["id"]; !ok {
		t.Fatalf("expected camelCase id in /auth/me response, got %v", resp["user"])
	}
}

// assertNoCredentialMaterial fails when a response body carries user credential
// material. The check is case-insensitive so it survives field renames.
func assertNoCredentialMaterial(t *testing.T, body []byte) {
	t.Helper()
	lowered := strings.ToLower(string(body))
	for _, field := range []string{
		"PasswordHash",
		"TOTPSecret",
		"ResetTokenHash",
		"MagicLinkTokenHash",
		"SMSCodeHash",
		"EmailVerificationTokenHash",
		"EmailChangeTokenHash",
		"PendingEmail",
	} {
		if strings.Contains(lowered, strings.ToLower(field)) {
			t.Errorf("response exposes %q: %s", field, body)
		}
	}
}

func TestMount_Me_Unauthenticated(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	chiadapter.Mount(r, a)

	hreq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	a := newAuth(t)
	ctx := req().Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "chimw@example.com", Password: "password1", TenantID: "t1"})

	r := chi.NewRouter()
	r.With(chiadapter.Middleware(a)).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	hreq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	hreq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	r.With(chiadapter.Middleware(a)).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	hreq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	hreq.Header.Set("Authorization", "Bearer notavalidtoken")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	a := newAuth(t)
	r := chi.NewRouter()
	r.With(chiadapter.Middleware(a)).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	hreq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, hreq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func req() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}
