package echo_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// TestMount_Register_RedactsCredentialMaterial pins the POST /auth/register
// response body. TestMount_Me_Authenticated only covers GET /auth/me, so
// without this the register response site is unprotected.
func TestMount_Register_RedactsCredentialMaterial(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)

	body, _ := json.Marshal(map[string]string{"email": "echoredact@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	assertNoCredentialMaterial(t, rr.Body.Bytes())
	assertCamelCaseUser(t, rr.Body.Bytes(), "echoredact@example.com")
}

// TestMount_Login_RedactsStoredPasswordHash pins the POST /auth/login response
// body against the real bcrypt hash held for the account.
func TestMount_Login_RedactsStoredPasswordHash(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	user, _, err := a.Register(ctx, auth.RegisterInput{Email: "echoredactlogin@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.PasswordHash == "" {
		t.Fatal("expected stored user to carry a password hash")
	}

	e := buildEcho(a)
	body, _ := json.Marshal(map[string]string{"email": "echoredactlogin@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), user.PasswordHash) {
		t.Fatalf("login response leaked the stored password hash: %s", rr.Body.String())
	}
	assertNoCredentialMaterial(t, rr.Body.Bytes())
	assertCamelCaseUser(t, rr.Body.Bytes(), "echoredactlogin@example.com")
}

// assertCamelCaseUser checks the response user object uses the family camelCase
// wire contract rather than Go field casing.
func assertCamelCaseUser(t *testing.T, body []byte, email string) {
	t.Helper()
	var resp struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.User["email"] != email {
		t.Fatalf("expected camelCase email %q, got %v", email, resp.User)
	}
	if _, ok := resp.User["id"]; !ok {
		t.Fatalf("expected camelCase id, got %v", resp.User)
	}
}
