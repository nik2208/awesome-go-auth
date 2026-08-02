package nethttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// sensitiveFields must never appear in an adapter response body.
var sensitiveFields = []string{
	"PasswordHash",
	"TOTPSecret",
	"ResetTokenHash",
	"MagicLinkTokenHash",
	"SMSCodeHash",
	"EmailVerificationTokenHash",
	"EmailChangeTokenHash",
	"PendingEmail",
}

func assertNoCredentialMaterial(t *testing.T, label string, body []byte) {
	t.Helper()
	lowered := strings.ToLower(string(body))
	for _, field := range sensitiveFields {
		if strings.Contains(lowered, strings.ToLower(field)) {
			t.Errorf("%s response exposes %q: %s", label, field, body)
		}
	}
}

func TestMountRegisterLoginMeFlow(t *testing.T) {
	a, err := auth.New(
		auth.WithSecret("01234567890123456789012345678901"),
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
	)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}

	mux := http.NewServeMux()
	Mount(mux, a)
	server := httptest.NewServer(mux)
	defer server.Close()

	registerBody, _ := json.Marshal(map[string]any{"email": "http@example.com", "password": "password1", "tenantId": "tenant-a"})
	resp, err := http.Post(server.URL+"/auth/register", "application/json", bytes.NewReader(registerBody))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status: %d", resp.StatusCode)
	}
	registerPayload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read register body: %v", err)
	}
	resp.Body.Close()
	assertNoCredentialMaterial(t, "register", registerPayload)

	loginBody, _ := json.Marshal(map[string]any{"email": "http@example.com", "password": "password1", "tenantId": "tenant-a"})
	resp2, err := http.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("login status: %d", resp2.StatusCode)
	}
	loginPayload, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("read login body: %v", err)
	}
	resp2.Body.Close()
	assertNoCredentialMaterial(t, "login", loginPayload)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/auth/me", nil)
	for _, c := range resp2.Cookies() {
		req.AddCookie(c)
	}
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me request: %v", err)
	}
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("me status: %d", resp3.StatusCode)
	}
	mePayload, err := io.ReadAll(resp3.Body)
	if err != nil {
		t.Fatalf("read me body: %v", err)
	}
	resp3.Body.Close()
	assertNoCredentialMaterial(t, "me", mePayload)

	var me struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(mePayload, &me); err != nil {
		t.Fatalf("decode me body: %v", err)
	}
	for _, key := range []string{"id", "email", "isEmailVerified", "isTotpEnabled", "createdAt"} {
		if _, ok := me.User[key]; !ok {
			t.Errorf("me response missing camelCase key %q: %s", key, mePayload)
		}
	}
	if me.User["email"] != "http@example.com" {
		t.Fatalf("unexpected me email: %s", mePayload)
	}
}

func TestLoginResponseRedactsStoredPasswordHash(t *testing.T) {
	a, err := auth.New(
		auth.WithSecret("01234567890123456789012345678901"),
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
	)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}

	mux := http.NewServeMux()
	Mount(mux, a)

	user, _, err := a.Register(context.Background(), auth.RegisterInput{Email: "redact@example.com", Password: "password1", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.PasswordHash == "" {
		t.Fatal("expected stored user to carry a password hash")
	}

	body, _ := json.Marshal(map[string]any{"email": "redact@example.com", "password": "password1", "tenantId": "tenant-a"})
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	loginReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, loginReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), user.PasswordHash) {
		t.Fatalf("login response leaked the stored password hash: %s", rr.Body.String())
	}
	assertNoCredentialMaterial(t, "login", rr.Body.Bytes())
}
