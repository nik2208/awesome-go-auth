package nethttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

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

	loginBody, _ := json.Marshal(map[string]any{"email": "http@example.com", "password": "password1", "tenantId": "tenant-a"})
	resp2, err := http.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("login status: %d", resp2.StatusCode)
	}

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
}
