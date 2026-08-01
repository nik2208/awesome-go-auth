package gin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginadapter "github.com/nik2208/awesome-go-auth/adapter/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := auth.New()
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func buildRouter(a *auth.Auth) *gin.Engine {
	r := gin.New()
	ginadapter.Mount(r, a)
	return r
}

func TestMount_Register(t *testing.T) {
	a := newAuth(t)
	r := buildRouter(a)

	body, _ := json.Marshal(map[string]string{"email": "gin@example.com", "password": "password1", "tenantId": "t1"})
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
	r := buildRouter(a)

	body, _ := json.Marshal(map[string]string{"email": "gin2@example.com", "password": "x", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMount_Register_DuplicateEmail(t *testing.T) {
	a := newAuth(t)
	r := buildRouter(a)

	body, _ := json.Marshal(map[string]string{"email": "dup@example.com", "password": "password1", "tenantId": "t1"})
	req1 := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	httptest.NewRecorder()
	r.ServeHTTP(httptest.NewRecorder(), req1)

	body, _ = json.Marshal(map[string]string{"email": "dup@example.com", "password": "password1", "tenantId": "t1"})
	req2 := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req2)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestMount_Login(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "ginlogin@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	body, _ := json.Marshal(map[string]string{"email": "ginlogin@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
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
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "ginloginbad@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	body, _ := json.Marshal(map[string]string{"email": "ginloginbad@example.com", "password": "wrong", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Refresh(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "ginrefresh@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMount_Refresh_InvalidToken(t *testing.T) {
	a := newAuth(t)
	r := buildRouter(a)

	body, _ := json.Marshal(map[string]string{"refreshToken": "bogus"})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Logout(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "ginlogout@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMount_Me_Authenticated(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "ginme@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
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
	if user["email"] != "ginme@example.com" {
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
	r := buildRouter(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "ginmw@example.com", Password: "password1", TenantID: "t1"})

	r := gin.New()
	r.GET("/protected", ginadapter.Middleware(a), func(c *gin.Context) {
		user, ok := ginadapter.UserFromContext(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"email": user.Email})
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	a := newAuth(t)
	r := gin.New()
	r.GET("/protected", ginadapter.Middleware(a), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	a := newAuth(t)
	r := gin.New()
	r.GET("/protected", ginadapter.Middleware(a), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid_token_value")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Me_CookieToken(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "gincookie@example.com", Password: "password1", TenantID: "t1"})

	r := buildRouter(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokens.AccessToken})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with cookie auth, got %d: %s", rr.Code, rr.Body.String())
	}
}
