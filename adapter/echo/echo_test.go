package echo_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoadapter "github.com/nik2208/awesome-go-auth/adapter/echo"
)

func newAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := auth.New()
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

func buildEcho(a *auth.Auth) *echo.Echo {
	e := echo.New()
	echoadapter.Mount(e.Group(""), a)
	return e
}

func TestMount_Register(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)

	body, _ := json.Marshal(map[string]string{"email": "echo@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMount_Register_WeakPassword(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)

	body, _ := json.Marshal(map[string]string{"email": "echo2@example.com", "password": "x", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMount_Register_DuplicateEmail(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)

	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(map[string]string{"email": "echodup@example.com", "password": "password1", "tenantId": "t1"})
		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, req)
		if i == 1 && rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 on duplicate, got %d", rr.Code)
		}
	}
}

func TestMount_Login(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "echologin@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	body, _ := json.Marshal(map[string]string{"email": "echologin@example.com", "password": "password1", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
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
	_, _, _ = a.Register(ctx, auth.RegisterInput{Email: "echologinbad@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	body, _ := json.Marshal(map[string]string{"email": "echologinbad@example.com", "password": "wrong", "tenantId": "t1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Refresh(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "echorefresh@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMount_Refresh_InvalidToken(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)

	body, _ := json.Marshal(map[string]string{"refreshToken": "bogus"})
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Logout(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "echologout@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	body, _ := json.Marshal(map[string]string{"refreshToken": tokens.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMount_Me_Authenticated(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "echome@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["user"] == nil {
		t.Fatal("expected user in response")
	}
}

func TestMount_Me_Unauthenticated(t *testing.T) {
	a := newAuth(t)
	e := buildEcho(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "echomw@example.com", Password: "password1", TenantID: "t1"})

	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		user, ok := echoadapter.UserFromContext(c)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]any{"error": "no user"})
		}
		return c.JSON(http.StatusOK, map[string]any{"email": user.Email})
	}, echoadapter.Middleware(a))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_NoToken(t *testing.T) {
	a := newAuth(t)
	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.JSON(http.StatusOK, nil)
	}, echoadapter.Middleware(a))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	a := newAuth(t)
	e := echo.New()
	e.GET("/protected", func(c echo.Context) error {
		return c.JSON(http.StatusOK, nil)
	}, echoadapter.Middleware(a))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-valid")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMount_Me_CookieAuth(t *testing.T) {
	a := newAuth(t)
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_, tokens, _ := a.Register(ctx, auth.RegisterInput{Email: "echocookie@example.com", Password: "password1", TenantID: "t1"})

	e := buildEcho(a)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokens.AccessToken})
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with cookie auth, got %d: %s", rr.Code, rr.Body.String())
	}
}
