package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFMiddlewareSetsCookie(t *testing.T) {
	cfg := DefaultCSRFConfig("/auth")
	cfg.CookieSecure = false
	handler := CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf-token" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected csrf-token cookie to be set")
	}
}

func TestCSRFMiddlewareRejectsMissingHeaderForMutatingRequest(t *testing.T) {
	cfg := DefaultCSRFConfig("/auth")
	cfg.CookieSecure = false
	handler := CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "abc"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rec.Code)
	}
}

func TestCSRFMiddlewareAllowsMutatingRequestWithMatchingHeader(t *testing.T) {
	cfg := DefaultCSRFConfig("/auth")
	cfg.CookieSecure = false
	handler := CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPatch, "/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "match-token"})
	req.Header.Set("X-CSRF-Token", "match-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d", rec.Code)
	}
}

func TestCSRFMiddlewareSkipsAuthFlowAndBearerRequests(t *testing.T) {
	cfg := DefaultCSRFConfig("/auth")
	cfg.CookieSecure = false
	handler := CSRFMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqLogin := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	recLogin := httptest.NewRecorder()
	handler.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected login skip to pass, got %d", recLogin.Code)
	}

	reqBearer := httptest.NewRequest(http.MethodDelete, "/auth/account", nil)
	reqBearer.Header.Set("Authorization", "Bearer some-access-token")
	recBearer := httptest.NewRecorder()
	handler.ServeHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusOK {
		t.Fatalf("expected bearer skip to pass, got %d", recBearer.Code)
	}
}
