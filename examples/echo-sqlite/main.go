//go:build ignore

// Echo + SQLite example for awesome-go-auth.
// Shows how to use the Echo adapter with a SQLite-backed store.
// The store implementation is a comment skeleton — replace it with
// your mattn/go-sqlite3 or modernc.org/sqlite adapter.
//
// Run (after implementing the store):
//
//	go run main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	emw "github.com/labstack/echo/v4/middleware"
	auth "github.com/nik2208/awesome-go-auth"
	echoAdapter "github.com/nik2208/awesome-go-auth/adapter/echo"
)

func main() {
	// ── 1. Build the auth service ──────────────────────────────────────────
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		// Swap for your SQLiteUserStore:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
		auth.WithTenantProvider(auth.NewMemoryTenantStore()),
		auth.WithRequire2FA(false),
		auth.WithLogger(func(format string, args ...any) {
			log.Printf("[auth] "+format, args...)
		}),
	)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}
	svc := a.Service()

	// ── 2. OAuth providers (optional) ─────────────────────────────────────
	oauthSvc := auth.NewOAuthService(
		auth.GoogleProvider(
			getEnv("GOOGLE_CLIENT_ID", ""),
			getEnv("GOOGLE_CLIENT_SECRET", ""),
			"http://localhost:8080/oauth/google/callback",
		),
		auth.GitHubProvider(
			getEnv("GITHUB_CLIENT_ID", ""),
			getEnv("GITHUB_CLIENT_SECRET", ""),
			"http://localhost:8080/oauth/github/callback",
		),
	)
	linkedAccounts := auth.NewMemoryLinkedAccounts()

	// ── 3. Telemetry ──────────────────────────────────────────────────────
	telemetry := auth.NewMemoryTelemetryStore()
	_ = telemetry

	// ── 4. Echo server ────────────────────────────────────────────────────
	e := echo.New()
	e.HideBanner = true
	e.Use(emw.Logger())
	e.Use(emw.Recover())
	e.Use(emw.CORS())

	adapt := echoAdapter.New(svc)

	// Auth routes
	e.POST("/auth/register", adapt.Register)
	e.POST("/auth/login", adapt.Login)
	e.POST("/auth/refresh", adapt.Refresh)
	e.POST("/auth/logout", adapt.Logout)
	e.GET("/auth/me", adapt.Me, adapt.RequireAuth())
	e.POST("/auth/forgot-password", adapt.ForgotPassword)
	e.POST("/auth/reset-password", adapt.ResetPassword)
	e.POST("/auth/magic-link/send", adapt.SendMagicLink)
	e.POST("/auth/magic-link/verify", adapt.VerifyMagicLink)
	e.POST("/auth/change-password", adapt.ChangePassword, adapt.RequireAuth())
	e.POST("/auth/totp/setup", adapt.SetupTOTP, adapt.RequireAuth())
	e.POST("/auth/totp/verify", adapt.VerifyTOTP)
	e.GET("/auth/sessions", adapt.ListSessions, adapt.RequireAuth())

	// OAuth callback
	e.GET("/oauth/:provider/authorize", func(c echo.Context) error {
		provider := c.Param("provider")
		// Use a random state to prevent CSRF; store in session in production
		state := fmt.Sprintf("%d", time.Now().UnixNano())
		authURL, err := oauthSvc.AuthorizeURL(provider, state)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		return c.Redirect(http.StatusFound, authURL)
	})
	e.GET("/oauth/:provider/callback", func(c echo.Context) error {
		provider := c.Param("provider")
		code := c.QueryParam("code")
		info, err := oauthSvc.ExchangeCode(c.Request().Context(), provider, code)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		user, tokens, err := oauthSvc.HandleCallback(c.Request().Context(), svc, linkedAccounts, info, "", "")
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return c.JSON(http.StatusOK, map[string]any{"user": user, "tokens": tokens})
	})

	// Embedded UI
	e.GET("/admin", echo.WrapHandler(auth.ServeAdminUI()))
	e.GET("/auth.js", echo.WrapHandler(auth.ServeAuthJS()))

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(e.Start(addr))
}

// ── MemoryLinkedAccountStore (demo) ───────────────────────────────────────
// auth.NewMemoryLinkedAccounts() provides an in-memory LinkedAccountStore.
// In production, implement LinkedAccountStore against your database.

// ── SQLite store skeleton ──────────────────────────────────────────────────
// Uncomment and implement with your preferred SQLite driver:
//
// type SQLiteUserStore struct{ db *sql.DB }
// func (s *SQLiteUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// ...

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
