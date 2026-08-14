// Echo + SQLite example for awesome-go-auth.
//
// It wires the Echo adapter, OAuth login with account linking, and the embedded
// UI. The SQLite store is left as a comment skeleton — swap NewMemoryUserStore
// for your modernc.org/sqlite or mattn/go-sqlite3 implementation.
//
//	go run ./examples/echo-sqlite
//
// This file is compiled by `go build ./...`, so it cannot drift away from the
// library API without CI noticing.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoAdapter "github.com/nik2208/awesome-go-auth/adapter/echo"
)

func main() {
	// ── 1. Build the auth instance ─────────────────────────────────────────
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
		// The passwordless routes need somewhere to send what they mint, or they
		// answer 500 EMAIL_NOT_CONFIGURED / SMS_NOT_CONFIGURED. These log instead
		// of sending; in production use a transport:
		//
		//	auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
		//		auth.NewHTTPMailerTransport(endpoint, secret),
		//		"My App", "https://api.example.com/auth",
		//	).Send),
		auth.WithMagicLinkSender(func(_ context.Context, d auth.MagicLinkDelivery) error {
			log.Printf("[auth] magic link for %s: %s", d.Email, auth.MagicLinkURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		auth.WithSMSCodeSender(func(_ context.Context, d auth.SMSCodeDelivery) error {
			log.Printf("[auth] sms to %s: %s", d.Phone, auth.SMSCodeMessage(d.Code))
			return nil
		}),
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

	// ── 3. Echo server ────────────────────────────────────────────────────
	e := echo.New()
	e.HideBanner = true

	// One call mounts every auth route under the configured prefix (/auth by
	// default); echoAdapter.MountWithConfig takes an *echo.Group for a different
	// prefix or cookie policy.
	echoAdapter.Mount(e.Group(""), a)

	// ── 4. OAuth login ────────────────────────────────────────────────────
	e.GET("/oauth/:provider/authorize", func(c echo.Context) error {
		// A real deployment must bind the state to the browser session; this
		// example only needs it to be unguessable per request. A timestamp will
		// not do — the state is the CSRF defence on the callback.
		state, err := randomState()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		authURL, err := oauthSvc.AuthorizeURL(c.Param("provider"), state)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		return c.Redirect(http.StatusFound, authURL)
	})
	e.GET("/oauth/:provider/callback", func(c echo.Context) error {
		provider := c.Param("provider")
		info, err := oauthSvc.ExchangeCode(c.Request().Context(), provider, c.QueryParam("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		user, tokens, err := oauthSvc.HandleCallback(c.Request().Context(), svc, linkedAccounts, info, "", "")
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		// Never serialise the raw User: it carries the password hash and the TOTP
		// secret. NewPublicUser is the response-safe projection the auth routes use.
		return c.JSON(http.StatusOK, map[string]any{
			"success":      true,
			"user":         auth.NewPublicUser(user),
			"accessToken":  tokens.AccessToken,
			"refreshToken": tokens.RefreshToken,
		})
	})

	// ── 5. Embedded UI ────────────────────────────────────────────────────
	e.GET("/admin", echo.WrapHandler(auth.ServeAdminUI()))
	e.GET("/auth.js", echo.WrapHandler(auth.ServeAuthJS()))

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(e.Start(addr))
}

// ── SQLite store skeleton ──────────────────────────────────────────────────
// Implement with your preferred SQLite driver:
//
// type SQLiteUserStore struct{ db *sql.DB }
// func (s *SQLiteUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *SQLiteUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *SQLiteUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
