//go:build ignore

// Chi + PostgreSQL example for awesome-go-auth.
// This example shows how to wire awesome-go-auth with a Chi router
// and a PostgreSQL-backed store. The store implementation is left as
// a comment skeleton — replace it with your actual database adapter.
//
// Run (after implementing the store):
//
//	go run main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	auth "github.com/nik2208/awesome-go-auth"
	chiAdapter "github.com/nik2208/awesome-go-auth/adapter/chi"
)

func main() {
	// ── 1. Build the auth service ──────────────────────────────────────────
	// Cost 12 is a common production baseline, above the library default of 10.
	// The API-key service below is given the same cost so both kinds of secret
	// this process stores are hashed alike.
	const bcryptCost = 12
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		auth.WithBcryptCost(bcryptCost),
		// Swap NewMemoryUserStore() for your PostgresUserStore implementation:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
		auth.WithTenantProvider(auth.NewMemoryTenantStore()),
		auth.WithLogger(func(format string, args ...any) {
			log.Printf("[auth] "+format, args...)
		}),
	)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}
	svc := a.Service()

	// ── 2. Optional event bus integration ─────────────────────────────────
	bus := auth.NewEventBus()
	bus.Subscribe("user.registered", func(e auth.Event) {
		log.Printf("new user registered: %s", e.UserID)
	})

	// ── 3. Optional SSE hub ────────────────────────────────────────────────
	hub := auth.NewSseHub()
	bus.Subscribe("*", func(e auth.Event) {
		_ = hub.Publish(context.Background(), e.UserID, auth.SseMessage{
			Event: e.Name,
			Data:  map[string]any{"user_id": e.UserID},
		})
	})

	// ── 4. Optional webhooks ───────────────────────────────────────────────
	dispatcher := auth.NewWebhookDispatcher(
		auth.WebhookEndpoint{
			ID:     "slack",
			URL:    getEnv("WEBHOOK_SLACK_URL", ""),
			Secret: getEnv("WEBHOOK_SECRET", ""),
			Events: []string{"user.registered", "user.login"},
		},
	)
	bus.Subscribe("*", func(e auth.Event) { dispatcher.Dispatch(context.Background(), e) })

	// ── 5. Mail templater ─────────────────────────────────────────────────
	mailer := auth.NewMailTemplater("My App")
	_ = mailer // wire into your email handler

	// ── 6. Chi router ─────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// Mount auth adapter
	adapt := chiAdapter.New(svc)
	r.Post("/auth/register", adapt.Register)
	r.Post("/auth/login", adapt.Login)
	r.Post("/auth/refresh", adapt.Refresh)
	r.Post("/auth/logout", adapt.Logout)
	r.With(adapt.RequireAuth).Get("/auth/me", adapt.Me)
	r.Post("/auth/forgot-password", adapt.ForgotPassword)
	r.Post("/auth/reset-password", adapt.ResetPassword)

	// Admin UI
	r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		auth.ServeAdminUI().ServeHTTP(w, r)
	})
	r.Get("/auth-ui", func(w http.ResponseWriter, r *http.Request) {
		auth.ServeAuthUI().ServeHTTP(w, r)
	})
	r.Get("/auth.js", func(w http.ResponseWriter, r *http.Request) {
		auth.ServeAuthJS().ServeHTTP(w, r)
	})

	// SSE endpoint
	r.With(adapt.RequireAuth).Get("/events/{userID}", func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "userID")
		auth.ServeSSE(hub, userID)(w, r)
	})

	// MCP tool server
	mcpSrv := auth.NewMCPServer(svc)
	r.Post("/mcp", mcpSrv.ServeHTTP)

	// OpenAPI spec
	r.Get("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
			Title:     "My App API",
			ServerURL: "https://api.example.com",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(spec) //nolint:errcheck
	})

	// API key protected route
	apiKeySvc := auth.NewAPIKeyService(bcryptCost)
	_ = apiKeySvc

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

// ── Postgres store skeleton ────────────────────────────────────────────────
// Uncomment and implement these when you add a pgx/sqlx dependency:
//
// type PostgresUserStore struct{ db *pgxpool.Pool }
// func (s *PostgresUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *PostgresUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *PostgresUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }
// ... implement remaining UserStore methods

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Compile-time interface checks
var (
	_ auth.UserStore    = (*auth.MemoryUserStore)(nil)
	_ auth.SessionStore = (*auth.MemorySessionStore)(nil)
)

func init() {
	fmt.Println("awesome-go-auth chi+postgres example")
}
