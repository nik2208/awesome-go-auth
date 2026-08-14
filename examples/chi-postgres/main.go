// Chi + PostgreSQL example for awesome-go-auth.
//
// It wires the Chi adapter, the event bus, SSE, webhooks and the generated
// OpenAPI spec. The Postgres store is left as a comment skeleton — swap
// NewMemoryUserStore for your own implementation.
//
//	go run ./examples/chi-postgres
//
// This file is compiled by `go build ./...`, so it cannot drift away from the
// library API without CI noticing.
package main

import (
	"context"
	"encoding/json"
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
	// ── 1. Build the auth instance ─────────────────────────────────────────
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
		// Delivery for the passwordless routes. Without a sender,
		// POST /auth/magic-link/send answers 500 EMAIL_NOT_CONFIGURED and
		// POST /auth/sms/send answers 500 SMS_NOT_CONFIGURED — by design: the
		// credential cannot be returned in the response body. These two log
		// instead of sending so the example runs with no provider; in production
		// use a transport:
		//
		//	auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
		//		auth.NewHTTPMailerTransport(endpoint, secret),
		//		"My App", "https://api.example.com/auth",
		//	).Send),
		//	auth.WithSMSCodeSender(auth.SMSTransportSender(
		//		auth.NewHTTPSMSTransport(endpoint, apiKey, username, password),
		//	)),
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
			Data:  map[string]any{"userId": e.UserID},
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

	// ── 5. Chi router ─────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// One call mounts every auth route under the configured prefix (/auth by
	// default) with the cookie, CSRF and envelope conventions already applied.
	// Use chiAdapter.MountWithConfig(r, a, cfg) to change the prefix or the
	// cookie policy.
	chiAdapter.Mount(r, a)

	// Embedded UI
	r.Get("/admin", auth.ServeAdminUI().ServeHTTP)
	r.Get("/auth-ui", auth.ServeAuthUI().ServeHTTP)
	r.Get("/auth.js", auth.ServeAuthJS().ServeHTTP)

	// SSE endpoint, behind the same access-token middleware the auth routes use.
	r.With(chiAdapter.Middleware(a)).Get("/events/{userID}", func(w http.ResponseWriter, r *http.Request) {
		auth.ServeSSE(hub, chi.URLParam(r, "userID"))(w, r)
	})

	// MCP tool server
	mcpSrv := auth.NewMCPServer(svc)
	r.Post("/mcp", mcpSrv.ServeHTTP)

	// OpenAPI spec. APIPrefix must match the mount, or the spec documents paths
	// this server does not serve.
	r.Get("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
			Title:     "My App API",
			ServerURL: "https://api.example.com",
			APIPrefix: auth.DefaultAPIPrefix,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(spec)
	})

	// API key protected route
	apiKeySvc := auth.NewAPIKeyService(bcryptCost)
	_ = apiKeySvc

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

// ── Postgres store skeleton ────────────────────────────────────────────────
// Implement these when you add a pgx/sqlx dependency:
//
// type PostgresUserStore struct{ db *pgxpool.Pool }
// func (s *PostgresUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *PostgresUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *PostgresUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }
//
// UserStore is the only required interface; the optional ones
// (MagicLinkStore, SMSStore, TOTPStore, …) each switch on a feature.

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
