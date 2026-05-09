//go:build ignore

// Gin + MongoDB example for awesome-go-auth.
// Shows how to use the Gin adapter and wire a MongoDB-backed store.
// The store implementation is left as a comment skeleton — replace it
// with your actual go.mongodb.org/mongo-driver adapter.
//
// Run (after implementing the store):
//
//	go run main.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginAdapter "github.com/nik2208/awesome-go-auth/adapter/gin"
)

func main() {
	// ── 1. Build the auth service ──────────────────────────────────────────
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		// Swap for your MongoUserStore:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
	)
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}
	svc := a.Service()

	// ── 2. OIDC IDP (optional) ─────────────────────────────────────────────
	idp, err := auth.NewIDP(
		auth.IDPConfig{
			Issuer:         "https://auth.example.com",
			AccessTokenTTL: 15 * time.Minute,
			IDTokenTTL:     time.Hour,
		},
		svc,
		auth.IDPClient{
			ClientID:     "webapp",
			ClientSecret: getEnv("IDP_CLIENT_SECRET", "secret"),
			RedirectURIs: []string{"https://app.example.com/callback"},
			Name:         "Web App",
		},
	)
	if err != nil {
		log.Fatalf("idp init: %v", err)
	}

	// ── 3. Gin router ─────────────────────────────────────────────────────
	if getEnv("GIN_MODE", "") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	adapt := ginAdapter.New(svc)

	// Auth routes
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", adapt.Register)
		authGroup.POST("/login", adapt.Login)
		authGroup.POST("/refresh", adapt.Refresh)
		authGroup.POST("/logout", adapt.Logout)
		authGroup.GET("/me", adapt.RequireAuth(), adapt.Me)
		authGroup.POST("/forgot-password", adapt.ForgotPassword)
		authGroup.POST("/reset-password", adapt.ResetPassword)
		authGroup.POST("/magic-link/send", adapt.SendMagicLink)
		authGroup.POST("/magic-link/verify", adapt.VerifyMagicLink)
		authGroup.POST("/totp/setup", adapt.RequireAuth(), adapt.SetupTOTP)
		authGroup.POST("/totp/verify", adapt.VerifyTOTP)
	}

	// OIDC IDP endpoints
	oidcMux := http.NewServeMux()
	idp.RegisterHandlers(oidcMux, "/oidc/")
	r.Any("/oidc/*path", gin.WrapH(oidcMux))

	// Admin UI
	r.GET("/admin", gin.WrapH(auth.ServeAdminUI()))
	r.GET("/auth.js", gin.WrapH(auth.ServeAuthJS()))

	// OpenAPI spec
	r.GET("/openapi.json", func(c *gin.Context) {
		spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
			Title:     "My App API",
			ServerURL: "https://api.example.com",
		})
		c.Header("Content-Type", "application/json")
		json.NewEncoder(c.Writer).Encode(spec) //nolint:errcheck
	})

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(r.Run(addr))
}

// ── MongoDB store skeleton ─────────────────────────────────────────────────
// Uncomment and implement these when you add a mongo-driver dependency:
//
// type MongoUserStore struct{ coll *mongo.Collection }
// func (s *MongoUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *MongoUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// ...

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
