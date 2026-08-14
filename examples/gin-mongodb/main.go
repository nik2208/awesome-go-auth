// Gin + MongoDB example for awesome-go-auth.
//
// It wires the Gin adapter, the OIDC identity-provider endpoints and the
// generated OpenAPI spec. The Mongo store is left as a comment skeleton — swap
// NewMemoryUserStore for your go.mongodb.org/mongo-driver implementation.
//
//	go run ./examples/gin-mongodb
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

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginAdapter "github.com/nik2208/awesome-go-auth/adapter/gin"
)

func main() {
	// ── 1. Build the auth instance ─────────────────────────────────────────
	a, err := auth.New(
		auth.WithSecret(getEnv("AUTH_SECRET", "change-me-in-production-32bytes!!")),
		auth.WithIssuer("https://api.example.com"),
		auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
		// Swap for your MongoUserStore:
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
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
		// The password-reset, verification and email-change routes answer 200 and
		// mail nothing without these three, as a reference deployment with no email
		// block does. NewPasswordResetMailer / NewEmailVerificationMailer /
		// NewEmailChangeMailer over a MailerTransport give you the built-in
		// templates instead of a callback.
		auth.WithPasswordResetSender(func(_ context.Context, d auth.PasswordResetDelivery) error {
			log.Printf("[auth] password reset for %s: %s", d.Email, auth.PasswordResetURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		auth.WithEmailVerificationSender(func(_ context.Context, d auth.EmailVerificationDelivery) error {
			log.Printf("[auth] verify %s: %s", d.Email, auth.EmailVerificationURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
		// Note the recipient: the new address, not the current one.
		auth.WithEmailChangeSender(func(_ context.Context, d auth.EmailChangeDelivery) error {
			log.Printf("[auth] email change to %s: %s", d.NewEmail, auth.EmailChangeConfirmURL("http://localhost:8080/auth", d.Token))
			return nil
		}),
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

	// One call mounts every auth route under the configured prefix (/auth by
	// default). Mounting on a group works too — the CSRF middleware locates the
	// prefix on any segment boundary — via ginAdapter.MountWithConfig.
	ginAdapter.Mount(r, a)

	// OIDC IDP endpoints
	oidcMux := http.NewServeMux()
	idp.RegisterHandlers(oidcMux, "/oidc/")
	r.Any("/oidc/*path", gin.WrapH(oidcMux))

	// Embedded UI
	r.GET("/admin", gin.WrapH(auth.ServeAdminUI()))
	r.GET("/auth.js", gin.WrapH(auth.ServeAuthJS()))

	// OpenAPI spec. APIPrefix must match the mount.
	r.GET("/openapi.json", func(c *gin.Context) {
		spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
			Title:     "My App API",
			ServerURL: "https://api.example.com",
			APIPrefix: auth.DefaultAPIPrefix,
		})
		c.Header("Content-Type", "application/json")
		_ = json.NewEncoder(c.Writer).Encode(spec)
	})

	addr := getEnv("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(r.Run(addr))
}

// ── MongoDB store skeleton ─────────────────────────────────────────────────
// Implement these when you add a mongo-driver dependency:
//
// type MongoUserStore struct{ coll *mongo.Collection }
// func (s *MongoUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) { ... }
// func (s *MongoUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) { ... }
// func (s *MongoUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) { ... }

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
