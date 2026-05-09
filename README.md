# awesome-go-auth

`awesome-go-auth` is a Go authentication library with stateful sessions and access/refresh tokens.

## Installation

```bash
go get github.com/nik2208/awesome-go-auth
```

## Quick start

```go
package main

import (
	"context"
	"log"

	auth "github.com/nik2208/awesome-go-auth"
)

func main() {
	cfg := auth.DefaultConfig("replace-with-at-least-32-random-chars")
	service, err := auth.NewService(cfg, auth.NewMemoryUserStore(), auth.NewMemorySessionStore())
	if err != nil {
		log.Fatal(err)
	}

	_, tokens, err := service.Register(context.Background(), auth.RegisterInput{
		Email:    "alice@example.com",
		Password: "supersecurepassword",
		TenantID: "tenant-1",
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("access token issued", tokens.AccessToken != "")
}
```

## Features

- Secure configuration with validation.
- Register/login with password hashing (bcrypt).
- Signed access token + refresh token (HMAC-SHA256) with expiry.
- Stateful sessions with refresh token rotation and revocation (logout).
- Authenticated user retrieval (`Me`).
- Password reset (`ForgotPassword`, `ResetPassword`, `ChangePassword`).
- Passwordless magic link (`SendMagicLink`, `VerifyMagicLink`).
- SMS OTP login (`SendSMSCode`, `VerifySMSCode`).
- TOTP 2FA (`SetupTOTP`, `VerifyTOTPSetup`, `VerifyTOTP`, `DisableTOTP`).
- Email verification (`SendVerificationEmailToken`, `VerifyEmail`) and email change (`RequestEmailChange`, `ConfirmEmailChange`).
- Session admin helpers (`ListSessions`, `RevokeSessionByID`, `CleanupExpiredSessions`).
- User metadata store and service helpers.
- Multi-tenant in-memory RBAC (`MemoryRolesPermissionsStore`) with roles and permissions.
- In-memory tenant store (`MemoryTenantStore`) with user↔tenant membership.
- Custom token claims via `Config.BuildTokenClaims`, also reflected in the enriched profile.
- API key service and HTTP middleware (`APIKeyService`, `APIKeyMiddleware`).
- In-process event bus (`EventBus`) for event-driven integrations.
- Extended storage interfaces and thread-safe in-memory implementations for all the above flows.

## Idiomatic entrypoint and HTTP adapters

- `auth.New(...)` entrypoint with functional options (`WithSecret`, `WithTokenTTLs`, `WithUserStore`, `WithSessionStore`, etc.).
- Framework-agnostic adapters available:
  - `adapter/nethttp` (`Middleware`, `Mount`)
  - `adapter/chi` (`Middleware`, `Mount`)
  - `adapter/gin` (`Middleware`, `Mount`)
  - `adapter/echo` (`Middleware`, `Mount`)

## Parity Snapshot

| Feature | awesome-node-auth | awesome-go-auth | Notes |
|---------|-------------------|-----------------|-------|
| JWT access + refresh tokens | ✅ | ✅ | HMAC-SHA256, stateful sessions |
| Token rotation + revocation | ✅ | ✅ | |
| Email/Password auth (bcrypt) | ✅ | ✅ | |
| Magic Link | ✅ | ✅ | |
| SMS OTP | ✅ | ✅ | |
| TOTP 2FA | ✅ | ✅ | |
| OAuth 2.0 (Google, GitHub, generic) | ✅ | ✅ | |
| Account linking | ✅ | ✅ | |
| Multi-tenancy | ✅ | ✅ | |
| RBAC | ✅ | ✅ | |
| Session management | ✅ | ✅ | |
| API Keys (M2M) | ✅ | ✅ | scopes, IP allowlist |
| Event Bus | ✅ | ✅ | in-process pub/sub |
| SSE real-time notifications | ✅ | ✅ | SseDistributor for Redis scaling |
| Outbound webhooks (HMAC) | ✅ | ✅ | |
| Inbound webhooks sandbox | ✅ | ⚠️ | Wazero WASM sandbox planned |
| Telemetry | ✅ | ✅ | TelemetryStore interface |
| Mail templating i18n | ✅ | ✅ | en + it built-in |
| HTTP mailer transport | ✅ | ✅ | no SMTP needed |
| IDP / OIDC mode | ✅ | ✅ | Discovery, JWKS, Auth, Token, UserInfo |
| Admin UI (embedded) | ✅ | ✅ | embed.FS |
| Auth UI (embedded) | ✅ | ✅ | embed.FS |
| auth.js browser SDK | ✅ | ✅ | embed.FS |
| MCP server | ✅ | ✅ | JSON-RPC tools for AI editors |
| OpenAPI spec generation | ✅ | ✅ | |
| net/http adapter | — | ✅ | |
| Chi adapter | — | ✅ | |
| Gin adapter | — | ✅ | |
| Echo adapter | — | ✅ | |
| User metadata store | ✅ | ✅ | |
| Password reset flow | ✅ | ✅ | |
| Email verification | ✅ | ✅ | |
| Email change flow | ✅ | ✅ | |
| Custom token claims | ✅ | ✅ | BuildTokenClaims hook |
| Zero DB dependencies | — | ✅ | interface-based stores |
| Zero CGo | — | ✅ | CGO_ENABLED=0 compatible |
