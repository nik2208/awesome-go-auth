# awesome-go-auth

`awesome-go-auth` e una libreria Go per autenticazione con sessioni stateful e token access/refresh.

## Installazione

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

## Funzionalità disponibili in questa versione Go

- Configurazione sicura con validazione.
- Register/login con hashing password (bcrypt).
- Access token + refresh token firmati (HMAC-SHA256) con expiry.
- Sessioni stateful con rotazione refresh token e revoca (logout).
- Policy session check configurabile (`allcalls` / `refresh` / `none`).
- Recupero utente autenticato (`Me`).
- Gestione account (`UpdateProfile`, `DeleteAccount`) oltre a password/email lifecycle.
- Middleware CSRF double-submit (cookie + header) per flussi browser.
- Password reset (`ForgotPassword`, `ResetPassword`, `ChangePassword`).
- Magic link passwordless (`SendMagicLink`, `VerifyMagicLink`).
- SMS OTP login (`SendSMSCode`, `VerifySMSCode`).
- TOTP 2FA (`SetupTOTP`, `VerifyTOTPSetup`, `VerifyTOTP`, `DisableTOTP`).
- Email verification (`SendVerificationEmailToken`, `VerifyEmail`) e cambio email (`RequestEmailChange`, `ConfirmEmailChange`).
- Session admin helpers (`ListSessions`, `RevokeSessionByID`, `CleanupExpiredSessions`).
- User metadata store + helper di service.
- RBAC multi-tenant in-memory (`MemoryRolesPermissionsStore`) con ruoli e permessi.
- Tenant store in-memory (`MemoryTenantStore`) con membership utente↔tenant.
- Custom token claims via `Config.BuildTokenClaims`, replicate anche nel profilo arricchito.
- API key service + middleware HTTP (`APIKeyService`, `APIKeyMiddleware`).
- Event bus in-process (`EventBus`) per integrazioni event-driven.
- Interfacce storage estese + implementazioni in-memory thread-safe per i flussi sopra.

## Entrypoint idiomatico + adapter HTTP

- Entrypoint `auth.New(...)` con functional options (`WithSecret`, `WithTokenTTLs`, `WithUserStore`, `WithSessionStore`, ecc.).
- Adapter framework-agnostic disponibili:
  - `adapter/nethttp` (`Middleware`, `Mount`)
  - `adapter/chi` (`Middleware`, `Mount`)
  - `adapter/gin` (`Middleware`, `Mount`)
  - `adapter/echo` (`Middleware`, `Mount`)

## Parity Snapshot vs `awesome-node-auth`

| Capability | Status in `awesome-go-auth` | Notes |
|------------|-----------------------------|-------|
| Auth strategies (email/password, magic link, SMS OTP, TOTP 2FA, OAuth linking) | ✅ Implemented | OAuth + account linking in `oauth.go`. |
| Token management (cookie/bearer, access/refresh rotation, secure cookies) | ✅ Implemented | Adapter HTTP supportano cookie e bearer; rotation attiva. |
| Identity Provider (IdP) mode (RS256 + JWKS + resource server validation) | ✅ Implemented | OIDC IdP con discovery, authorize, token, userinfo e JWKS. |
| Stateful sessions | ✅ Implemented | Revoca/rotation + `Config.SessionCheckOn` (`allcalls`/`refresh`/`none`). |
| Dynamic email templates + UI i18n fallback | ✅ Implemented | Template mail + fallback i18n built-in. |
| CSRF protection | ✅ Implemented | `CSRFMiddleware` cookie+header double-submit. |
| Account management | ✅ Implemented | Register, `UpdateProfile`, `DeleteAccount`, password/email lifecycle. |
| Account linking | ✅ Implemented | Pending link + linked account store. |
| RBAC | ✅ Implemented | `RolesPermissionsStore` tenant-aware. |
| Multi-tenancy | ✅ Implemented | `TenantStore` e membership utente↔tenant. |
| Admin panel | ✅ Implemented | `ServeAdminUI()` embedded. |
| Built-in UI + auth runtime (`auth.js`) | ✅ Implemented | `ServeAuthUI()` + `ServeAuthJS()`. |
| Client libraries compatibility (Angular + Flutter) | ✅ Implemented | Cookie+CSRF browser e bearer per native client. |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify channels) | ✅ Implemented | Event bus, SSE, webhooks, telemetry, notify. |
| API keys (M2M) | ✅ Implemented | `APIKeyService` + middleware API key. |
| OpenAPI / Swagger docs | ✅ Implemented | `GenerateOpenAPISpec`. |
| MCP server (`awesome-node-auth-mcp-server`) | ➖ Out of scope | Fuori scope di parity per questa libreria. |
