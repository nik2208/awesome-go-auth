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
- Recupero utente autenticato (`Me`).
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
