# awesome-go-auth — Full Reference

> **Quick-start README** → [README.md](./README.md)

Una libreria JWT auth production-ready, database-agnostic e framework-agnostic per Go, ispirata a [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) e allineata ai porting ufficiali Rust/Dart/Python.

## Feature Overview

- JWT access/refresh con modalità cookie o bearer
- Sessioni stateful con revoca real-time
- Email/password auth, OAuth, magic link, SMS OTP, TOTP 2FA
- Account management completo (profilo, password/email, verification, delete)
- RBAC multi-tenant, account linking, API keys M2M
- Event bus, SSE, telemetry, inbound/outbound webhooks
- UI auth embedded, admin UI, OpenAPI/Swagger
- IdP mode OIDC (RS256 + JWKS)

## Parity Snapshot vs `awesome-node-auth`

| Capability | Status in `awesome-go-auth` | Notes |
|---|---|---|
| Auth strategies (email/password, magic link, SMS OTP, TOTP 2FA, OAuth linking) | ✅ Implemented | Copertura completa dei flow auth di Node. |
| Token management (cookie/bearer, access/refresh rotation, secure cookies) | ✅ Implemented | Cookie+bearer strategy, rotazione token e cookie hardening. |
| Identity Provider (IdP) mode (RS256 + JWKS + resource server validation) | ✅ Implemented | Discovery/JWKS + validazione downstream resource server. |
| Stateful sessions | ✅ Implemented | Store-backed session lifecycle con revoca e cleanup. |
| Dynamic email templates + UI i18n fallback | ✅ Implemented | Template store con fallback localizzato per email/UI. |
| CSRF protection | ✅ Implemented | Double-submit cookie pattern con header validation. |
| Account management | ✅ Implemented | Registrazione, profilo, password reset/change, email verify/change, delete. |
| Account linking | ✅ Implemented | Pending-link token flow + gestione linked accounts. |
| RBAC | ✅ Implemented | Permission checks con supporto tenant-aware. |
| Multi-tenancy | ✅ Implemented | Tenant propagation su modelli, endpoint e claims JWT. |
| Admin panel | ✅ Implemented | Admin UI + API admin per funzioni operative. |
| Built-in UI + auth runtime (`auth.js`) | ✅ Implemented | UI embedded servita con runtime JS pronto all’uso. |
| Client libraries compatibility (Angular + Flutter) | ✅ Implemented | Compatibilità strategy web cookie/CSRF e native bearer. |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify channels) | ✅ Implemented | Pipeline eventi completa con canali realtime e webhook. |
| API keys (M2M) | ✅ Implemented | API keys con scope, expiry, revoca e audit trail. |
| OpenAPI / Swagger docs | ✅ Implemented | Specifica OpenAPI per auth/admin/tools routers. |
| MCP server (`awesome-node-auth-mcp-server`) | ➖ Out of scope | Non incluso in questo package Go. |

## Installation

```bash
go get github.com/nik2208/awesome-go-auth
```

## Quick Start

```go
package main

import (
	"context"
	"log"

	auth "github.com/nik2208/awesome-go-auth"
)

func main() {
	cfg := auth.DefaultConfig("replace-with-a-long-random-secret")
	service, err := auth.NewService(cfg, myUserStore, mySessionStore)
	if err != nil {
		log.Fatal(err)
	}

	_, _, err = service.Login(context.Background(), auth.LoginInput{
		Email:    "alice@example.com",
		Password: "s3cur3P@ssw0rd",
		TenantID: "tenant-abc",
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

## Core Modules

- `AuthService`: login, refresh, logout, session listing
- `AccountService`: profile, password/email workflows, account deletion
- `MagicLinkService`, `OtpService`, `TotpService`: passwordless / OTP / 2FA
- `ApiKeyService`: machine-to-machine authentication
- `AuthTools`: event bus, telemetry, SSE, webhooks
- `IdPService`: OIDC discovery, JWKS, token issuing (RS256)

## Store Contracts (database agnostic)

Implementa le interfacce storage per collegare il tuo DB:

- `UserStore`
- `SessionStore`
- `RolesPermissionsStore`
- `TenantStore`
- `TemplateStore`
- `ApiKeyStore`
- `WebhookStore`
- `TelemetryStore`
- `PendingLinkStore`

## Security Model

- Hash password robusto + token TTL configurabili
- Revoca sessione e refresh rotation
- Cookie `HttpOnly`/`Secure`/`SameSite` e optional prefix `__Host-`/`__Secure-`
- CSRF double-submit per browser flow
- OIDC/JWKS per federazione RS256

## API Surface (high level)

- Session: `/login`, `/register`, `/refresh`, `/logout`, `/me`, `/sessions`
- Password & email: `/forgot-password`, `/reset-password`, `/change-password`, `/verify-email`, `/change-email/*`
- 2FA e passwordless: `/2fa/*`, `/magic-link/*`, `/sms/*`
- OAuth/linking: `/oauth/*`, `/link-request`, `/link-verify`, `/linked-accounts`
- UI/admin/tools: `/ui/*`, `/admin/*`, `/tools/*`, `/openapi.json`, `/.well-known/jwks.json`
