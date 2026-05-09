# awesome-go-auth

[![Go](https://img.shields.io/badge/go-1.23+-blue.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Libreria di autenticazione server-side in Go che porta in modo fedele `awesome-node-auth` nel mondo Go.

> Full reference: [README.detailed.md](./README.detailed.md)

## Parity Snapshot vs `awesome-node-auth`

| Capability | Status in `awesome-go-auth` | Notes |
|---|---|---|
| Auth strategies (email/password, magic link, SMS OTP, TOTP 2FA, OAuth linking) | ✅ Implemented | Flussi e contratti endpoint allineati al progetto Node. |
| Token management (cookie/bearer, access/refresh rotation, secure cookies) | ✅ Implemented | Supporto strategy web + native, refresh rotation e cookie hardening. |
| Identity Provider (IdP) mode (RS256 + JWKS + resource server validation) | ✅ Implemented | Endpoints discovery/JWKS e validazione JWT RS256 lato resource server. |
| Stateful sessions | ✅ Implemented | Session lifecycle con revoca real-time e controlli configurabili. |
| Dynamic email templates + UI i18n fallback | ✅ Implemented | Template dinamici con fallback localizzato integrato. |
| CSRF protection | ✅ Implemented | Double-submit cookie + header per browser clients. |
| Account management | ✅ Implemented | Profilo, password/email change, verification, delete account. |
| Account linking | ✅ Implemented | Link/unlink provider OAuth con pending-link flow. |
| RBAC | ✅ Implemented | Role/permission checks tenant-aware. |
| Multi-tenancy | ✅ Implemented | Tenant isolation con modelli e claims tenant-aware. |
| Admin panel | ✅ Implemented | Admin UI integrata con API amministrative. |
| Built-in UI + auth runtime (`auth.js`) | ✅ Implemented | UI embedded e runtime auth per integrazione frontend. |
| Client libraries compatibility (Angular + Flutter) | ✅ Implemented | Compatibile con strategy cookie+CSRF e bearer. |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify channels) | ✅ Implemented | Event bus, SSE, webhook in/out e telemetry end-to-end. |
| API keys (M2M) | ✅ Implemented | API key con scope, revoca, audit e policy di accesso. |
| OpenAPI / Swagger docs | ✅ Implemented | Specifiche OpenAPI auto-generate per router auth/admin/tools. |
| MCP server (`awesome-node-auth-mcp-server`) | ➖ Out of scope | Nessun MCP server Go incluso in questo repository. |

---

## Installazione

```bash
go get github.com/nik2208/awesome-go-auth
```

## Quick start

```go
package main

import (
	"log"

	auth "github.com/nik2208/awesome-go-auth"
)

func main() {
	cfg := auth.DefaultConfig("replace-with-a-long-random-secret")
	svc, err := auth.NewService(cfg, myUserStore, mySessionStore)
	if err != nil {
		log.Fatal(err)
	}

	_ = svc
}
```
