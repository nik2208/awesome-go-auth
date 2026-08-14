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
- Configurable session check policy (`allcalls` / `refresh` / `none`).
- Authenticated user retrieval (`Me`).
- Account management (`UpdateProfile`, `DeleteAccount`) in addition to password/email lifecycle.
- CSRF double-submit middleware (cookie + header) for browser flows.
- Password reset (`ForgotPassword`, `ResetPassword`, `ChangePassword`).
- Passwordless magic link (`SendMagicLink`, `VerifyMagicLink`).
- SMS OTP login (`SendSMSCode`, `VerifySMSCode`).
- Mail and SMS delivery for both of the above via `Config.SendMagicLink` / `Config.SendSMSCode`, with built-in senders over an HTTP mailer or SMS gateway ([Delivery](README_DETAILED.md#delivery)).
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
  - `adapter/nethttp` (`Middleware`, `Mount`, `MountWithConfig`)
  - `adapter/chi` (`Middleware`, `Mount`, `MountWithConfig`)
  - `adapter/gin` (`Middleware`, `Mount`, `MountWithConfig`)
  - `adapter/echo` (`Middleware`, `Mount`, `MountWithConfig`)
- All four adapters serve the same wire contract, configured by a single
  `auth.HTTPConfig` (mount prefix, cookie policy, CSRF) and written through the
  shared helpers in `wire.go`.

## HTTP wire conventions

The HTTP surface follows the `awesome-node-auth` contract the family clients
(Angular, Flutter, the served `auth.js`) are pinned to:

- `GET <prefix>/me` returns the user object **unwrapped**.
- Cookie mode (default) answers `{"success": true}` and sets the cookies;
  `X-Auth-Strategy: bearer` (exact, case-sensitive) answers with top-level
  `accessToken`/`refreshToken` and sets no cookies.
- Cookie names resolve to `__Host-` / `__Secure-` / bare from the cookie policy,
  and every read tries `__Host-` → `__Secure-` → bare.
- Errors are `{"error": "<message>", "code": "<CODE>"}`; a revoked session is
  `401 {"code": "SESSION_REVOKED"}`, the signal both browser clients use to stop
  refreshing and log out.
- CSRF is double-submit on `X-CSRF-Token`, enforced for cookie-authenticated
  unsafe methods only. There is no `/csrf` endpoint: the cookie is distributed by
  the router-level middleware.

## Deliberate deviations from the reference

The standing rule is to reproduce `awesome-node-auth` including its quirks, because
the family clients are pinned to it. The entries below are the places this port
knowingly does **not**, each with the reason the rule was set aside.

This list is hand-maintained and not yet exhaustive. The machine-checked
`CompatibilityNotes()` that would keep it honest — an exported function the README
mirrors and a test asserts — is still open as item 6 of
[#22](https://github.com/nik2208/awesome-go-auth/issues/22).

### `forgot-password`: unconditional 200 on delivery failure

- **Route**: `POST <prefix>/forgot-password`.
- **This port**: always `200 {"success": true}` — when the mail was sent, when the
  configured sender returns an error, and when no sender is configured at all. The
  reset token stays stored in every case. A *store* failure still answers `500`,
  which is the reference's behaviour and is kept.
- **The reference**: the send sits inside the route's `try`, so a throwing mailer
  reaches `handleError` and answers `500` (`auth.router.ts:787-798`).
- **Why**: that `500` fires only for an address that **exists**, so a broken mail
  gateway turns the one route whose purpose is to reveal nothing about who is
  registered into an account-enumeration oracle. The contract records it and marks
  it `[UNTESTED]`, and no client can depend on a status that appears only when the
  operator's mailer is down. `SMSVerifyHTTPError` answering `401` where the
  reference would answer `404` is the precedent for declining an oracle the
  reference leaves open.
- **Observing the failure**: only the HTTP surface swallows it.
  `Auth.ForgotPassword` absorbs `ErrDeliveryFailed` (and nothing else) and logs
  `auth: password reset delivery failed; the route still answered success: …`,
  without naming the address. `Service.ForgotPassword` still returns the error, so
  a direct library caller learns about it.

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
