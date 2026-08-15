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

This section mirrors `CompatibilityNotes()`, which returns the same register as
data. Neither is hand-maintained against the other: `compatibility_test.go` pins
the set of deviations, the facts each one has to keep stating, and the presence of
every entry and citation below, so a deviation cannot quietly drop out of either.
Adding one means updating the function, this section and the pinned set together.

Citations are `file:line` into `awesome-node-auth@cc01e997` (npm 1.9.0), the
revision the whole contract was extracted from.

### `forgot-password`: unconditional 200 on delivery failure

`forgot-password-succeeds-on-delivery-failure`

- **Surface**: `POST <prefix>/forgot-password`.
- **This port**: always `200 {"success": true}` — when the mail was sent, when the
  configured sender returns an error, and when no sender is configured at all. The
  reset token stays stored in every case. A *store* failure still answers `500`,
  which is the reference's behaviour and is kept.
- **The reference**: the send sits inside the route's `try`, so a throwing mailer
  reaches `handleError` and answers `500` (`auth.router.ts:787-798`).
- **Why**: that `500` fires only for an address that **exists**, so a broken mail
  gateway turns the one route whose purpose is to reveal nothing about who is
  registered into an account-enumeration oracle. The contract records the status
  and marks it `[UNTESTED]`, and no client can depend on one that appears only when
  the operator's mailer is down.
- **Observing the failure**: only the HTTP surface swallows it.
  `Auth.ForgotPassword` absorbs `ErrDeliveryFailed` (and nothing else) and logs
  `auth: password reset delivery failed; the route still answered success: …`,
  without naming the address. `Service.ForgotPassword` still returns the error, so
  a direct library caller learns about it.

### The 2FA step-up token is typed, not an access token

`temp-token-is-typed-not-an-access-token`

- **Surface**: `POST <prefix>/login` (the `tempToken` in a 2FA challenge) and the
  step-up routes that accept it.
- **This port**: the step-up token carries its own type. It is accepted by the
  second-factor routes and by nothing else, and an ordinary access token is not
  accepted in its place.
- **The reference**: mints the `tempToken` as an ordinary 5-minute access token
  with no claim distinguishing it, so it authenticates any protected route for five
  minutes before the second factor has been presented, and a full access token also
  passes as a `tempToken` (`auth.router.ts:572-575`, `token.service.ts:20-24`).
- **Why**: reproducing it would mean shipping a five-minute bypass of the second
  factor the challenge exists to demand. The type claim is not on the wire — the
  token is opaque to every client — and the reference's own sharing is `[UNTESTED]`
  there, so no shipped client depends on it. The cost is that the `tempToken` in a
  `2FA_SETUP_REQUIRED` answer cannot reach the enrolment routes, which sit behind
  the access-token gate.

### `link-request` exempts a bearer credential from CSRF

`link-request-exempts-bearer-from-csrf`

- **Surface**: `POST <prefix>/link-request`.
- **This port**: a request carrying a real `Authorization: Bearer` credential is
  exempt from the double-submit check, as it is on every other route. Without one
  the check is enforced whether or not the request is cookie-authenticated.
- **The reference**: gates its hand-written double-submit check on
  `config.csrf.enabled` alone, with no `usingBearer` term — unlike its own auth
  middleware (`auth.middleware.ts:35`) — so it answers `403 CSRF_INVALID` to a
  bearer-authenticated caller that carries no cookie pair
  (`auth.router.ts:1489-1495`).
- **Why**: `Authorization` is not CORS-safelisted, so no cross-site page can set it
  and the exemption costs no CSRF protection: every request it admits is one an
  attacker could not have forged. The family contract records the reference's
  behaviour as a MISMATCH that breaks native bearer clients with no cookie jar, and
  marks it `[UNTESTED]`. A client that sends the pair is accepted by both.

### A password policy on `reset-password` and `change-password`

`password-policy-on-reset-and-change`

- **Surface**: `POST <prefix>/reset-password` and `POST <prefix>/change-password`.
- **This port**: rejects a new password shorter than `Config.MinPasswordLen` with
  `400 {"error": "Password is too weak", "code": "WEAK_PASSWORD"}`, checked before
  the current-password comparison on `/change-password`.
- **The reference**: applies no strength check on either route — the password goes
  straight to `passwordService.hash`. Its own OpenAPI document declares
  `minLength: 8` on both bodies and nothing enforces it
  (`auth.router.ts:801-825`, `auth.router.ts:904-932`).
- **Why**: the reference will hash and store a two-character password on a route
  reached with a mailed token, which silently undoes whatever policy the host
  applied at registration. `WEAK_PASSWORD` has no reference counterpart, so a client
  that does not know the code still sees a `400` it must show the user either way.
  The check order differs too: the reference would report a wrong current password
  first.

### `2fa/setup` omits the QR code

`totp-setup-omits-qrcode`

- **Surface**: `POST <prefix>/2fa/setup`.
- **This port**: answers `{"secret", "otpauthUrl"}` and nothing else.
- **The reference**: also returns `qrCode`, the same provisioning URI rendered as a
  PNG data URL (`auth.router.ts:832-835`).
- **Why**: the root package is stdlib plus `golang.org/x/crypto` and a QR encoder is
  neither. A client renders `otpauthUrl` itself, which is what the Rust port of this
  family does too. A client that displays the reference's PNG directly has to encode
  the URI instead.

### One-time tokens are base64url, not hex

`one-time-tokens-are-base64url`

- **Surface**: the reset-password, email-verification and email-change tokens
  carried in mailed links.
- **This port**: renders 32 random bytes as 43 base64url characters.
- **The reference**: renders the same 32 random bytes as 64 hexadecimal characters
  (`token.service.ts:270-272`).
- **Why**: `randomToken` is shared with the API-key and IdP code paths, which have
  no reason to be hex. Both forms are URL-safe and opaque, and no shipped client
  parses or measures a token — but a host that pinned a column width or a validation
  regex to 64 hex characters has to widen it.

### An advertised 2FA method must be one the store supports

`advertised-2fa-methods-require-store-support`

- **Surface**: `POST <prefix>/login`, the `available2faMethods` list in a 2FA
  challenge.
- **This port**: advertises a second factor only when the configured user store
  implements the capability that factor needs, as well as the configuration and user
  state the reference checks.
- **The reference**: checks configuration and user state alone, so it can advertise
  a method whose route then answers `501` because the store does not implement it
  (`auth.router.ts:557-559`).
- **Why**: a client picks its next request from this list, so advertising a factor
  that cannot complete strands the login with no way forward. The extra term can only
  ever remove an option that would have failed; a deployment whose store implements
  the capability sees the reference's list.

### The CSRF cookie is not reissued alongside tokens

`csrf-cookie-not-reissued-with-tokens`

- **Surface**: `Set-Cookie` on every route that issues tokens, including
  `POST <prefix>/login` and `POST <prefix>/refresh`.
- **This port**: the CSRF cookie is written by the router-level auto-init only, when
  the request carries no readable one. Issuing tokens does not reissue it, so one
  response never carries two `Set-Cookie` headers for that name.
- **The reference**: `sendTokens` sets a fresh `csrf-token` cookie on every issuance,
  in addition to the router-level auto-init, so a first login emits two `Set-Cookie`
  headers for the same name with different values in one response
  (`token.service.ts:204-209`).
- **Why**: which of two same-name `Set-Cookie` headers survives is left to the cookie
  jar, so the reference's pair makes the token a client will send back ambiguous on
  exactly the response that establishes it. Emitting one keeps the double-submit pair
  consistent. The cookie stays JS-readable and valid either way, so a client that
  reads it per request — as all three family clients do — cannot tell the difference.

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
