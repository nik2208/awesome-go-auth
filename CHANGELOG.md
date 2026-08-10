# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-07

Aligns the HTTP surface with the family wire contract (#22): the full auth-router
surface (~32 routes across all four adapters) now matches the reference in
routes, response envelopes, cookies, error codes and CSRF, so the shipped
Angular, Flutter and `auth.js` clients work against this port with only a
base-URL change. This is a breaking release across the token format, the cookie
names, the response bodies and several constructor signatures — see the BREAKING
entries below. There are no known prior consumers other than the family's own
clients, which this release is what makes compatible.

### Changed
- **BREAKING — `GET /auth/me` returns the user object unwrapped.** It was
  `{"user": {...}}`; it is now the object itself, matching the reference and the
  shipped Angular, Flutter and `auth.js` clients.
- **BREAKING — `login`, `register` and `refresh` no longer return tokens or the
  user in the body by default.** Cookie mode (the default) answers
  `{"success": true}` — plus `"userId"` on register — and sets the cookies.
  Sending `X-Auth-Strategy: bearer` (exact, case-sensitive) switches to
  `{"success": true, "accessToken": "...", "refreshToken": "..."}` with **no**
  `Set-Cookie` at all, including no CSRF cookie.
- **BREAKING — cookies are renamed and prefix-resolved.** `access_token` and
  `refresh_token` become `accessToken` and `refreshToken`, and the written name
  is resolved per the reference rule: insecure → bare, secure + root path + no
  domain → `__Host-<name>`, otherwise `__Secure-<name>`. Because `Secure`
  defaults to true, the default names are now `__Host-accessToken`,
  `__Host-refreshToken` and `__Host-csrf-token`. Existing sessions are logged
  out on upgrade. Every read site tries `__Host-` → `__Secure-` → bare, so a
  client is never locked out by a configuration change; logout expires all three
  variants of each cookie.
- **BREAKING — errors are JSON, not `text/plain`.** Every error is
  `{"error": "<message>", "code": "<CODE>"}`, with `code` omitted where the
  reference emits none. The codes are the reference catalog
  (`INVALID_CREDENTIALS`, `EMAIL_NOT_VERIFIED`, `SESSION_REVOKED`,
  `INVALID_REFRESH_TOKEN`, `CSRF_INVALID`, …) plus `USER_EXISTS`,
  `WEAK_PASSWORD` and `INVALID_BODY`, which have no reference counterpart. A
  revoked session is `401 {"code": "SESSION_REVOKED"}` on both `POST /refresh`
  and, under `SessionCheckOn: allcalls`, on any middleware-protected route.
- **BREAKING — a missing or unusable access token is `403`, not `401`, and
  carries no `code`.** This reproduces the reference middleware exactly. It is
  surprising next to the 401s, and it means a client keying refresh-retry on 401
  will not retry on an expired access token — but that is the behaviour the
  shipped clients were built against, and `SESSION_REVOKED` stays the one coded
  401 on the refresh path.
- **BREAKING — `POST /auth/logout` never fails.** It revokes best-effort,
  expires every cookie variant and answers `200 {"success": true}` even with no
  token at all. It used to answer `400` without one. Revocation goes through the
  new `(*Auth).LogoutRequest`, which tries the refresh token from the body or
  cookie first and then falls back to the access-token cookie — the credential
  the reference logout reads. The fallback is not optional: the refresh cookie is
  scoped to `<prefix>/refresh` in every configuration whose name does not resolve
  to `__Host-`, so a browser sends nothing to `<prefix>/logout` and a
  refresh-token-only logout silently leaves the session live server-side.
- **BREAKING — `POST /auth/refresh` accepts an empty body in cookie mode** and
  answers `401 {"error": "No refresh token provided"}` (was `400`) when no token
  is present anywhere. The body is read first, the cookie second.
- **BREAKING — `CSRFMiddleware` now takes an `HTTPConfig`** and
  `DefaultCSRFConfig` takes no arguments; the cookie attributes moved into
  `HTTPConfig.Cookies`. Enforcement follows the reference matrix: only
  cookie-authenticated unsafe methods on routes that sit behind the auth
  middleware. `logout` is exempt — the reference deliberately leaves it
  unprotected — as are bearer requests and safe methods. Rejection is
  `403 {"error": "CSRF token validation failed", "code": "CSRF_INVALID"}`.
  The exemption table is the contract for every route added later and is pinned
  route by route against the reference: `/2fa/verify` and
  `/change-email/confirm` are exempt (neither has an auth gate), while
  `/link-request` is **not** — it is the one unauthenticated route the reference
  CSRF-checks, via a manual double-submit inside the handler. The mount prefix is
  now located anywhere on a segment boundary in the request path, so an adapter
  mounted on a gin/echo group or a chi `Route` (URL `<base><prefix>/<route>`) is
  still enforced instead of silently unprotected.

  "Cookie-authenticated" is literal: a mutating request that carries no
  `accessToken` cookie is passed through to the access-token gate, which answers
  `403 {"error": "No access token provided"}` with **no** `code`. That is the
  reference's ordering — it extracts the token first and only then reaches its
  CSRF branch (`auth.middleware.ts:29-42`) — and it is what a client with neither
  credential now sees, where an earlier revision of this port answered
  `CSRF_INVALID`. `POST /auth/link-request` is the exception: it has no auth gate
  behind it, so it stays enforced with no credential at all, mirroring the
  reference's hand-written check (`auth.router.ts:1489-1495`). Without that carve-out
  a pure cross-site form post — no cookies, no `Authorization`, no headers —
  would reach the handler and overwrite an in-flight account-link token.
  One term of that route's reference check is **deliberately not reproduced**: the
  reference gates its manual check on `config.csrf.enabled` alone
  (`auth.router.ts:1489`), with no bearer exemption, so it refuses a
  bearer-authenticated `POST /auth/link-request` that carries no double-submit
  pair; this port exempts a real `Authorization: Bearer` credential there as it
  does everywhere else. `Authorization` is not CORS-safelisted, so no cross-site
  page can set it — the exemption costs no CSRF protection — and the family
  contract records the reference's behaviour as a mismatch that breaks native
  bearer clients. A client that sends the pair is accepted by both.

  The carve-out is matched against **every** reading of where the mount prefix
  sits in the request path, not just the leftmost. The middleware is told the
  prefix but never the base a host mounted it under, so it has to search for it —
  and the search is ambiguous when the base ends in the same segment as the prefix.
  A host that groups its API under `/auth` and keeps the default `/auth` prefix
  serves `/auth/auth/link-request`, which resolves at the leftmost occurrence to
  `/auth/link-request`: in neither route table, so it fell through to the
  cookie test, and a forgery carries no cookie. That combination left
  `POST /link-request` unenforced under a supported mount shape — a cross-site form
  post reached the handler, wrote the account-link token and mailed the address.
  Exemptions are still read from the leftmost occurrence only: path parameters are
  part of the path, so honouring a later one would let
  `DELETE /auth/linked-accounts/auth/login` borrow `/login`'s exemption. The
  remaining cost of a colliding base is over-enforcement, not under-enforcement —
  such a deployment also fails to recognise its own exempt routes, so a browser that
  still holds an access cookie is CSRF-checked on `POST /login`. That is
  pre-existing and fail-closed; giving the middleware the base path is the real fix
  and is an API change.
- **BREAKING — gin and echo now agree with net/http on cookie attributes.** Gin
  used to give the refresh cookie an arbitrary lifetime of ten times the access
  token's; both now write through the same serialiser, so the four adapters emit
  identical bytes.
- The CSRF cookie is distributed by router-level auto-init only, as in the
  reference — a request without a readable one gets a fresh 32-hex-character
  token. Unlike the reference, it is not additionally rotated inside
  login/refresh, which would emit two conflicting `Set-Cookie` headers for the
  same name on a first login. The client-visible behaviour is unchanged.

- **BREAKING — `auth.NewAPIKeyService` now takes the bcrypt cost:**
  `NewAPIKeyService(bcryptCost int)`. `Create` stores a bcrypt hash of the key,
  so it carried the same hardcoded cost as passwords and was equally
  unreachable; an operator raising `Config.BcryptCost` would otherwise still get
  key hashes pinned at 10. Pass `0` for the default — including from a
  verify-only call site, since `Verify` reads the cost out of the stored hash
  and never produces one. Existing keys keep verifying at whatever cost they
  were written with. Callers update as
  `auth.NewAPIKeyService()` → `auth.NewAPIKeyService(0)`.

### Added
- `Config.BcryptCost` and `auth.WithBcryptCost`, closing item 2 of #25. This is
  the port's spelling of the reference's `AuthConfig.bcryptSaltRounds`; "cost" is
  what `x/crypto/bcrypt` calls the parameter. The default is unchanged:
  `DefaultConfig` sets `bcrypt.DefaultCost`, and a zero value means "unset",
  which resolves to `bcrypt.DefaultCost` and never to `bcrypt.MinCost`.
  `Config.validate` rejects anything outside `[bcrypt.MinCost, bcrypt.MaxCost]`,
  and a cost explicitly configured *below* `DefaultCost` is reported once
  through `Config.Logger` at construction — legal, since the test suites need
  it, but never silent.
- `auth.NewWithConfig(cfg Config, opts ...Option)`, closing item 3 and the root
  cause of #25. `New` builds its `Config` internally and the exported `Option`
  set has always been narrower than `Config`, so the individual TTLs and
  `EmailVerificationMode` were unreachable from outside the package. Taking the
  struct fixes that class of gap once and cannot drift as `Config` grows.
  Options still apply on top, so the two styles compose. (Item 1, the single
  signing secret, is untouched and #25 stays open for it.)
- `wire.go`: the shared conventions in the root package (stdlib only) —
  `HTTPConfig`, `CookieOptions`, `HTTPError` and the error catalog,
  `WriteJSON`/`WriteHTTPError`/`WriteSuccess`/`WriteTokens`, `CookieValue`,
  `IsBearerRequest`, `AccessTokenFromRequest`, `RefreshTokenFromRequest`. Routes
  added by later PRs call these rather than re-deriving shapes.
- `MountWithConfig` and `NewWithConfig` on all four adapters, so the mount prefix
  and cookie policy are configurable and identical across frameworks.
- `auth.WithSessionCheckOn`, without which the middleware's `SESSION_REVOKED`
  branch was unreachable through `auth.New`.
- `Service.TokenTTLs`, so cookie lifetimes track token lifetimes instead of
  being hardcoded.
- `adapter/internal/wiretest`: one conformance suite asserting status, exact
  body key set, exact `Set-Cookie` attributes and both delivery modes, run
  against all four adapters.

### Known limitations
- `openapi.go` and the served `ui/auth.js` still describe and consume the
  pre-0.2.0 shapes (`{"tokens": …}`, snake_case request fields). Bringing them
  onto the new contract is follow-up work, tracked with the rest of #22.

## [0.1.0] - 2026-08-02

First tagged release. The repository had never been tagged, so this release
carries everything built so far, including the four fixes below. Earlier work is
listed under "Pre-release baseline" and was only ever available as a pseudo-version.

### Added
- **OAuth 2.0 + Account Linking** (`oauth.go`): `OAuthService`, `GoogleProvider`, `GitHubProvider`, `HandleCallback`, `MemoryLinkedAccounts`, `PendingLinkStore`, `LinkedAccountStore`
- **SSE (Server-Sent Events)** (`sse.go`): `SseHub`, `SseDistributor` interface, `ServeSSE` handler with 30-second keepalive pings
- **Outbound Webhooks** (`webhooks.go`): `WebhookDispatcher`, `VerifyWebhookSignature`, HMAC-SHA256 signed delivery
- **Telemetry** (`telemetry.go`): `TelemetryStore` interface, `MemoryTelemetryStore`, `TelemetryFilter`
- **Mail** (`mailer.go`): `MailerTransport` interface, `HTTPMailerTransport`, `MailTemplater` with built-in English and Italian templates (reset_password, magic_link, verify_email, email_change)
- **OIDC IDP** (`idp.go`): `IDP` with Discovery, JWKS, Authorization, Token, UserInfo endpoints; RS256 JWT signing (stdlib only, no external JWT library)
- **MCP Server** (`mcp.go`): JSON-RPC 2.0 MCP tool server exposing auth operations for AI editors (tools/list, tools/call)
- **OpenAPI 3.0** (`openapi.go`): `GenerateOpenAPISpec` returning a complete spec for all auth endpoints
- **Embedded UI** (`ui.go`, `ui/`): `ServeAdminUI`, `ServeAuthUI`, `ServeAuthJS` backed by `embed.FS`
  - `ui/admin.html` — single-page admin dashboard
  - `ui/auth.html` — login/register/magic-link/TOTP UI
  - `ui/auth.js` — vanilla JS browser SDK (~3KB, no dependencies)
- **Examples**: `examples/chi-postgres/`, `examples/gin-mongodb/`, `examples/echo-sqlite/`
- **Community files**: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, issue templates, PR template
- **Email verification mode** (`config.go`, `service.go`): `Config.EmailVerificationMode`, one of `none`|`lazy`|`strict`, default `none`. Previously `Register` hardcoded `IsEmailVerified: true`, which made the verification flow a no-op for self-registered users. `none` keeps the old behaviour exactly: `Register` marks the address verified, and `Login` still refuses any address that is unverified for another reason. `lazy` registers unverified and allows login; `strict` registers unverified and refuses login until the address is confirmed. `lazy` is the only mode that relaxes the pre-existing `Login` gate, so an embedder that does not set the field sees no behaviour change.

### Known limitations
- `EmailVerificationMode: strict` gates `Login`, not access as a whole: `Register` still returns a usable token pair, so a caller can hold a session without ever verifying (#21).
- `EmailVerificationMode: strict` is not reachable over HTTP: no adapter route exposes `SendVerificationEmailToken` or `VerifyEmail` (#9).
- `EmailVerificationMode: lazy` has no grace deadline; the Node reference expires it via `emailVerificationDeadline`, and the Go `User` has no such field.

### Changed
- **BREAKING — access and refresh tokens are now standard HS256 JWTs** (`token.go`): tokens are emitted as `base64url(header).base64url(claims).base64url(signature)` with a JOSE header of `{"alg":"HS256","typ":"JWT"}`, replacing the previous two-segment `payload.signature` format. Tokens issued before the upgrade will not validate. The signature is HMAC-SHA256 over the RFC 7515 §5.1 signing input — the ASCII string `base64url(header) + "." + base64url(claims)`, both segments unpadded — so the JOSE header is covered by the signature. Verification enforces an explicit `HS256` allow-list keyed on a strictly-named lowercase `alg` member, so `alg: none`, algorithm-confusion tokens and headers that only spell the member `ALG`/`Alg` are all rejected. Access and refresh tokens now also carry `email`, `role`, `isEmailVerified` and `isTotpEnabled` claims

## Pre-release baseline (never tagged)

### Added
- Core auth service: Register, Login, Refresh, Logout, Me
- Password reset flow: ForgotPassword, ResetPassword, ChangePassword
- Magic Link: SendMagicLink, VerifyMagicLink
- SMS OTP: SendSMSCode, VerifySMSCode
- TOTP 2FA: SetupTOTP, VerifyTOTPSetup, VerifyTOTP, DisableTOTP
- Email verification: SendVerificationEmailToken, VerifyEmail
- Email change: RequestEmailChange, ConfirmEmailChange
- Session management: ListSessions, RevokeSessionByID, CleanupExpiredSessions
- User metadata store and service helpers
- RBAC: CreateRole, AssignRole, UserHasPermission
- Multi-tenancy: CreateTenant, AddUserToTenant
- API Keys: APIKeyService, APIKeyMiddleware
- Event Bus: EventBus, Subscribe, Publish
- HTTP adapters: net/http, Chi, Gin, Echo
- In-memory stores: MemoryUserStore, MemorySessionStore, MemoryMetadataStore, MemoryRolesPermissionsStore, MemoryTenantStore
- Custom token claims via BuildTokenClaims hook
