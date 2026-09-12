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
- Custom token claims via `Config.BuildTokenClaims`, written by hand or built from configuration with `StaticClaims`, `UserFieldClaims`, `ChainClaims` and the synchronous `ClaimsWebhook`; reflected under `customClaims` on `GET /me`. The hook may override the reference's six base claims (`sub`, `email`, `role`, `loginProvider`, `isEmailVerified`, `isTotpEnabled`); the session claims `sid`, `tid`, `jti`, `typ`, `iss`, `iat` and `exp` are reserved. It runs at mint time and on `/me`, never in the adapters' middleware ([Custom Claims](README_DETAILED.md#custom-claims)).
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

<!-- BEGIN GENERATED: deviations -->
<!--
GENERATED FILE SECTION — do not edit by hand.

Every word below comes from CompatibilityNotes() in compatibility.go, which is
the single source of truth for the deviation register. To change what this
section says, change the register, then regenerate:

    go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .

TestREADMEIsGeneratedFromCompatibilityNotes re-renders the register and compares
it against the text below, failing on any difference in either direction: a Go
edit that was not regenerated, and a README edit that has no Go edit behind it,
both fail.
-->

## Deliberate deviations from the reference

The standing rule is to reproduce `awesome-node-auth` including its quirks,
because the family clients are pinned to it. The entries below are the places
this port knowingly does **not**, each with the reason the rule was set aside.

This section is generated from `CompatibilityNotes()`, which returns the same
register as data — it is not a second copy kept in step by hand.
`compatibility_test.go` re-renders it and compares it against this file, so a
deviation cannot be edited on one side only, and cannot be added to the register
without appearing here. The test also pins the set of ids and the wire facts
each entry has to keep stating, so an entry cannot be quietly hollowed out by
someone who does regenerate.

Citations are `file:line` into `awesome-node-auth@cc01e997 (npm 1.9.0)`, the
revision the whole contract was extracted from.

### `forgot-password`: unconditional 200 on delivery failure

`forgot-password-succeeds-on-delivery-failure`

- **Surface**: `POST <prefix>/forgot-password`.
- **This port**: Always `200 {"success": true}` — when the mail was sent, when
  the configured sender returns an error, and when no sender is configured at
  all. The reset token stays stored in every case. A *store* failure still
  answers `500`, which is the reference's behaviour and is kept.
- **The reference**: The send sits inside the route's `try`, so a throwing
  mailer reaches `handleError` and answers `500` (`auth.router.ts:787-798`).
- **Why**: That `500` fires only for an address that **exists**, so a broken
  mail gateway turns the one route whose purpose is to reveal nothing about who
  is registered into an account-enumeration oracle. The contract records the
  status as `[UNTESTED]`, and no client can depend on one that appears only when
  the operator's mailer is down.
- **Observing the failure**: Only the HTTP surface swallows it.
  `Auth.ForgotPassword` absorbs `ErrDeliveryFailed` (and nothing else) and logs
  `auth: password reset delivery failed; the route still answered success: …`,
  without naming the address. `Service.ForgotPassword` still returns the error,
  so a direct library caller learns about it.

### The 2FA step-up token is typed, not an access token

`temp-token-is-typed-not-an-access-token`

- **Surface**: `POST <prefix>/login` (the `tempToken` in a 2FA challenge) and
  the step-up routes that accept it.
- **This port**: The step-up token carries its own type. It is accepted by the
  second-factor routes and by nothing else, and an ordinary access token is not
  accepted in its place.
- **The reference**: Mints the `tempToken` as an ordinary 5-minute access token
  with no claim distinguishing it, so it authenticates any protected route for
  five minutes before the second factor has been presented, and a full access
  token also passes as a `tempToken` (`auth.router.ts:572-575`,
  `token.service.ts:20-24`).
- **Why**: Reproducing it would mean shipping a five-minute bypass of the second
  factor the challenge exists to demand. The type claim is not on the wire — the
  token is opaque to every client — and the reference's own sharing is
  `[UNTESTED]` there, so no shipped client depends on it. The cost is that the
  `tempToken` in a `2FA_SETUP_REQUIRED` answer cannot reach the enrolment
  routes, which sit behind the access-token gate.

### `link-request` exempts a bearer credential from CSRF

`link-request-exempts-bearer-from-csrf`

- **Surface**: `POST <prefix>/link-request`.
- **This port**: A request carrying a real `Authorization: Bearer` credential is
  exempt from the double-submit check, as it is on every other route. Without
  one the check is enforced whether or not the request is cookie-authenticated.
- **The reference**: Gates its hand-written double-submit check on
  `config.csrf.enabled` alone, with no `usingBearer` term — unlike its own auth
  middleware (`auth.middleware.ts:35`) — so it answers `403 CSRF_INVALID` to a
  bearer-authenticated caller that carries no cookie pair
  (`auth.router.ts:1489-1495`).
- **Why**: `Authorization` is not CORS-safelisted, so no cross-site page can set
  it and the exemption costs no CSRF protection: every request it admits is one
  an attacker could not have forged. The family contract records the reference's
  behaviour as a MISMATCH that breaks native bearer clients with no cookie jar,
  and marks it `[UNTESTED]`. A client that sends the pair is accepted by both.

### A password policy on `reset-password` and `change-password`

`password-policy-on-reset-and-change`

- **Surface**: `POST <prefix>/reset-password` and
  `POST <prefix>/change-password`.
- **This port**: Rejects a new password shorter than `Config.MinPasswordLen`
  with `400 {"error": "Password is too weak", "code": "WEAK_PASSWORD"}`, checked
  before the current-password comparison on `/change-password`.
- **The reference**: Applies no strength check on either route — the password
  goes straight to `passwordService.hash`. Its own OpenAPI document declares
  `minLength: 8` on both bodies and nothing enforces it
  (`auth.router.ts:801-825`, `auth.router.ts:904-932`).
- **Why**: The reference will hash and store a two-character password on a route
  reached with a mailed token, which silently undoes whatever policy the host
  applied at registration. `WEAK_PASSWORD` has no reference counterpart, so a
  client that does not know the code still sees a `400` it must show the user
  either way. The check order differs too: the reference would report a wrong
  current password first.

### `2fa/setup` omits the QR code

`totp-setup-omits-qrcode`

- **Surface**: `POST <prefix>/2fa/setup`.
- **This port**: Answers `{"secret", "otpauthUrl"}` and nothing else.
- **The reference**: Also returns `qrCode`, the same provisioning URI rendered
  as a PNG data URL (`auth.router.ts:832-835`).
- **Why**: The root package is stdlib plus `golang.org/x/crypto` and a QR
  encoder is neither. A client renders `otpauthUrl` itself, which is what the
  Rust port of this family does too. A client that displays the reference's PNG
  directly has to encode the URI instead.

### The default TOTP issuer is `Config.Issuer`, not `awesome-node-auth`

`totp-issuer-defaults-to-config-issuer`

- **Surface**: `POST <prefix>/2fa/setup`, the issuer in `otpauthUrl`.
- **This port**: Labels the provisioning URI with `Config.TwoFactorAppName` when
  it is set and with `Config.Issuer` when it is not — `awesome-go-auth` on
  `DefaultConfig` — as both the label prefix and the `issuer` parameter, in
  otplib's `issuer:account` form.
- **The reference**: Labels it with `config.twoFactor.appName` and falls back to
  the literal `'awesome-node-auth'` — its own package name — when no app name is
  configured (`auth.router.ts:830`, `totp.strategy.ts:11-17`).
- **Why**: The reference's fallback names the library, not the deployment, which
  is the wrong thing to show a user who opens their authenticator app. This port
  has carried `Config.Issuer` there since the route existed, so enrolments made
  before `TwoFactorAppName` was added sit under that name in users' apps, and
  switching the default now would file every new enrolment under a different
  name from the old ones on the same deployment. The difference is visible only
  on a deployment that sets neither field: one that sets `TwoFactorAppName` —
  the reference's `appName` — gets exactly the reference's label.
- **Matching the reference exactly**: `WithTwoFactorAppName("awesome-node-auth")`.
  Any name given is carried verbatim; only the fallback differs.

### TOTP codes from the adjacent 30-second steps are accepted

`totp-accepts-one-step-of-skew`

- **Surface**: `POST <prefix>/2fa/verify-setup` and `POST <prefix>/2fa/verify`,
  the two routes that check a TOTP code (`/2fa/disable` takes none, in either
  implementation).
- **This port**: Accepts a code from the previous or the next 30-second step as
  well as the current one: `validateTOTPCode` tries `TOTPSkew = 1` step either
  side of now (`totp.go`), so three codes are valid at any instant and each code
  is accepted over a 90-second window — its own step and the 30 seconds before
  and after it — where the reference's window is 30.
- **The reference**: Accepts the current step only. `TotpStrategy.verify` in
  `totp.strategy.ts` calls `totp.verify(token, { secret })` and sets no other
  option, and otplib's `verify` — `@otplib/totp` 13.4.0, the version the
  reference's package-lock.json pins for `otplib ^13.3.0` (13.4.1 today, same
  default) — defaults its window to zero seconds either side of now:
  `epochTolerance:f=0` in the `verify` method of `@otplib/totp`'s
  `dist/index.js`, documented in its types as
  `default: 0 = current period only`. A code is refused from the first second of
  the step after its own (`totp.strategy.ts:22-25`, `auth.router.ts:846`,
  `auth.router.ts:868`).
- **Why**: An authenticator runs on the phone's clock, and a user reads a code
  some seconds before the server sees it, so with no tolerance a code read in
  the last seconds of a step — or on a phone a few seconds adrift — is refused
  and the user has to try again, at every step boundary. RFC 6238 §5.2
  recommends allowing one step for exactly that delay, and one step is the
  tolerance mainstream verifiers ship with. The cost is that three of the
  million possible codes are valid at any instant instead of one.
- **Matching the reference exactly**: Not possible: `TOTPSkew` is a constant,
  not a knob, and no knob is planned. A deployment gets the one-step window
  whether or not it wants it.

### One-time tokens are base64url, not hex

`one-time-tokens-are-base64url`

- **Surface**: The reset-password, email-verification and email-change tokens
  carried in mailed links.
- **This port**: Renders 32 random bytes as 43 base64url characters.
- **The reference**: Renders the same 32 random bytes as 64 hexadecimal
  characters (`token.service.ts:270-272`).
- **Why**: `randomToken` is shared with the API-key and IdP code paths, which
  have no reason to be hex. Both forms are URL-safe and opaque, and no shipped
  client parses or measures a token — but a host that pinned a column width or a
  validation regex to 64 hex characters has to widen it.

### An advertised 2FA method must be one the store supports

`advertised-2fa-methods-require-store-support`

- **Surface**: `POST <prefix>/login`, the `available2faMethods` list in a 2FA
  challenge.
- **This port**: Advertises a second factor only when the configured user store
  implements the capability that factor needs, as well as the configuration and
  user state the reference checks.
- **The reference**: Checks configuration and user state alone, so it can
  advertise a method whose route then answers `501` because the store does not
  implement it (`auth.router.ts:557-559`).
- **Why**: A client picks its next request from this list, so advertising a
  factor that cannot complete strands the login with no way forward. The extra
  term can only ever remove an option that would have failed; a deployment whose
  store implements the capability sees the reference's list.

### `Config.Require2FA` is a deployment-level 2FA policy the reference has no equivalent of

`config-require2fa-is-a-system-policy-term`

- **Surface**: `POST <prefix>/2fa/disable` and `POST <prefix>/login`.
- **This port**: `Config.Require2FA` is a third term in two decisions the
  reference makes with two. On `/2fa/disable` it is ORed with the stored
  `require2FA` into the system-policy refusal, so a deployment that sets it and
  configures no settings store at all answers
  `403 {"error":"Cannot disable 2FA: required by system policy","code":"2FA_REQUIRED"}`
  where the reference answers `200 {"success":true}` and turns the factor off.
  At login it is ORed into the challenge term, so a user with no enrolled TOTP
  and no per-user flag is challenged where the reference logs them straight in.
- **The reference**: Has no config-level `require2FA`: the name exists only on
  the settings store and on the user record, never on `AuthConfig`.
  `/2fa/disable` refuses on the per-user flag and on the stored setting and on
  nothing else, and login challenges on an enrolled TOTP or the per-user flag
  alone (`auth.router.ts:880-902`, `auth.router.ts:552`,
  `settings-store.interface.ts:64`, `user.model.ts:39`).
- **Why**: A deployment-wide switch is what an embedder without the admin router
  has instead of the Control panel: the reference reaches the same policy by
  writing `require2FA: true` through a settings store, which requires running a
  store and an admin surface to write it. The term is additive and inert by
  default — `Config.Require2FA` is `false` unless a deployment sets it, and a
  deployment that leaves it alone gets the reference's answers on both routes,
  including with a settings store attached. Both wire shapes are the reference's
  own: the `403` body is the one it sends for the stored setting, and the
  challenge is the one it sends for the per-user flag, so a client meets nothing
  it has no branch for.
- **Matching the reference exactly**: Leave `Config.Require2FA` unset (the
  default) and express the policy through a `SettingsStore` holding
  `require2FA: true`, which is the reference's own term and produces the same
  `/2fa/disable` refusal with no login-side difference.

### The CSRF cookie is not reissued alongside tokens

`csrf-cookie-not-reissued-with-tokens`

- **Surface**: `Set-Cookie` on every route that issues tokens, including
  `POST <prefix>/login` and `POST <prefix>/refresh`.
- **This port**: The CSRF cookie is written by the router-level auto-init only,
  when the request carries no readable one. Issuing tokens does not reissue it,
  so one response never carries two `Set-Cookie` headers for that name.
- **The reference**: `setTokenCookies` sets a fresh `csrf-token` cookie on every
  cookie-mode issuance — it is reached from `sendTokens` (`auth.router.ts:403`)
  and from the OAuth redirect path — in addition to the router-level auto-init,
  so a first login emits two `Set-Cookie` headers for the same name with
  different values in one response (`token.service.ts:204-209`,
  `auth.router.ts:529-538`).
- **Why**: Which of two same-name `Set-Cookie` headers survives is left to the
  cookie jar, so the reference's pair makes the token a client will send back
  ambiguous on exactly the response that establishes it. Emitting one keeps the
  double-submit pair consistent. The cookie stays JS-readable and valid either
  way, so a client that reads it per request — as all three family clients do —
  cannot tell the difference.

### OAuth provisioning is a configured policy, with three refusals the reference has no counterpart for

`oauth-provisioning-is-a-policy-not-a-function`

- **Surface**: `GET <prefix>/oauth/{provider}/callback`.
- **This port**: Resolves the callback under `OAuthWiring.Provisioning`
  (`OAuthProvisioning{AutoCreate, AllowedEmailDomains, RequireVerifiedEmail, OnEmailMatch, FieldMap}`).
  Three of its outcomes are refusals with no reference counterpart, all `403`
  JSON on the callback: `OAUTH_EMAIL_NOT_VERIFIED` when `RequireVerifiedEmail`
  is set and the provider asserted nothing, `OAUTH_EMAIL_DOMAIN_NOT_ALLOWED`
  when the address is outside `AllowedEmailDomains`, and
  `OAUTH_USER_NOT_PROVISIONED` when the identity is unknown and `AutoCreate` is
  false, or when the address belongs to an account and `OnEmailMatch` is
  `reject`. The fourth, `OnEmailMatch: "conflict"`, is the reference's own
  `OAUTH_ACCOUNT_CONFLICT`: the stash and the 302 to `/account-conflict`, sent
  exactly as the reference sends them. An account the callback creates records
  the provider as `loginProvider`, takes `isEmailVerified` from the provider's
  claim — true when the provider said nothing, which is the common case — and
  fills further columns from `FieldMap`.
- **The reference**: Has no provisioning at all:
  `findOrCreateUser(profile, state)` is an abstract method the integrator
  implements, and the library knows only two outcomes from it — a user, which
  becomes a session, or an `AuthError` coded `OAUTH_ACCOUNT_CONFLICT`, which
  becomes the stash and the redirect. Anything else that function throws reaches
  `handleError`, which answers `500` unless it is an `AuthError` carrying its
  own status (`generic-oauth.strategy.ts:169-172`, `google.strategy.ts:67`,
  `github.strategy.ts:78`, `auth.router.ts:1346-1355`).
- **Why**: This port's consumer configures the library from a file; it cannot
  subclass a strategy, so a policy expressed as configuration is the only form
  the reference's function can take here. The refusals are what that policy
  needs to say and the reference never had to: its integrator would have thrown
  whatever they liked. Defaults reproduce what this port did before the policy
  existed — `AutoCreate` true, `OnEmailMatch` `link`, no domain list, no
  verification demand — so a deployment that configures nothing cannot see any
  of the three codes. `OnEmailMatch` exists because linking by address across
  providers is the account-takeover shape the reference's own store interface
  warns about (`findByProviderAccount`, `user-store.interface.ts:105-119`), and
  the port's default is the unsafe one only because changing it silently would
  lock accounts out of deployments that rely on it.
- **Matching the reference exactly**: Leave `OAuthWiring.Provisioning` nil. The
  callback then behaves as it always has, no refusal is reachable, and the only
  policy-driven answer that can appear is the reference's own account conflict —
  which needs `OnEmailMatch: "conflict"` and so cannot appear either.

### Cookie `Max-Age` follows the configured TTL, not a hardcoded 7 days

`cookie-max-age-follows-configured-ttl`

- **Surface**: `Set-Cookie` on every cookie-mode route that issues tokens,
  including `POST <prefix>/login`, `POST <prefix>/register` and
  `POST <prefix>/refresh`.
- **This port**: Derives each token cookie's `Max-Age` from the lifetime of the
  token it carries — the access cookie from `Config.AccessTokenTTL`, the refresh
  cookie from `Config.RefreshTokenTTL` — unless the deployment sets
  `CookieOptions.AccessTokenMaxAge` or `RefreshTokenMaxAge` explicitly. On
  `DefaultConfig` that is `Max-Age=900` on the access cookie and
  `Max-Age=2592000` (30 days) on the refresh cookie.
- **The reference**: Hardcodes both lifetimes in `setTokenCookies`, ignoring
  configuration: `maxAge: 15 * 60 * 1000` on the access cookie and
  `maxAge: 7 * 24 * 60 * 60 * 1000` on the refresh cookie, so it always emits
  `Max-Age=604800` there whatever `refreshTokenExpiresIn` says
  (`token.service.ts:28`, `token.service.ts:195`, `token.service.ts:199-202`).
- **Why**: Deriving the cookie lifetime from the configured TTL is the point: a
  cookie must not outlive, or expire before, the token it carries. The
  reference's hardcoded value silently contradicts its own
  `refreshTokenExpiresIn` — that option signs the refresh token (defaulting to
  `7d`), so raising it to 30 days leaves the token valid for 30 days while the
  browser drops the cookie carrying it after 7, ending the session early with a
  credential nobody can present. The divergence is a header value, not a
  validity change: each port honours its own tokens' server-side expiry either
  way. The access cookie matches the reference on `DefaultConfig` (both 15
  minutes, `Max-Age=900`) and diverges on any custom `AccessTokenTTL`; the
  refresh cookie diverges at the default too, because `Config.RefreshTokenTTL`
  is 30 days here where the reference's refresh token defaults to `7d`.
- **Matching the reference exactly**: A host that needs the reference's literal
  headers sets `CookieOptions.RefreshTokenMaxAge` to 7 days (and
  `AccessTokenMaxAge` to 15 minutes); an explicit value is never overwritten by
  the derivation.

### The JWKS CORS wildcard is the one-element `[]string{"*"}`, not an entry

`jwks-cors-wildcard-string-form`

- **Surface**: `GET <prefix>/.well-known/jwks.json`.
- **This port**: A `JWKSCORSOrigins` of exactly `[]string{"*"}` answers
  `Access-Control-Allow-Origin: *` to every request, the same as leaving the
  field nil. Every other slice is an allowlist: a listed `Origin` is echoed
  back, an unlisted one gets no `Access-Control-Allow-Origin` header at all, and
  an entry `*` inside a longer slice is an ordinary entry that matches only an
  `Origin` header of literally `*`.
- **The reference**: `jwksCorsOrigins` is typed `string | string[]` and the
  wildcard test is `corsOrigins === '*'` against the whole value, so only the
  *string* is the wildcard. Every array is an allowlist, including `['*']`,
  whose one entry matches only the `Origin` header `*` — one no browser sends —
  so that value disables the header rather than opening the route
  (`auth.router.ts:492-500`, `auth-config.model.ts:102`).
- **Why**: Go has no `string | string[]`, and `[]string` is the shape every
  other list in this package has, so one of the two readings of `{"*"}` had to
  win. The reference's own documented default for the field is the wildcard
  (`@default '*'`), so the slice that spells it is read as the string form
  rather than as an allowlist that can never match — the reading a host writing
  `{"*"}` plainly intends. The difference is confined to that single value: nil,
  the empty slice and every other allowlist behave exactly as the reference
  does.
- **Matching the reference exactly**: A deployment that means the reference's
  `['*']` — an allowlist no browser `Origin` can match — writes the empty slice
  `[]string{}` here, which sends the header to nobody. Note also that neither
  implementation sends `Vary: Origin` while both send
  `Cache-Control: public, max-age=3600`, so an allowlisted response must not
  reach a shared cache.

### Resource-server mode unmounts the whole credential set, not six routes of it

`resource-server-gates-all-credential-routes`

- **Surface**: `HTTPConfig.ResourceServer`: the nineteen routes of
  `ResourceServerGatedRoutes`.
- **This port**: Registers none of the nineteen routes that mint, deliver or
  consume a credential, so each answers `404` — `/register`, `/login`,
  `/refresh`, `/logout`, `/forgot-password`, `/reset-password`,
  `/change-password`, `/send-verification-email`, `/verify-email`,
  `/change-email/request`, `/change-email/confirm`, `/magic-link/send`,
  `/magic-link/verify`, `/sms/send`, `/sms/verify`, `/2fa/setup`,
  `/2fa/verify-setup`, `/2fa/verify` and `/2fa/disable`. `GenerateOpenAPISpec`
  drops the same nineteen under `OpenAPIInfo.ResourceServer`, so the published
  spec and the mount agree. What stays is `/me`, the session routes, `/profile`,
  `/add-phone`, `/account` and the OAuth and linking group — and those still
  need a local user store: `/me` reads it through `Service.Authenticate`,
  `/profile`, `/add-phone` and `/account` write it, and the OAuth callback
  provisions a user and mints a local session. The flag is about credentials,
  not about store independence. The deployment with no user store is the one
  that mounts `ResourceServerMiddleware` on its own routes, whose bearer and
  cookie paths both build the principal from verified claims and read no store
  at all.
- **The reference**: Guards six registrations on `isResourceServer` — `/login`,
  `/logout`, `/refresh`, `/register`, `/forgot-password` and `/reset-password` —
  and leaves the other thirteen mounted. Those thirteen reach handlers that read
  and write the user store the mode says this instance does not have, so a
  caller gets a `500` from a failing store lookup, or a `200` on a route that
  mailed nothing, rather than a routing answer (`auth.router.ts:507-510`,
  `auth.router.ts:541`, `auth.router.ts:590`, `auth.router.ts:622`,
  `auth.router.ts:713`, `auth.router.ts:777`, `auth.router.ts:802`).
- **Why**: The reference's own comment for the flag is that this instance has no
  local user DB and only token verification makes sense, and the six guards are
  an incomplete application of exactly that rule: a magic link cannot be minted,
  an SMS code cannot be stored and a TOTP secret cannot be enrolled without the
  store the mode has removed. Leaving them mounted turns a configuration mistake
  into a runtime failure on a credential route, which is the worst place to
  discover it. Gating all nineteen makes the mode mean one thing, and makes it
  checkable: the same list drives the mount, the OpenAPI spec and the
  conformance suite. It is drawn at the credential and not at the store
  deliberately: gating every store-reading route would unmount `/me` and the
  account routes from the deployment that has both a store and a remote issuer,
  which is the commoner configuration, to protect one that has no reason to
  mount the auth router at all.
- **Matching the reference exactly**: Leave `HTTPConfig.ResourceServer` unset
  and mount `ResourceServerMiddleware` on the host's own routes: the bearer
  verification is independent of the gating, and every auth route then stays
  mounted as it is today. A host that wants the reference's partial set mounts
  two routers — one with the flag, one without — under different prefixes.

### An unknown `kid` refetches the JWKS at most once per `MinRefreshInterval`

`jwks-unknown-kid-refetch-is-rate-limited`

- **Surface**: `VerifyRS256` / `JWKSClient`: the rotation retry behind every
  bearer token.
- **This port**: On a `kid` the cached JWKS does not carry, the cache is
  invalidated and the key looked up once more — but only when the cached
  document is older than `ResourceServerConfig.MinRefreshInterval` (default
  `DefaultJWKSMinRefreshInterval`, 30 seconds). Inside that window the token is
  refused with `Unknown signing key` and no HTTP call is made, so N requests
  bearing unknown `kid`s cost at most one outbound fetch per interval. A
  negative `MinRefreshInterval` turns the limit off and restores the reference
  behaviour exactly. The `RS256` allow-list is also checked before the key
  lookup rather than after it, so an `alg: none` or `alg: HS256` token never
  reaches the issuer at all; both orderings answer `401` `INVALID_TOKEN`, only
  the logged message differs.
- **The reference**: Calls `jwksClient.invalidateCache()` and retries on every
  unknown `kid`, with no interval and no cap. `invalidateCache` clears the
  cached document *and* the in-flight `fetchPromise`, so concurrent requests do
  not even coalesce onto one fetch, and the `algorithms: ['RS256']` pin is
  inside `jwt.verify`, which runs after the key lookup
  (`token.service.ts:116-125`, `token.service.ts:136`,
  `jwks.service.ts:101-105`, `jwks.service.ts:56-58`).
- **Why**: Unrestricted, the retry is an unauthenticated request amplifier:
  anyone who can reach the resource server makes it call the issuer once per
  request by sending a random `kid`, and because the in-flight handle is dropped
  too, a burst multiplies rather than coalesces. Worse, the refusal is
  collateral: every legitimate request arriving between the invalidation and the
  next document landing takes the cold path and blocks on the issuer, which is
  the one thing the stale-while-revalidate cache exists to prevent. The interval
  costs a real rotation nothing — a cached document is typically an hour old by
  the time a token names a key it does not carry, so the first such token still
  refetches and still verifies — and only refuses the case of two rotations
  inside 30 seconds. `node-jwks-rsa` ships the same guard as its `rateLimit`
  option for the same reason.
- **Matching the reference exactly**: Set
  `ResourceServerConfig.MinRefreshInterval` to any negative duration: every
  unknown `kid` then invalidates and refetches, as the reference does. Nothing
  else in the verifier changes.

### `register` opens a session, where the reference only creates the account — provisional, tracked as `nik2208/awesome-go-auth#21`

`register-issues-a-session`

- **Surface**: `POST <prefix>/register`.
- **This port**: Mints a token pair for the new account and delivers it with the
  `201`, through the same delivery switch every other issuing route uses: in
  cookie mode the response is `201 {"success": true, "userId": "…"}` plus
  `Set-Cookie` for `accessToken` and `refreshToken`, and in bearer mode
  (`X-Auth-Strategy: bearer`) the same body with top-level `accessToken` and
  `refreshToken` fields and no cookies at all. A refresh session row is created
  with it, so the account is logged in as soon as it exists and
  `GET <prefix>/me` answers on the credential the registration returned.
- **The reference**: Mounts the route at all only when the host supplies
  `options.onRegister`; without it there is no `POST <prefix>/register` in the
  reference and the path answers `404` where this port answers `201` (or
  `400 INVALID_INPUT` for a body missing a credential). That unconditional mount
  is a second, smaller difference on this surface, and it is named here rather
  than kept as a separate entry because a host that has no register route has no
  session question to ask. Where the reference *is* mounted it answers
  `201 {"success": true, "userId": user.id}` and nothing else: the register
  route never reaches `sendTokens` — the one function that writes
  `setTokenCookies` or the body tokens — and never reaches `issueTokens`, so no
  cookie is set, no token is returned and no session row is created. The caller
  is unauthenticated after a successful registration and has to `POST /login`
  with the credentials it just chose (`auth.router.ts:713-730`,
  `auth.router.ts:726`, `auth.router.ts:399-406`).
- **Why**: **Provisional, and recorded rather than endorsed.** The entry exists
  so that a difference which is client-visible today is visible in the contract
  too; it is not a settled product decision. What it costs is a bypass of the
  email verification gate: `Service.Register` sets `IsEmailVerified` from the
  configured mode and then mints the token pair unconditionally, so under
  `strict` a brand-new account walks away holding a usable access token that
  `POST <prefix>/login` would have refused for the same user with
  `403 EMAIL_NOT_VERIFIED`. The registration hands out exactly the credential
  the gate exists to withhold. The family already carries that as a defect and
  not as a decision: it is tracked as
  [nik2208/awesome-go-auth#21](https://github.com/nik2208/awesome-go-auth/issues/21),
  and `awesome-lambda-auth`'s contract suite pins the current behaviour under
  protest in `test/contract/cases_register_test.go`, which calls it
  security-relevant and is written to fail the moment #21 lands. This entry
  follows that suite: when #21 lands, the behaviour changes and the entry is
  retired, not reworded. What has kept the issuance in place so far is only the
  first-run cost of the alternative — a registration that leaves the caller
  logged out makes the first thing a new account does re-present the password it
  typed one screen earlier, and issuing here removes that round trip. That
  argument covers the round trip and nothing else; it is not a reason to skip a
  verification gate the deployment asked for, and where the two conflict the
  gate is the stronger claim. The difference has stayed invisible this long
  because it costs the shipped clients nothing: `ng-awesome-node-auth` posts the
  registration `withCredentials` and reads only `userId` off the body, so the
  cookies simply land in the jar and its next session check succeeds instead of
  redirecting to the login form; the Flutter client reads `userId` (or `id`) and
  ignores every other field, so on native it discards the tokens and logs in
  exactly as it does today, and on web it inherits the same cookie jar. Neither
  reads a field this port omits, and neither has a branch that a present session
  breaks — but a client that does not notice is not a client that consented, and
  it is the gate, not the client, that #21 is about.
- **Matching the reference exactly**: Not possible today: there is no knob. The
  issuance is unconditional in the handler and no configuration field switches
  it off, which is part of why `nik2208/awesome-go-auth#21` is open rather than
  closed as configurable: a deployment running `EmailVerificationModeStrict`
  cannot opt out of the email verification bypass described above. The only way
  to get the reference's answer now is to not mount `POST <prefix>/register` —
  `HTTPConfig.ResourceServer` unmounts it along with the rest of the credential
  set — and create accounts through `UserStore` itself, verifying the address
  before the first login. Read "no knob" as the state of this release and not as
  a decision that it stays that way: the fix for #21 is expected to remove the
  issuance rather than add a switch.
<!-- END GENERATED: deviations -->

## Parity Snapshot vs `awesome-node-auth`

Status as of v0.3.1, verified against the code rather than the intent. ✅ means the
surface is mounted by all four adapters and covered by the wiretest conformance
suite; ⚠️ means the building blocks exist but a caller cannot get the reference's
behaviour without writing code; ❌ means absent. The milestone column names the
release that closes the gap.

| Capability | Status in `awesome-go-auth` | Notes | Closes in |
|------------|-----------------------------|-------|-----------|
| Auth strategies (email/password, magic link, SMS OTP, TOTP 2FA) | ✅ Implemented | Every route mounted on net/http, chi, gin and echo; delivery through `Config.Send*` senders. | — |
| Token management (cookie/bearer, access/refresh rotation, secure cookies) | ✅ Implemented | HS256 JWS, `X-Auth-Strategy: bearer`, rotation on refresh, `__Host-`/`__Secure-`/bare cookie policy. | — |
| Stateful sessions | ✅ Implemented | Revocation, rotation, `Config.SessionCheckOn` (`allcalls`/`refresh`/`none`). | — |
| CSRF protection | ✅ Implemented | `CSRFMiddleware`, double-submit cookie + header, exemption table pinned to the reference. | — |
| Account management | ✅ Implemented | Register, `UpdateProfile`, `DeleteAccount`, password and email lifecycle. | — |
| OAuth login + account linking | ✅ Implemented | Signed state, PKCE, single-use nonce; Google and GitHub presets, `AdditionalAuthParams` and declarative `ProfileMap`/`MapProfile` for generic providers; `OAuthProvisioning` replaces the reference's abstract `findOrCreateUser` (auto-create, domain allowlist, verified-address demand, `FieldMap`), and the account-conflict flow is complete — stash, the reference's `/account-conflict` redirect, then `/link-request` and `/link-verify`. | — |
| Dynamic email templates + UI i18n fallback | ✅ Implemented | The reference's six template ids with its en/it built-ins, `TemplateStore` overrides rendered under its `{{T.key}}`/`{{key}}` rule, per-request site-URL links and the old-address notice on `/change-email/confirm`. The `welcome` template renders but `POST /register` does not mail it yet (the reference does, `auth.router.ts:719-724`); UI translations are stored and are read by `GET /ui/config` once the UI router lands (v0.7.0 for the route, v0.9.0 for the pages). | — |
| Custom token claims | ✅ Implemented | `Config.BuildTokenClaims` hook, plus `StaticClaims`/`UserFieldClaims`/`ChainClaims` and the synchronous `ClaimsWebhook` (this port's extension); the hook runs at mint time and on `/me`, never in the middleware. | — |
| Identity Provider (IdP) mode (RS256 + JWKS + resource-server validation) | ⚠️ Partial | Discovery, authorize, token and userinfo endpoints exist; the signing key, `kid` and published keys are injectable (`IDPConfig.Signer`, `KeyID`, `PublicKeys`, with `ParseRSAPrivateKeyPEM` for the reference's PEM form), authorization codes go through `AuthCodeStore`, and `IssueIdPTokenPair` mints the reference's RS256 pair. Both halves of the JWKS contract are in: `auth.WithIDP` makes all four adapters serve the document at `<prefix>/.well-known/jwks.json` (`IDPConfig.JWKSPath`) with the reference's `Cache-Control` and CORS headers, with `<base>/jwks` kept as a deprecated alias through the 0.x line and removed in v1.0.0; and on the consuming side `JWKSClient` caches a remote JWKS with stale-while-revalidate, `VerifyRS256` verifies a bearer token against it (RS256 pinned before the key lookup, `kid` rotation retried once and rate-limited, `iss` checked), `ResourceServerMiddleware` is wired on all four adapters — bearer against the JWKS, cookie against the local HS256 secret, neither path reading a store — and `HTTPConfig.ResourceServer` unmounts the credential routes. What keeps this ⚠️: the OIDC endpoints themselves are mounted by `(*IDP).RegisterHandlers` on the host's own mux rather than by the four adapters, so they are outside the wiretest conformance suite; the adapters take them over in v0.7.0. | v0.7.0 |
| RBAC | ⚠️ Service-level | `RolesPermissionsStore` and service helpers; no HTTP surface (the admin router is absent). | v0.10.0 |
| Multi-tenancy | ⚠️ Service-level | `TenantStore` and membership helpers; no HTTP surface. | v0.10.0 |
| API keys (M2M) | ⚠️ Service-level | `APIKeyService` + `APIKeyMiddleware`; no management routes. | v0.10.0 |
| Admin panel | ❌ Absent | `ServeAdminUI()` serves a static page; none of the reference's admin routes exist, and no admin guard. | v0.10.0 |
| Built-in UI + auth runtime (`auth.js`) | ⚠️ Partial | `ServeAuthUI()`/`ServeAuthJS()` serve hand-written assets, not the reference's; no `GET /ui/config`, no branding. | v0.9.0 |
| OpenAPI / Swagger docs | ⚠️ Partial | `GenerateOpenAPISpec` returns the document; nothing serves it. | v0.7.0 |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify) | ⚠️ Primitives only | `EventBus`, `SseHub`, `WebhookDispatcher` and `TelemetryStore` exist, but the service publishes no events, there is no tools router, and the outbound webhook headers differ from the reference. | v0.11.0 |
| Client libraries compatibility (Angular + Flutter) | ✅ For the auth surface | Verified by [awesome-lambda-auth](https://github.com/nik2208/awesome-lambda-auth) with both official clients unmodified against a live stack. | — |
| Rate limiting | ✅ Slot implemented | The reference ships no algorithm — it declares a slot (`RouterOptions.rateLimiter`) and spreads it onto every auth route. `HTTPConfig.RateLimiter` is that slot: a `func(http.Handler) http.Handler` applied by all four adapters to every auth route, outside the CSRF and auth middlewares as the reference applies it, `nil` (the default) meaning none. The algorithm stays the integrator's middleware, as it is there. | — |
| MCP server (`awesome-node-auth-mcp-server`) | ➖ Out of scope | Out of parity scope for this library. | — |

### Roadmap

The gaps above close in order, one minor release per milestone. Shipped so far:
v0.4.0 email flows (site URLs, template store, delivery webhook), v0.5.0 2FA
knobs, token claims and the IdP signing key, v0.6.0 OAuth provisioning, the JWKS
route, RS256 verification and the settings store.

What is left, and where each row of the table above closes:

| Release | Closes |
|---|---|
| v0.7.0 | served OpenAPI and Swagger UI, `GET /ui/config`, a rate-limiter middleware slot, the OIDC endpoints mounted by the adapters, a password-verifier seam |
| v0.8.0 | the store seams the admin surface needs: user, session and role listers, a complete `APIKeyStore`, a `WebhookStore` |
| v0.9.0 | the reference's UI assets vendored byte for byte, with SSR and the page catch-all |
| v0.10.0 | the admin router, all fifty-one routes |
| v0.11.0 | the event plane, the reference's outbound-webhook wire format, the `SseManager` protocol and the tools router |
| v1.0.0 | removal of the shims those releases deprecate, and a final documentation truth pass |

v0.11.0 carries the breaking removals (`SseHub`, `WebhookDispatcher`, the
`X-Signature-SHA256` header, the old `TelemetryEvent` shape), which is why they
are gathered into one release rather than spread across three.
