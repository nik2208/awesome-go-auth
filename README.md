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

### `ui/config`: `features.verifyEmail` follows the effective verification mode

`ui-config-verify-email-follows-the-effective-mode`

- **Surface**: `GET <prefix>/ui/config`, the `features.verifyEmail` flag.
- **This port**: Answers `true` when `Config.SendEmailVerification` is wired
  *and* the effective `Config.EmailVerificationMode` is `lazy` or `strict`. An
  unset mode is `none` here as it is everywhere else in this port, and
  `DefaultConfig` writes `none` into the field outright, so a deployment that
  wired the sender and left the mode alone is told `false` and its login page
  offers no verify-email affordance.
- **The reference**: Asks
  `(sendVerificationEmail || mailer) && (emailVerificationMode !== 'none' || requireEmailVerification)`.
  An *unset* mode passes the second term, since `undefined !== 'none'` is true
  in JavaScript, so the same deployment is told `true` — even though the
  reference's own fallback makes an unset mode behave as `'none'` in every
  decision that acts on it. Its deprecated `requireEmailVerification` boolean is
  a third route to `true`, reaching it even with the mode set to `'none'`; this
  port has no field of that name (`ui.router.ts:121`,
  `auth-config.model.ts:286-298`).
- **Why**: The family's clients read `features` to decide which affordances to
  render, so a flag that differs is a difference a consumer sees: a node-auth
  deployment that wired a verification sender and never set the mode loses the
  verify-email affordance when it moves here. Reproducing the term costs more
  than it buys. It needs a distinction between an unset `EmailVerificationMode`
  and one set to `none` that nothing else in this port makes — the service
  normalises the empty string to `none` for registration, for login and for the
  2FA path — and `DefaultConfig` erases that distinction anyway, so the flag
  would answer differently for two configurations that behave identically on
  every route, according to which of the two the host happened to build. It
  would also advertise a step the deployment does not perform: with the
  effective mode `none`, `Register` marks the address verified on the spot and
  verification never comes up. Answering for what this deployment does is the
  reading closest to what the flag means.
- **Matching the reference exactly**: Set `Config.EmailVerificationMode` to
  `lazy` or `strict` — which is what a deployment that wires a verification
  sender generally means — and the flag answers `true`, as the reference does
  for the same deployment. There is no way to reach `true` with the mode at
  `none`, because the legacy boolean that reaches it there does not exist here.

### `POST <prefix>/register` is unconditional, and `ui/config` reports it as such

`register-route-is-always-mounted`

- **Surface**: `POST <prefix>/register`, and the `features.register` flag of
  `GET <prefix>/ui/config`.
- **This port**: Registration is part of the library rather than a hook the host
  supplies: every adapter mounts `POST <prefix>/register` on `Service.Register`
  on every deployment, and `GET <prefix>/ui/config` answers
  `features.register: true` to match. Resource-server mode is the one thing that
  unmounts the route, with the rest of the credential set — see
  `resource-server-gates-all-credential-routes` — and the flag does not follow
  it there, which is what the reference does too for a resource server that
  supplied the hook.
- **The reference**: Mounts `/register` only when `routerOptions.onRegister` is
  supplied, the host having written the account-creation function itself, and
  reports `!!routerOptions?.onRegister` in `features.register`. A deployment
  that supplies no hook answers `404` on the route and tells the UI to hide the
  sign-up affordance (`auth.router.ts:712-715`, `ui.router.ts:115`).
- **Why**: This port ships registration instead of asking for it:
  `Service.Register` applies the password policy, hashes the password, applies
  the email verification mode and writes through `UserStore`. There is no hook
  that can be absent, so there is nothing for the route's presence to be
  conditional on, and the flag — derived from the wiring rather than configured
  — answers for the routes this port actually serves. The difference runs one
  way only: a client is offered sign-up against a deployment whose node-auth
  counterpart, having no `onRegister`, would have hidden it.
- **Matching the reference exactly**: Not available from configuration. A host
  that wants no public sign-up mounts the adapter on its own mux and refuses
  `POST <prefix>/register` there, or runs in resource-server mode;
  `features.register` still answers `true` in the first case, so such a host
  hides the affordance in its own UI rather than reading the flag.

### The documentation routes are off until asked for, and the document describes them

`docs-routes-are-opt-in`

- **Surface**: `HTTPConfig.Docs.Enabled`: `GET <prefix>/openapi.json` and
  `GET <prefix>/docs`.
- **This port**: Registers neither route unless `HTTPConfig.Docs.Enabled` is
  set, so a deployment that configures nothing answers `404` for both. Set, the
  two answer what the reference answers, to a request carrying no credential of
  any kind: the generated document as `application/json`, and the reference's
  Swagger UI page reproduced byte for byte, `swagger-ui-dist@5` from the unpkg
  CDN included. Neither route has an auth gate, as neither has one there; both
  sit behind the CSRF middleware, as every reference route registered after the
  router-level auto-init does, which on a `GET` only writes the `csrf-token`
  cookie to a reader who arrives without one. The served document additionally
  describes those same two paths, which is what `OpenAPIInfo.Docs` adds; the
  reference's generator describes neither, under any option.
- **The reference**: Registers both when
  `swagger === true || (swagger !== false && NODE_ENV !== 'production')`. The
  option defaults to `'auto'`, which is the second arm, so a deployment that
  configures nothing serves them everywhere except where the process environment
  sets `NODE_ENV` to exactly `production`. Its generator emits the auth routes
  and stops, so neither `/openapi.json` nor `/docs` appears in the document it
  serves (`auth.router.ts:123-131`, `auth.router.ts:529-538`,
  `auth.router.ts:1652-1654`, `auth.router.ts:1656-1677`,
  `openapi.ts:1646-1669`).
- **Why**: What a library serves must follow from its own configuration, not
  from a process-wide variable it never sees set. `NODE_ENV` is a Node
  convention with no Go counterpart — there is no one variable a Go deployment
  agrees on, and picking one would make these routes appear and disappear on a
  value the caller never passed to this library. Reading the ambient environment
  is the host's call, and `Docs.Enabled` is where its answer goes, which is also
  the reference's own `swagger: true | false` for a host that wants to decide
  rather than infer. Defaulting to off rather than to on is the safe direction
  of that choice: an unserved document is a missing convenience, a served one is
  a description of the surface an attacker would otherwise have to guess — and
  `<prefix>/docs` is more than a description. The page is the reference's, so it
  loads `swagger-ui-dist@5` from the unpkg CDN with no subresource integrity,
  and whatever that CDN serves then runs on the auth origin, where the
  `csrf-token` cookie is readable from JavaScript by design. A deployment should
  keep the UI route off in production, or serve it behind a
  `Content-Security-Policy` that pins the CDN.
- **Restoring the reference's default**: One line where the `HTTPConfig` is
  built — `cfg.Docs.Enabled = os.Getenv("APP_ENV") != "production"` — with
  whatever variable the deployment actually uses. Nothing else changes: the
  routes, the bodies and the mount are the same either way.
- **Why the document lists itself**: The wire conformance suite compares the
  generated document to the mounted routes in both directions, on every adapter:
  a documented operation that answers `404` fails, and so does a mounted route
  the document omits. A document that hid the endpoint serving it would have to
  be exempted from the second half, and the exemption is what lets a spec drift.
  `OpenAPIInfo.Docs` is set with `HTTPConfig.Docs.Enabled` and describes exactly
  the two paths that flag mounts.

### The library raises `identity.*` events where the published reference raises none

`identity-events-are-raised-from-the-development-line`

- **Surface**: `auth.Config.Events` / `auth.WithEventBus`, and the nineteen
  routes that publish through it.
- **This port**: Nineteen publication points raise fifteen of the twenty-six
  declared `identity.*` names: login success and failure, logout, session
  rotation, registration, the two 2FA transitions, password change, email
  verification, email change, the magic-link and SMS logins, and the OAuth
  success and conflict. Each carries the payload and the `data` keys the
  development line builds there, and each goes through
  `EventBus.PublishContext`, so the correlation id, client address and user
  agent the request carried travel with it. A deployment that configures no bus
  — the default, and the common case — publishes nothing and allocates nothing.
- **The reference**: At this revision **nothing in the library publishes at
  all**. `AuthEventBus.publish` exists, is documented and is never called from
  the router; the twenty-six names are declared and none is raised. The single
  `.publish` outside the bus is `AuthTools.track`, which re-emits an event a
  *host* handed it rather than one the library observed. A host wiring
  `new AuthEventBus()` into `routerOptions.eventBus` at this revision receives
  nothing (`auth-event-bus.ts:55-64`, `auth-event-names.ts:5-40`,
  `auth-tools.ts:231`).
- **Why**: The publication points are not invented, they are ported: they exist
  in nik2208/node-auth, the private development line the published package is
  cut from, where `publishRouterEvent` is called nineteen times in the auth
  router, four times in the admin router and three times in the configurator —
  twenty-six in all. That is the behaviour the family's next release has, and
  the whole event plane this milestone builds (webhook delivery, the SSE stream,
  the telemetry store) subscribes to a bus that would otherwise never speak.
  Shipping the vocabulary without the publishers would mean every consumer
  downstream subscribing to silence. The alternative — waiting for the dev line
  to ship — would leave this port's `EventBus` as documented dead code it
  already was.
- **Which tree a citation means**: The citations on this entry are the published
  reference, as every entry in this register is. The publication points
  themselves are cited in the source as `node-auth <file>:<line>`, which
  resolves against `DevLineRevision`; a bare `<file>:<line>` is
  `ReferenceRevision`. A reviewer who greps the published tree for
  `publishRouterEvent` finds nothing, and that is the expected result rather
  than a missing port.
- **What is deliberately not published**: Eleven of the twenty-six declared
  names are raised by neither tree, and this port has the obvious call site for
  several — `identity.tenant.created` next to `Service.CreateTenant`,
  `identity.user.linked` next to the account-linking routes. None is raised. The
  seven remaining development-line points are in its admin router and its
  configurator, neither of which this port has yet; the admin router is M8's.
  `event_publication_test.go` pins all twenty-six, exercises the nineteen and
  names the surface and milestone for each of the seven.

### Refreshing rotates the token inside the session instead of opening a new one

`session-rotated-reports-one-session-id`

- **Surface**: `POST <prefix>/refresh`, and the `identity.session.rotated` event
  it raises.
- **This port**: The refresh token is rotated in place: the stored hash and
  expiry of the *existing* session row are rewritten, the session id is
  unchanged, and no row is revoked. The `sid` claim of the new token pair is
  therefore the same as the old one, `GET <prefix>/sessions` shows one row per
  login however often it refreshes, and on the `identity.session.rotated`
  payload `data.previousSessionId` is equal to the event's own `sessionId`.
- **The reference**: `issueTokens` creates a **new** session on every call and,
  when it was given the previous `sid` — which the refresh route passes —
  revokes the old one immediately after. So a refresh moves the session id, the
  session list grows a row per refresh and loses the revoked one, and the
  development line's `identity.session.rotated` carries two different ids: the
  new session in `sessionId` and the one just revoked in
  `data.previousSessionId` (`auth.router.ts:425-439`, `auth.router.ts:649`).
- **Why**: The difference predates the event by a long way — it is how this
  port's `Service.Refresh` has always worked — but until U18 nothing exposed it,
  and the event is what makes it a fact a consumer has to know rather than an
  internal choice. A subscriber that reads `previousSessionId` to stitch a
  session lineage together gets a self-edge here and a chain there, and it would
  have no way to find that out from the payload. Recording it was the
  alternative to changing rotation semantics inside a PR about publishing
  events: moving the session id on every refresh changes what
  `GET <prefix>/sessions` returns and invalidates every `sid` a host has stored,
  which is a wire change and belongs to its own PR with its own conformance run.
- **What still holds**: Both halves of what rotation is for are unaffected: the
  presented refresh token is single-use, because the stored hash is replaced by
  the new one, and a stolen token stops working the moment the legitimate client
  refreshes. `POST <prefix>/logout` revokes the session in both ports. Only the
  identity of the session across a refresh differs.
- **Reading the event safely**: Treat `data.previousSessionId` as "the session
  the presented refresh token belonged to", which is true in both ports, rather
  than as "a session that has just been revoked", which is true only in the
  reference. A subscriber keying a session-management view on `sessionId` needs
  no change.

### A panicking event handler is contained instead of failing the request that published

`event-handler-panic-does-not-fail-the-publisher`

- **Surface**: `auth.EventBus.Publish` and `PublishContext`, and therefore every
  route that will publish an `identity.*` event.
- **This port**: Each handler runs with `recover` around it. A handler that
  panics is logged and stepped over, the remaining handlers for that event still
  run, and `Publish` returns normally — so the route that published answers as
  though nothing had gone wrong.
- **The reference**: `AuthEventBus` extends Node's `EventEmitter` and publishes
  with two `emit` calls, which invoke their listeners inline. A listener that
  throws propagates out of `emit`, out of `publish`, and into whatever
  published: for the router that is the route handler's own `catch`, which
  passes the error to `handleError` and answers `500` for work that already
  succeeded. The listeners after the one that threw are never called, and the
  wildcard channel is never reached if the throw came from the named one
  (`auth-event-bus.ts:48`, `auth-event-bus.ts:55-64`).
- **Why**: The reference's behaviour here is a consequence of extending
  `EventEmitter` rather than a decision it took, and the Go form of it is worse
  than the Node form. A panic that is not recovered unwinds the goroutine
  `net/http` serves the request on; the server recovers it at the top, drops the
  connection and logs, so a bug in a telemetry subscriber becomes a failed
  request with no response body rather than a `500` with one. Nothing about the
  auth operation is undone either way — the account is created, the session is
  minted, the password is changed — so the choice is only between reporting a
  subscriber's bug as a failure of the operation and reporting it where it
  belongs. Containment also keeps one broken subscriber from silencing the
  others, which the reference's ordering makes a real hazard: an SSE handler
  registered after a webhook handler stops receiving events entirely the moment
  the webhook handler throws.
- **Observing it**: Subscribe two handlers to one name, panic in the first, and
  both the second handler and the caller of `Publish` proceed; the panic appears
  on the standard logger as
  `auth: recovered panic in event handler for "<name>"`. Under the reference the
  second listener is not called and the publishing request fails.
- **For a host that wants the failure**: A handler that must not fail silently
  should report its own errors — to its logger, its error tracker, its metrics —
  rather than panicking. There is no knob that restores the reference's
  propagation, because a bus whose delivery semantics depend on configuration is
  a bus no downstream consumer can reason about.

### A slow SSE consumer is disconnected instead of being buffered without limit

`sse-slow-consumer-is-disconnected`

- **Surface**: `auth.SseManager.Serve` — every `text/event-stream` this port
  writes.
- **This port**: Each connection has a bounded queue of pending frames,
  `WithSseSendBuffer` frames deep and 64 by default. `Broadcast` never blocks
  and never waits on a reader: a frame that does not fit means the connection is
  closed, its registration removed and the handler returned, so the stream ends.
  A single write is bounded the same way, by a ten second deadline set through
  `http.ResponseController`, and a write that misses it ends the stream too. A
  browser's `EventSource` reconnects on its own afterwards.
- **The reference**: `SseManager` writes straight to the Express `Response` and
  ignores the `false` that `res.write` returns when the socket buffer is full —
  the backpressure signal Node offers. The unwritten frames sit in the stream's
  internal queue, which has no bound, so a consumer that stops reading costs the
  server memory until the socket is torn down by the client or the OS. Nothing
  disconnects it, and nothing tells the publisher, because `broadcast` returns
  `void` (`sse-manager.ts:204-221`, `sse-manager.ts:249-253`).
- **Why**: There is no portable way to reproduce it. Node's answer comes from
  stream backpressure, where an ignored `false` degrades into memory growth and
  nothing else; Go's equivalent is a channel, and the three things a full one
  can do are block the publisher, drop the frame, or end the connection.
  Blocking is not available: `EventBus.Publish` is synchronous and runs on the
  goroutine serving an HTTP request, so one client that stopped reading would
  stall every login in the process. Dropping is available and is the worse of
  the two remaining, because it is silent — neither implementation replays, so a
  dropped frame is not recoverable by any client, and a client that is never
  told has no way to know its view is now wrong. Ending the connection makes the
  same gap visible at the one moment a client can act on it. The bound is also
  what keeps one misbehaving reader from being a memory-exhaustion vector
  against the auth process, which on the reference is the operator's problem and
  here is not.
- **Observing it**: Open a stream, stop reading from the socket, and broadcast
  more than `WithSseSendBuffer` frames to a topic it holds: the response ends
  and `ConnectionCount` drops. Under the reference the stream stays open and the
  frames accumulate in the server's memory.
- **What a reconnecting client gets**: Nothing it missed. Neither implementation
  reads the `Last-Event-ID` header a browser sends when its `EventSource`
  reconnects, neither retains a delivered event, and the per-connection last
  event id is only ever compared against the next event's — so a reconnect
  resumes from *now*. Whatever was raised while the client was away is gone in
  both, and the difference this entry records is only how the gap happens:
  abruptly and observably here, silently and without bound there.
- **For a host that wants the frames kept**: Raise `WithSseSendBuffer` to the
  burst the slowest client must survive; it trades memory for tolerance, one
  queue per connection. There is no unbounded setting, and there deliberately is
  not: an unbounded queue on a Go server is the memory-exhaustion vector above
  with a configuration flag in front of it. Delivery that has to survive a
  disconnect needs an event log the client can replay from, which is a guarantee
  neither this port nor the reference offers.

### The SSR-injected `__AUTH_CONFIG__` is HTML-escaped JSON, and cannot be broken out of

`ui-ssr-config-json-is-html-escaped`

- **Surface**: `GET <prefix>/ui/<page>`, the
  `<script>window.__AUTH_CONFIG__ = …</script>` block.
- **This port**: Serialises the config object with `encoding/json` at its
  default settings, which escape `<`, `>` and `&` as `\u003c`, `\u003e` and
  `\u0026`. Any `</script>` inside `siteName`, `logoUrl` or `customCss`
  therefore reaches the browser as `\u003c/script\u003e`: it stays inside the
  string, the script block ends where the server put its `</script>`, and the
  value `JSON.parse` yields is character for character the one that was
  configured. The bytes on the wire differ from the reference's whenever any
  string in the document contains one of those three characters — a `customCss`
  with a child selector is enough.
- **The reference**: Writes `JSON.stringify(config)` straight into the
  `<script>` block. `JSON.stringify` escapes nothing for HTML, and a `<script>`
  element is terminated by the byte sequence `</script>` wherever it appears,
  quoted or not — so a `siteName` of `x</script><img src=x onerror=…>` closes
  the block and the rest is parsed as markup and runs. The same page
  HTML-escapes that identical `siteName` five characters at a time before
  putting it in `<title>` and `<h1 class="site-name">`, so the omission is in
  one sink rather than a decision about the value (`ui.router.ts:272`,
  `ui.router.ts:217-226`).
- **Why**: Reproducing the reference including its quirks is the standing rule
  here, and this is the register that exists for the cases where it is set
  aside. It is set aside because the cost and the benefit are as lopsided as
  they get. What reproducing it buys is byte-identical output for configurations
  containing `<`, `>` or `&`; what it costs is an HTML injection into every page
  this port serves, reachable by whoever can set the branding. No client can
  observe the difference: `\u003c` and `<` are the same character to
  `JSON.parse`, so `window.__AUTH_CONFIG__` is the identical object either way,
  and the escaping is visible only to something reading the raw bytes of the
  HTML — which is not what the family's clients do with this block. Turning the
  escaping off would have taken an explicit `Encoder.SetEscapeHTML(false)`, so
  keeping it is also the reading where the unsafe behaviour is the one that has
  to be asked for. The direction of the difference matters too: this is the only
  entry in this register where the port is *stricter* than the reference, and a
  deployment cannot be broken by a hole being closed.
- **Matching the reference exactly**: Not available from configuration, and
  deliberately so. A host that needs the exact bytes serves its own page:
  `UIOptions.Assets` takes any `fs.FS`, and `(*Auth).UIConfig` returns the same
  document to marshal however it likes.
- **The two sinks this does not close**: `customCss` is written into a second
  `<style>` element unescaped and `logoUrl` into an `<img src="…">` attribute
  unescaped, both exactly as the reference writes them, because there escaping
  would change what renders rather than only how it is encoded.
  `UIOptions.CustomCSS` is read from the static configuration alone and is
  therefore the host's own code; `logoUrl` can also come from a `SettingsStore`,
  whose only writer in this release is the host's own code, since the admin
  panel that would let an operator write one arrives in M8. A deployment that
  lets a lower-privileged actor write either value is trusting that actor with
  the auth origin.

### An admin console with no access policy is not served at all

`admin-console-requires-an-explicit-policy`

- **Surface**: `HTTPConfig.Admin`: the whole admin surface under `Admin.Path`,
  `/admin` by default.
- **This port**: Mounts nothing unless `HTTPConfig.AdminMounted()` —
  `Admin.Enabled` set *and* one of `Admin.AccessPolicy` or `Admin.Secret`
  configured. With the flag on and neither of those, no route under `Admin.Path`
  is registered and the console answers `404` everywhere, on all four adapters.
  The reference's own default is one call away and keeps its own name:
  `AccessPolicy: auth.AdminOpen()` serves every route to every caller, which is
  what `'open'` means there.
- **The reference**: Builds the router regardless. The selection is
  `accessPolicy`, then `adminSecret`, then neither — and the third arm writes
  the line "[awesome-node-auth] WARNING: createAdminRouter called without
  `accessPolicy` or `adminSecret`. Admin routes are unprotected. Set
  accessPolicy in production." to `process.stderr`, and installs a guard that
  calls `next()` for every request. The console, including every route that
  reads or writes the user table, is then served to anyone who can reach the
  port (`admin.router.ts:511-537`, `admin.router.ts:531-536`).
- **Why**: Reproducing the reference including its quirks is the standing rule,
  and it is set aside here because the quirk is an open administrative console
  and because — uniquely in this register — reproducing it costs a deployment
  nothing to move away from. `HTTPConfig.Admin` is new in this release, so there
  is no existing Go deployment whose configuration this can break: no host has
  ever set these fields, and the first host to set them reads the field doc
  while doing it. That is not true of the reference, whose `createAdminRouter`
  has shipped with this default since 1.8.0 and cannot withdraw it without
  breaking callers. The second half of the reasoning is that `process.stderr`
  has no counterpart here. This package writes diagnostics through
  `Config.Logger`, which defaults to nil and discards them, so a faithful port
  of the warning would be a line nobody sees in front of a door nobody closed.
  Refusing to mount is the same statement made where it cannot be missed, and
  `AdminMounted()` is exported so a host can turn the refusal into its own
  startup error in one line:
  `if cfg.Admin.Enabled && !cfg.AdminMounted() { log.Fatal("admin: no access policy") }`.
  Choosing `AdminOpen()` explicitly also puts the decision in the deployment's
  own configuration, where a reviewer reading the host's source can see it,
  instead of in the absence of a field.

### The unauthenticated browser branch of the admin guard reaches the shell and nothing else

`admin-unauthenticated-get-serves-only-the-login-form`

- **Surface**: `HTTPConfig.Admin`: every route behind `AdminGuard.Protect`, and
  `GET <admin>/`.
- **This port**: Honours the `adminNeedsAuth` marker on exactly one route: the
  HTML shell, which is the only thing that can render the built-in login form.
  Every other guarded route answers `401 {"error":"Unauthorized"}` to an
  unauthenticated request whatever its `Accept` header says. The shell rendered
  through that branch additionally carries no feature flags:
  `window.__ADMIN_CONFIG__` reports every `feat*` member as `false` and an empty
  `uploadBaseUrl`, so the page discloses the mount path and the login form and
  nothing about the deployment. The vendored `admin.js` reloads the page after a
  successful login, so it has the real flags before it draws a tab.
- **The reference**: Sets `(req as any).adminNeedsAuth = true` and calls
  `next()` for **any** guarded `GET` whose `Accept` contains `text/html`, when
  no `loginPath` is configured. The marker is advisory: no handler behind the
  guard reads it except the shell, so `GET /admin/api/ping` and — as the rest of
  the admin API lands behind the same guard — `GET /admin/api/users` answer
  normally to a request carrying no credential at all.
  `curl -H 'Accept: text/html' …/admin/api/users` is the whole exploit. The
  shell it serves through the same branch carries the full feature object
  regardless (`admin.router.ts:309-325`, `admin.router.ts:709`,
  `admin.router.ts:741-743`, `admin.router.ts:748`).
- **Why**: The branch exists so a browser arriving without a session sees a
  login form rather than a JSON `401`, and that purpose is served entirely by
  the one route that renders the form. Extending it to every `GET` is not a
  decision the reference makes anywhere in prose — the comment at the marker
  says "so the UI router can show the built-in login form" — it is the
  consequence of putting the marker on the request instead of on the route.
  Reproducing it would mean shipping a library whose admin API is readable by
  anyone who sets a request header, which is not a quirk a client can depend on
  but a hole a deployment can be breached through, and M8's remaining PRs all
  mount behind this same guard. Emptying the feature flags on that render is the
  same argument applied to the one thing the shell would otherwise disclose: the
  flag object is the body of `GET <admin>/api/ping`, a route that requires a
  session, so serving it beside the login form would hand out through the door
  what the lock next to it refuses. No client notices, because the SPA reloads
  after login. Under `Admin.Secret` the shell is unguarded by design and still
  carries the full object, exactly as there — this narrowing is the marker
  branch only.

### The admin guard accepts an admin token or an access token, and `isRoot` only on the first

`admin-guard-accepts-only-typed-session-tokens`

- **Surface**: `HTTPConfig.Admin`: the `Authorization: Bearer` and cookie
  credential every guarded admin route reads.
- **This port**: Verifies HS256 over `Admin.JWTSecret` and then checks three
  claims the reference does not: `typ`, `iss` and — for the store lookup —
  `tid`. Two types are accepted. `typ: "admin"` is the token
  `POST <admin>/login` mints and the only one on which the `isRoot` claim is
  honoured; `typ: "access"` is an ordinary session token, which is the
  integration the reference documents when it says `jwtSecret` must match
  `AuthConfig.accessTokenSecret`, and on which `isRoot` is ignored outright.
  Everything else is not a credential: a refresh token, and the typed step-up
  token a user holds after a password and before a second factor, are both
  `401`.
- **The reference**: Signs `{sub, email, isRoot}` with `expiresIn: '24h'` and
  verifies with a bare `jwt.verify(rawToken, jwtSecret)`. Nothing distinguishes
  one token from another, so every token that secret signs is an admin
  credential. The 2FA step-up token always is: it is
  `generateTokenPair(...).accessToken` with a five-minute expiry and no marking
  claim (auth.router.ts:563-566, :572-575), signed with
  `config.accessTokenSecret`, which is the secret `jwtSecret` is documented as
  having to match. So a user who has proved a password and not the second factor
  the deployment requires can present that token to the console and be judged by
  the access policy as though the second factor had been given. The refresh
  token is signed with `config.refreshTokenSecret` there
  (token.service.ts:25-29) and is therefore a second admin credential only in a
  deployment that sets both secrets to one value — where it is one for seven
  days rather than five minutes. This port has a single Config.Secret, so
  refusing it here is not hypothetical. A payload carrying `isRoot: true`
  short-circuits the user-store lookup and the policy together, whatever minted
  it (`admin.router.ts:76-79`, `admin.router.ts:300`, `admin.router.ts:343-352`,
  `admin.router.ts:585`).
- **Why**: This port already types its tokens and already refuses an untyped
  one: `typ` is a reserved claim `issueToken` writes after the
  `Config.BuildTokenClaims` merge precisely so that a hook cannot turn a step-up
  token into a session, which is the `temp-token-is-typed-not-an-access-token`
  deviation. A guard that verified a signature and stopped would be the one door
  in the building that reopened it, and it would reopen it on the console. The
  `iss` check is the same argument: `parseToken` refuses a token from another
  issuer on every other route, and the admin surface is not the place to start
  accepting one. Confining `isRoot` to the admin token is what makes the
  reference's bootstrap override safe to reproduce at all. A claim that bypasses
  the user store must have exactly one minter, and `POST <admin>/login` is it;
  without the type check the claim could also arrive on an access token, where
  `Config.BuildTokenClaims` is a host hook free to return any name the reserved
  set does not cover — so a mapping written for some unrelated purpose could
  grant the console. What it costs: a host that mints admin tokens with some
  third-party signer has to add `typ`, `iss` and an `exp`. The documented
  integration — the auth router's own login — is unaffected, because its tokens
  already carry all three.

### The admin session cookie's `Secure` flag and name come from the configuration, never from a request header

`admin-cookie-secure-flag-is-configured-not-forwarded`

- **Surface**: `POST <admin>/login` and `POST <admin>/logout`: the `Set-Cookie`
  they write.
- **This port**: Derives both the `Secure` attribute and the `__Host-` /
  `__Secure-` prefix from `CookieOptions.Secure`, `CookieOptions.Path` and
  `CookieOptions.Domain` — `CookieOptions.CookieName`, the same function the
  auth routes name their own cookies with, whose `Secure` defaults to `true`
  here. `X-Forwarded-Proto` is read nowhere and changes nothing.
  `AdminOptions.CookiePrefix` still overrides the prefix outright, as there, and
  the `__Host-` requirements (`Secure`, `Path=/`, no `Domain`) are reapplied
  after it. The guard's read order is unchanged: `__Host-accessToken`,
  `__Secure-accessToken`, `accessToken`.
- **The reference**: Computes `isSecure` per request as
  `req.secure || req.headers['x-forwarded-proto'] === 'https'` and feeds it to
  `resolveAdminCookieName`, so a request header decides both whether the cookie
  carrying a 24-hour admin session is marked `Secure` and which of the three
  names it is written under. The failure is bidirectional: a spoofed `https`
  over plaintext writes a `Secure`, possibly `__Host-` cookie the browser then
  drops, and a genuine TLS deployment whose proxy does not set the header writes
  a bare, non-`Secure` `accessToken` holding that same session
  (`admin.router.ts:218-231`, `admin.router.ts:243-252`, `admin.router.ts:591`,
  `admin.router.ts:601-611`, `admin.router.ts:619`).
- **Why**: `HTTPConfig.ClientIP` settled this class of question a release ago
  and in this direction: a forwarded header is only as trustworthy as the trust
  configuration behind it, that configuration is the host's knowledge, and this
  package ships no parser that would pretend otherwise. Here the seam the host
  needs already exists and is already being read three cookies over —
  `CookieOptions.Secure` is the operator's statement about the deployment — so
  honouring the header would mean letting a caller contradict the operator about
  one cookie and not the other three. It also removes a way for the login route
  and the guard to disagree: the reference's own `resolveAdminCookieName`
  comment says it exists so that "the guard reads exactly the cookie that was
  written by the admin login handler", which holds only while every request
  agrees about `isSecure`, and a proxy that sets the header on some paths and
  not others breaks it. The direction of the difference is the safe one in the
  case that matters: where the reference would emit a non-`Secure` admin session
  cookie, this port emits a `Secure` one.
- **Matching the reference exactly**: Not available from configuration,
  deliberately. A deployment terminating TLS at a proxy sets `Cookies.Secure` —
  its default — and gets the right answer on every request without a header; one
  genuinely serving plain HTTP sets it to false and says so once, in its own
  source, instead of per request from outside.

### The admin listings answer in a defined order, where the reference's own stores impose none

`admin-listings-are-ordered-by-id`

- **Surface**: `HTTPConfig.Admin`: the paged and listing reads —
  `GET <admin>/api/users`, `/api/sessions`, `/api/roles`, `/api/tenants`,
  `/api/users/{id}/roles`, `/api/users/{id}/tenants` and
  `/api/tenants/{id}/users`.
- **This port**: Answers in a total order, and states it as part of the store
  contract rather than as an implementation detail: **ID ascending, by Go string
  comparison**. `AdminUserStore.ListUsers` orders by `User.ID`,
  `SessionLister.GetAllSessions` by `Session.ID`, `RoleLister.GetAllRoles` and
  `RolesPermissionsStore.GetRolesForUser` by the role name, and the tenant
  listings by the tenant or user id — which is what every other list method in
  this package already did. A store that cannot answer in that order may answer
  in its own, but owes its callers the same kind of entry this one is. The two
  listings that are *not* covered stay as the reference has them:
  `GET <admin>/api/templates/mail` and `/api/templates/ui` come back in
  first-insertion order, matching its `Map` iteration, and a user's linked
  accounts in the order they were linked.
- **The reference**: Declares no order anywhere, and none of its shipped stores
  supplies one. `listUsers` is `SELECT * FROM users LIMIT ? OFFSET ?` with no
  `ORDER BY` in the SQLite and MySQL examples, `find({}).skip().limit()` in
  natural order in the MongoDB one, and a `Map`'s insertion order in the
  in-memory one. So the console's own paging is undefined against its own
  examples: a row can appear on two consecutive pages or on neither, and nothing
  in the router notices, because `total` is the best-effort expression at `:782`
  rather than a count. Its `'first-user'` access policy reads
  `listUsers(1, 0)[0]` and calls that user "the first registered user"
  (`:25-27`), which under a `SELECT` with no `ORDER BY` is whichever row the
  engine happened to return (`admin.router.ts:748`, `admin.router.ts:782`,
  `admin.router.ts:1086`, `admin.router.ts:1129`,
  `sqlite-user-store.example.ts:305`, `mysql-user-store.example.ts:356`,
  `mongodb-user-store.example.ts:327`, `in-memory-user-store.ts:175`).
- **Why**: `offset` without an order is not paging. The reference's route
  signature is positional — limit and offset, page after page — and a positional
  cursor over an unordered set is a different set each time it is asked, so an
  operator walking the users table can be shown one account twice and another
  not at all, with nothing on the wire to say so. Reproducing the absence would
  mean reproducing a defect that only manifests as missing rows, which is the
  one class of wire difference a client cannot detect and a reviewer cannot see.
  The second reason is that the guard already depends on the order:
  `AdminPolicyFirstUser` grants the console to `ListUsers(ctx, "", 1, 0)[0]`, so
  under an unordered store the answer to "who may administer this deployment" is
  whatever the query planner felt like — and it can differ between two requests.
  An access decision cannot rest on that. Nothing is given up by fixing it. No
  shipped client reads these routes — they are the admin SPA's, and the SPA
  renders whatever order it is sent — and an order is strictly more information
  than no order, so a consumer written against the reference cannot break on
  receiving one. The cost falls entirely on a store implementor, which is why it
  is stated on the three interfaces rather than only here.

### A tools router with no stated access posture is not served at all

`tools-router-requires-an-explicit-guard-decision`

- **Surface**: `HTTPConfig.Tools`: the whole tools surface under `Tools.Path`,
  `/tools` by default.
- **This port**: Mounts nothing unless `HTTPConfig.ToolsMounted()` —
  `Tools.Enabled` set, a `Tools.AuthTools` facade supplied *and* `Tools.Access`
  configured. With the flag on and no access decision, no route under
  `Tools.Path` is registered and every tools path answers `404`, on all four
  adapters, the two unguarded documentation routes included. The reference's own
  default is one named call away: `Access: auth.ToolsPublic()` serves every
  route to every caller, which is what an empty `protect` list means there.
  `auth.ToolsProtected(mw)` is the other posture, and it answers nil — so
  nothing mounts — for a nil `mw`, because a configuration that degrades from
  guarded to open when a variable was left unassigned is the failure this entry
  is about.
- **The reference**: Builds the router regardless. The guard slot is
  `const protect: RequestHandler[] = authMiddleware ? [authMiddleware] : []`,
  and nothing at all is said when it is left empty — unlike `createAdminRouter`,
  which at least writes a line to `process.stderr`. All four feature flags
  default to `true`, so the router a host gets by forgetting `authMiddleware` is
  not a stub: `POST /track/:eventName`, `POST /notify/:target` and `GET /stream`
  answer anyone who can reach the port, and so does `GET /telemetry` wherever a
  telemetry store is configured (`tools.router.ts:117-135`,
  `tools.router.ts:121-124`, `tools.router.ts:135`, `tools.router.ts:140-245`,
  `admin.router.ts:531-536`).
- **Why**: The two grounds that decided
  `admin-console-requires-an-explicit-policy` both hold here, and the second
  holds with more force. `HTTPConfig.Tools` is new in this release, so no
  existing Go deployment's configuration can be broken by refusing: no host has
  ever set these fields, and the first to set them reads the field doc while
  doing it. And the reference's signal cannot be ported because there is none —
  this package writes diagnostics through `Config.Logger`, which defaults to nil
  and discards them, and here the reference does not even print the warning its
  admin router prints. What is different is the surface, and it is priced rather
  than assumed. `track` and `notify` do not read the user table; they write
  telemetry and send messages, and that door costs more rather than less.
  `POST /track/:eventName` takes `userId`, `tenantId` and `sessionId` from the
  request body and only falls back to the authenticated principal, so an
  anonymous caller forges telemetry attributed to any user — and `Track` fans
  that forgery out to all four sinks: it is persisted, it is published on the
  event bus where the host's own subscribers act on it, it is broadcast to the
  SSE connections holding `user:<id>`, and it fires every matching outgoing
  webhook, which is the deployment POSTing attacker-chosen content to a third
  party in its own name and under its own signature. `POST /notify/:target`
  sends on the `sse`, `email` and `sms` channels, so with a mailer and an SMS
  transport configured an anonymous caller makes the deployment send a named
  user mail and SMS — which costs money and sender reputation, neither
  refundable. And `GET /stream` with no principal still resolves to the topic
  `global`, which carries every tracked event as a whole telemetry record, user
  id, session id, IP and user agent included. Requiring the host to name the
  posture is the same statement made where it cannot be missed, and
  `ToolsMounted()` is exported so a host can turn the refusal into its own
  startup error in one line:
  `if cfg.Tools.Enabled && !cfg.ToolsMounted() { log.Fatal("tools: no access decision") }`.
- **Restoring the reference's default**: One field where the `HTTPConfig` is
  built — `cfg.Tools.Access = auth.ToolsPublic()` — and the router is served
  exactly as `createToolsRouter(tools, {})` serves it. Nothing else changes: the
  routes, the bodies, the mount and the four feature flags are the same either
  way. The name is the point: a reviewer reading the host's own source sees the
  posture, instead of having to notice a field that is not there.
- **What the guard does and does not cover**: `Tools.Access` is spread onto the
  routes the reference spreads `...protect` onto: `track`, `notify`, `stream`
  and the telemetry query. Two route groups never see it, there or here. The
  inbound webhook is registered with no guard at all, because the caller is a
  third-party provider with no session to present, and the two documentation
  routes carry none either — so `GET <tools>/docs` and
  `GET <tools>/openapi.json` are readable by anyone who can reach the mount even
  when everything else is guarded. Keep `Tools.Docs.Enabled` off in production
  for the reason `docs-routes-are-opt-in` gives.
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
| Dynamic email templates + UI i18n fallback | ✅ Implemented | The reference's six template ids with its en/it built-ins, `TemplateStore` overrides rendered under its `{{T.key}}`/`{{key}}` rule, per-request site-URL links and the old-address notice on `/change-email/confirm`. The `welcome` template renders but `POST /register` does not mail it yet (the reference does, `auth.router.ts:719-724`); UI translations are stored and are read by `GET <prefix>/ui/config`, which serves the `config` page for the requested language with the reference's `en` fallback. | — |
| Custom token claims | ✅ Implemented | `Config.BuildTokenClaims` hook, plus `StaticClaims`/`UserFieldClaims`/`ChainClaims` and the synchronous `ClaimsWebhook` (this port's extension); the hook runs at mint time and on `/me`, never in the middleware. | — |
| Identity Provider (IdP) mode (RS256 + JWKS + resource-server validation) | ✅ Implemented | **Not yet an enforcing authorization server: PKCE parameters are recorded with the authorization code and never checked at the token endpoint, and which token pair `token` returns is an open design decision (upstream plan D-15).** The reference ships no OIDC authorization server, so those four endpoints are this port's own surface rather than a parity item; what the ✅ claims is the row's legend — mounted on all four adapters and covered by the wire conformance suite. Discovery, authorize, token and userinfo are mounted by all four adapters; the signing key, `kid` and published keys are injectable (`IDPConfig.Signer`, `KeyID`, `PublicKeys`, with `ParseRSAPrivateKeyPEM` for the reference's PEM form), authorization codes go through `AuthCodeStore`, and `IssueIdPTokenPair` mints the reference's RS256 pair. Both halves of the JWKS contract are in: `auth.WithIDP` makes all four adapters serve the document at `<prefix>/.well-known/jwks.json` (`IDPConfig.JWKSPath`) with the reference's `Cache-Control` and CORS headers, with `<base>/jwks` kept as a deprecated alias through the 0.x line and removed in v1.0.0; and on the consuming side `JWKSClient` caches a remote JWKS with stale-while-revalidate, `VerifyRS256` verifies a bearer token against it (RS256 pinned before the key lookup, `kid` rotation retried once and rate-limited, `iss` checked), `ResourceServerMiddleware` is wired on all four adapters — bearer against the JWKS, cookie against the local HS256 secret, neither path reading a store — and `HTTPConfig.ResourceServer` unmounts the credential routes. The four OIDC endpoints are mounted from that same `auth.WithIDP` switch at `<prefix>/.well-known/openid-configuration`, `<prefix>/authorize`, `<prefix>/token` and `<prefix>/userinfo`, every method reaching the handler as `(*IDP).RegisterHandlers` has always mounted them, and the wiretest suite covers all four on all four adapters; `HTTPConfig.ResourceServer` unmounts `<prefix>/authorize` and `<prefix>/token` along with the other credential routes and leaves discovery, userinfo and the JWKS document public. `RegisterHandlers` stays for a host that would rather serve them on a mux of its own; doing both at once puts the same endpoints at two URLs, and on a single `http.ServeMux` that is a mount-time panic rather than a split endpoint — on a chi, gin or echo host the adapter and the `RegisterHandlers` mux are different routers, so there is no panic and the endpoints simply end up served twice. | — |
| RBAC | ⚠️ Service-level | `RolesPermissionsStore` and service helpers; no HTTP surface (the admin router is absent). | v0.10.0 |
| Multi-tenancy | ⚠️ Service-level | `TenantStore` and membership helpers; no HTTP surface. | v0.10.0 |
| API keys (M2M) | ⚠️ Service-level | `APIKeyService` + `APIKeyMiddleware`; no management routes. | v0.10.0 |
| Admin panel | ❌ Absent | `ServeAdminUI()` serves a static page; none of the reference's admin routes exist, and no admin guard. | v0.10.0 |
| Built-in UI + auth runtime (`auth.js`) | ⚠️ Partial | The reference's fourteen `src/ui/assets` files are vendored byte for byte at `cc01e997` under `ui/upstream/assets`, embedded, and pinned by a sha256 table that `go test ./...` re-hashes; `ServeAuthJS()` serves the vendored `auth.js` and is deprecated for removal in v1.0.0. `ServeAuthUI()` still serves a hand-written page. `GET <prefix>/ui/config` is mounted on all four adapters under `HTTPConfig.UI.Enabled` and serves the reference's document — feature flags derived from the wiring, branding from `UIOptions.Branding` with the `SettingsStore` on top, translations from the template store's `config` page, the echoed `headless` flag and the reduced store-failure fallback. What keeps this ⚠️: the vendored HTML pages, the static assets and the uploaded logos are not served yet — vendoring them and serving them are deliberately separate changes. | v0.9.0 |
| OpenAPI / Swagger docs | ✅ Implemented | `HTTPConfig.Docs.Enabled` makes all four adapters serve `GET <prefix>/openapi.json` and `GET <prefix>/docs`, with no auth guard of their own as the reference registers them and behind the CSRF middleware as its router-level auto-init puts every route registered after it — which on a `GET` only hands the `csrf-token` cookie to a reader who arrives without one; the page is the reference's, `swagger-ui-dist@5` from the unpkg CDN and all, and `DocsOptions.BasePath` is its `swaggerBasePath` — it moves the description, never the mount. Off by default, where the reference's `'auto'` reads `NODE_ENV`: that call is the host's here (`docs-routes-are-opt-in`). | — |
| Event-driven tooling (event bus, SSE, inbound/outbound webhooks, telemetry, notify) | ⚠️ Partial | The service publishes the `identity.*` vocabulary through `EventBus`, and outgoing webhooks are the reference's own wire: `WebhookSender` sends the four `X-Webhook-*` headers and the `OutgoingWebhookEvent` body with its retry policy, `WebhookStore` holds the subscriptions, and `WebhookDeliverer` is the seam a deployment replaces to deliver off-process. What is left: the `SseManager` protocol, the `AuthTools` facade that orders telemetry, bus, SSE and webhooks together, the tools router, and inbound webhook scripts (which run out of process, behind a seam, by design). | v0.11.0 |
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
