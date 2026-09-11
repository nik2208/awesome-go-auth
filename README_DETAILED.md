# awesome-go-auth — Detailed API Reference

Complete reference for every public type, interface, function, and option in the library.

---

## Table of Contents

1. [Core Service](#core-service)
2. [Configuration](#configuration)
3. [Runtime settings](#runtime-settings)
4. [Models](#models)
5. [Store Interfaces](#store-interfaces)
6. [In-Memory Stores](#in-memory-stores)
7. [Auth Functional Options](#auth-functional-options)
8. [Custom Claims](#custom-claims)
9. [OAuth 2.0 + Account Linking](#oauth-20--account-linking)
10. [SSE (Server-Sent Events)](#sse-server-sent-events)
11. [Webhooks](#webhooks)
12. [Telemetry](#telemetry)
13. [Mailer](#mailer)
14. [Delivery](#delivery)
15. [OIDC IDP](#oidc-idp)
16. [MCP Server (out of parity scope)](#mcp-server-out-of-parity-scope)
17. [OpenAPI](#openapi)
18. [Embedded UI](#embedded-ui)
19. [API Keys](#api-keys)
20. [Event Bus](#event-bus)
21. [HTTP Adapters](#http-adapters)
22. [Security Helpers](#security-helpers)
23. [Errors](#errors)

---

## Core Service

### `New(opts ...Option) (*Auth, error)`

Creates a fully configured `Auth` instance using functional options. Falls back to in-memory stores if none are provided.

```go
a, err := auth.New(
    auth.WithSecret("32-byte-secret"),
    auth.WithIssuer("https://api.example.com"),
    auth.WithTokenTTLs(15*time.Minute, 7*24*time.Hour),
)
```

### `NewWithConfig(cfg Config, opts ...Option) (*Auth, error)`

Same as `New`, but starting from a `Config` you populate yourself; any options are
applied on top. Use it to reach `Config` fields that have no `With*` option — the
individual TTLs, `EmailVerificationMode`, `BcryptCost`. `cfg` is validated exactly
as `New`'s is, so a partially filled struct is rejected rather than silently
defaulted.

```go
cfg := auth.DefaultConfig("32-byte-secret")
cfg.BcryptCost = 12
cfg.EmailVerificationMode = auth.EmailVerificationModeStrict
a, err := auth.NewWithConfig(cfg, auth.WithUserStore(myStore))
```

### `(*Auth).Service() *Service`

Returns the underlying `*Service` for direct method calls.

### `NewService(cfg Config, users UserStore, sessions SessionStore, opts ...ServiceOption) (*Service, error)`

Low-level constructor. Use `New()` for most cases.

### Service Methods

| Method | Description |
|--------|-------------|
| `Register(ctx, RegisterInput) (User, AuthTokens, error)` | Create a user and return tokens |
| `Login(ctx, LoginInput) (User, AuthTokens, error)` | Authenticate and return tokens |
| `Refresh(ctx, refreshToken) (AuthTokens, error)` | Rotate refresh token |
| `Logout(ctx, refreshToken) error` | Revoke session |
| `Authenticate(ctx, accessToken) (User, error)` | Verify an access token and load its user with the stores' enrichment; never runs `BuildTokenClaims` — see [Custom Claims](#custom-claims) |
| `Me(ctx, accessToken) (User, error)` | `Authenticate` plus `CustomClaims` from `BuildTokenClaims`: the `/me` profile |
| `UpdateProfile(ctx, UpdateProfileInput) (User, error)` | Update first/last name |
| `DeleteAccount(ctx, DeleteAccountInput) error` | Delete current account |
| `ForgotPassword(ctx, ForgotPasswordInput) (string, error)` | Generate reset token |
| `ResetPassword(ctx, ResetPasswordInput) error` | Consume reset token |
| `ChangePassword(ctx, ChangePasswordInput) error` | Change password for authenticated user |
| `SendMagicLink(ctx, MagicLinkSendInput) (string, error)` | Generate, store and deliver a magic link — see [Delivery](#delivery) |
| `VerifyMagicLink(ctx, MagicLinkVerifyInput) (User, AuthTokens, error)` | Consume magic link |
| `SendSMSCode(ctx, SMSCodeSendInput) (string, error)` | Generate, store and deliver a 6-digit SMS code — see [Delivery](#delivery) |
| `VerifySMSCode(ctx, SMSCodeVerifyInput) (User, AuthTokens, error)` | Verify SMS code |
| `SetupTOTP(ctx, userID, tenantID) (string, error)` | Generate TOTP secret |
| `VerifyTOTPSetup(ctx, userID, tenantID, secret, code) error` | Enable TOTP |
| `VerifyTOTP(ctx, userID, tenantID, code) (User, AuthTokens, error)` | TOTP second factor |
| `DisableTOTP(ctx, userID, tenantID) error` | Disable TOTP |
| `SendVerificationEmailToken(ctx, EmailVerificationInput) (string, error)` | Generate email verification token |
| `VerifyEmail(ctx, VerifyEmailInput) error` | Mark email verified |
| `RequestEmailChange(ctx, ChangeEmailRequestInput) (string, error)` | Generate email change token |
| `ConfirmEmailChange(ctx, ConfirmEmailChangeInput) error` | Apply email change |
| `GetMetadata(ctx, userID) (map[string]any, error)` | Get user metadata |
| `UpdateMetadata(ctx, userID, map[string]any) error` | Merge user metadata |
| `CreateRole(ctx, role, permissions) error` | Define a role |
| `AssignRole(ctx, userID, role, tenantID) error` | Assign role to user |
| `UserHasPermission(ctx, userID, permission, tenantID) (bool, error)` | Check permission |
| `CreateTenant(ctx, name, config) (Tenant, error)` | Create tenant |
| `AddUserToTenant(ctx, userID, tenantID) error` | Associate user with tenant |
| `ListSessions(ctx, userID, tenantID) ([]Session, error)` | List active sessions |
| `RevokeSessionByID(ctx, sessionID) error` | Revoke a specific session |
| `CleanupExpiredSessions(ctx) (int, error)` | Delete expired sessions |

---

## Configuration

### `Config`

```go
type Config struct {
    Secret                string                        // HMAC secret (min 32 bytes)
    Issuer                string
    AccessTokenTTL        time.Duration                 // default: 15m
    RefreshTokenTTL       time.Duration                 // default: 7d
    SessionCheckOn        string                        // allcalls|refresh|none (default: refresh)
    ResetTokenTTL         time.Duration                 // default: 1h
    MagicLinkTTL          time.Duration                 // default: 15m
    SMSCodeTTL            time.Duration                 // default: 10m
    EmailVerificationTTL  time.Duration                 // default: 24h
    EmailVerificationMode string                        // none|lazy|strict (default: none)
    EmailChangeTTL        time.Duration                 // default: 24h
    ClockSkew             time.Duration                 // default: 5s
    MinPasswordLen        int                           // default: 8
    BcryptCost            int                           // default: bcrypt.DefaultCost (10); 0 means unset
    Require2FA            bool
    TwoFactorAppName      string                        // TOTP issuer shown by authenticator apps; empty = Issuer — see TwoFactorAppName
    BuildTokenClaims      TokenClaimsBuilder            // see Custom Claims
    SendMagicLink         MagicLinkSender               // required by POST /auth/magic-link/send
    SendSMSCode           SMSCodeSender                 // required by POST /auth/sms/send
    SendPasswordReset     PasswordResetSender           // optional; POST /auth/forgot-password
    SendEmailVerification EmailVerificationSender       // optional; POST /auth/send-verification-email
    SendEmailChange       EmailChangeSender             // optional; POST /auth/change-email/request
    SendEmailChanged      EmailChangedSender            // optional; the notice POST /auth/change-email/confirm mails to the old address
    Templates             TemplateStore                 // optional; run-time overrides of the built-in mail templates — see Mailer
    Settings              SettingsStore                 // optional; the admin-flipped runtime settings — see Runtime settings
    SiteURLs              []string                      // first = canonical link base; all = origin allowlist — see Delivery
    Logger                func(format string, args ...any)
}
```

### `EmailVerificationMode`

| mode | `Register` | `Login` with an unverified address |
|---|---|---|
| `none` (default) | marks the address verified | refused (`ErrEmailNotVerified`) |
| `lazy` | leaves the address unverified | allowed |
| `strict` | leaves the address unverified | refused (`ErrEmailNotVerified`) |

Under `none` the gate is unobservable through `Register`, because a self-registered
user is already verified. It still applies to users that reach the store another way
(admin provisioning, a data import, a custom `UserStore` whose column defaults to
`false`). `lazy` is the only mode that lets an unverified address log in.

Two limitations apply to `strict`:

- `Register` still returns a usable `AuthTokens` pair, so the mode gates `Login`
  rather than access as a whole ([#21](https://github.com/nik2208/awesome-go-auth/issues/21)).
- `POST /send-verification-email` mints and persists the token and answers
  `{"success": true}`; it mails it only when `Config.SendEmailVerification` is
  wired (`WithEmailVerificationSender`, or
  `NewEmailVerificationMailer(...).Send` for the built-in template). With no
  sender the route still succeeds and sends nothing, which is what a reference
  deployment with no email block does, so a `strict` deployment either wires a
  sender or sends the mail itself from the token `SendVerificationEmailToken`
  returns.

### `TwoFactorAppName` and the TOTP parameters

`TwoFactorAppName` is the reference's `twoFactor.appName`: the issuer an
authenticator app files a TOTP enrolment under. `POST /2fa/setup` returns

```
otpauth://totp/<issuer>:<email>?algorithm=SHA1&digits=6&issuer=<issuer>&period=30&secret=<secret>
```

where `<issuer>` is `TwoFactorAppName`, or `Issuer` when that is empty. The
label takes otplib's `issuer:account` form, which is what the reference emits,
and every piece is escaped as `encodeURIComponent` escapes it (`@` is `%40`, a
space is `%20`). The reference falls back to the literal `'awesome-node-auth'`
instead of `Issuer`; this port keeps `Issuer` so that enrolments made before the
field existed and enrolments made after it sit under one name — registered as
the deviation `totp-issuer-defaults-to-config-issuer` in [README.md](README.md).
`WithTwoFactorAppName("awesome-node-auth")` reproduces the reference's label.

The TOTP parameters are not knobs, in the reference or here. They are exported
as constants, read by both the URI above and the verifier behind
`/2fa/verify-setup` and `/2fa/verify`, so the two cannot drift:

| Constant | Value | |
|---|---|---|
| `TOTPAlgorithm` | `"SHA1"` | otplib's default |
| `TOTPDigits` | `6` | otplib's default |
| `TOTPPeriod` | `30 * time.Second` | otplib's default |
| `TOTPSkew` | `1` | steps either side of now a code is accepted for; this port's tolerance — otplib's `epochTolerance` defaults to `0`, registered as the deviation `totp-accepts-one-step-of-skew` in [README.md](README.md) |

### `DefaultConfig(secret string) Config`

Returns a `Config` with sensible defaults.

### `(Config).validate() error`

Called internally; ensures secret length >= 32 and TTLs > 0.

---

## Runtime settings

`Config` is what a deployment decides at start-up. `SettingsStore` is the other
half: the handful of global switches an administrator flips at run time through
the reference's admin Control panel, the reference's `ISettingsStore`
(`src/interfaces/settings-store.interface.ts:28-40`, wired as
`routerOptions.settingsStore`, `src/router/auth.router.ts:92`).

```go
type SettingsStore interface {
    GetSettings(ctx context.Context) (AuthSettings, error)                       // zero value = nothing configured
    UpdateSettings(ctx context.Context, patch AuthSettings) (AuthSettings, error) // shallow merge; returns what is stored
}

type AuthSettings struct {
    RequireEmailVerification             *bool       `json:"requireEmailVerification,omitempty"`
    EmailVerificationMode                *string     `json:"emailVerificationMode,omitempty"`               // none|lazy|strict
    LazyEmailVerificationGracePeriodDays *int        `json:"lazyEmailVerificationGracePeriodDays,omitempty"` // 7 when unset
    Require2FA                           *bool       `json:"require2FA,omitempty"`
    EnabledWebhookActions                []string    `json:"enabledWebhookActions,omitempty"`
    UI                                   *UISettings `json:"ui,omitempty"`
}

type UISettings struct {
    PrimaryColor   *string `json:"primaryColor,omitempty"`
    SecondaryColor *string `json:"secondaryColor,omitempty"`
    LogoURL        *string `json:"logoUrl,omitempty"`
    SiteName       *string `json:"siteName,omitempty"`
    LogoPath       *string `json:"logoPath,omitempty"`
    BgColor        *string `json:"bgColor,omitempty"`
    BgImage        *string `json:"bgImage,omitempty"`
    CardBg         *string `json:"cardBg,omitempty"`
}
```

`MemorySettingsStore` (`NewMemorySettingsStore()`) is the in-memory
implementation: safe for concurrent use, copies in and out.
`WithSettingsStore(store)` wires it (`Config.Settings`); without one nothing
changes, exactly as in the reference, which skips the settings check altogether
when no store is configured (`auth.router.ts:890`).

### What is consulted

One setting, on one route. `Require2FA` is read by `(*Auth).TwoFactorPolicy(ctx)`
and `POST /auth/2fa/disable` refuses on it with
`403 {"error":"Cannot disable 2FA: required by system policy","code":"2FA_REQUIRED"}`
— the reference's answer, from the same check
(`auth.router.ts:890-896`). The route checks the per-user `User.Require2FA` flag
first and answers `403 ... "required for your account"` for that one
(`:884-888`), as the reference does.

```go
store := auth.NewMemorySettingsStore()
required := true
_, _ = store.UpdateSettings(ctx, auth.AuthSettings{Require2FA: &required})
a, err := auth.New(auth.WithSettingsStore(store))
```

`TwoFactorPolicy` is `Config.Require2FA || settings.require2FA`. The static term
is this port's own — the reference has no config-level `require2FA` anywhere,
which is a wire difference, registered as the deviation
`config-require2fa-is-a-system-policy-term` in [README.md](README.md) — and it is
checked first, so a deployment that already requires the factor never
pays for a store read. A store that cannot answer is an error, and the route
answers `500 {"error":"Internal server error"}` with no `code`: failing closed,
and the same status the reference produces when its `getSettings` throws
(`handleError`, `auth.router.ts:899-901` and `:189-195`). The error is logged
through `Config.Logger` before that body goes out, since the body carries none of
it — as the reference logs it in `handleError` (`:193`).

### What is deliberately not consulted

`RequireEmailVerification`, `EmailVerificationMode` and
`LazyEmailVerificationGracePeriodDays` are stored, returned and never read by
login. That is the reference's behaviour, not a gap here: no route that decides a
login reads the store there either — its local strategy reads the static
`config.emailVerificationMode` (`src/strategies/local/local.strategy.ts:32-35`).
The admin UI writes the keys and displays them back; nothing enforces them. It is
catalogued upstream as reference-issues N36, and reproducing it is the point — a
port that quietly enforced these would refuse logins the reference allows, and
the family's clients are pinned to the reference. Use
`Config.EmailVerificationMode` for the knob that does decide a login; see
[`EmailVerificationMode`](#emailverificationmode).

There is no deviation entry for any of this, because there is no wire
difference: every route this port serves answers what the reference answers for
the same stored settings.

`EnabledWebhookActions` and `UI` are stored for surfaces that have not landed yet
and are read by neither today. Both have a reader in the reference, and both sit
outside the login path:

- `GET <prefix>/ui/config` reads the `ui` block for branding
  (`src/router/ui.router.ts:99` and `:126-133`), mounted by `createAuthRouter`
  itself when `config.ui.enabled` (`auth.router.ts:1639-1648`).
- The tools router reads `enabledWebhookActions` as the global allowlist for the
  inbound-webhook sandbox (`src/router/tools.router.ts:261-262`) — and swallows a
  store failure (`.catch(() => ({}))`), i.e. it fails **open**, where this port
  fails closed on `/2fa/disable`. Worth knowing before that router is ported.

### The merge rule

`UpdateSettings` applies the patch as the reference's shallow spread,
`merged = {...current, ...settings}` — the JSDoc example at
`settings-store.interface.ts:20-24` and the interface comment at `:36-38`,
"Settings not present in the input are left untouched". A `nil` field keeps what
is stored; a set field replaces it. `MergeSettings(current, patch)` is that rule,
exported so a database-backed store applies the same one.

The reference's `src/` ships no `ISettingsStore` implementation to compare
against — `src/stores/` holds only `memory-template.store.ts`. The
implementations live beside it and all spread the same way; the closest to this
one is `examples/in-memory-user-store.ts:266-268`,
`this.settings = { ...this.settings, ...updates }`.

Shallow is the operative word, and it bites on `UI`: that is one key of the
spread, so a patch carrying a `UI` replaces the stored block **whole** — the
fields it does not name are dropped, not preserved. The reference depends on
this: its admin `PATCH /admin/api/settings/ui` reads the current settings, merges
the `ui` sub-object itself and writes the merged block back
(`admin.router.ts:979-981`), which it would have no reason to do if the store
merged it. To change one colour, read, merge, write. `EnabledWebhookActions`
follows the same rule as a whole value — `nil` keeps, and a non-`nil` slice
replaces, an empty one included, which is how every action is switched off.

That last distinction has to survive an encoder, and `omitempty` on a `[]string`
would not carry it: it drops the empty slice as well as the `nil` one, so a store
that persists `AuthSettings` as JSON would write the cleared list as an absent
key, read it back as `nil`, and the next merge would put the old list back.
`AuthSettings.MarshalJSON` encodes that one field through a pointer instead, so
`nil` stays absent and a cleared list is written as `[]` — which is what
`JSON.stringify` emits in the reference. Nothing is needed on the way in:
`encoding/json` already decodes `[]` into a non-`nil` empty slice.

The reference's `updateSettings` returns `void` and leaves the caller to read
the result back; this one returns what is stored afterwards, as `TemplateStore`
does.

---

## Models

### `User`

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Unique user ID (format: `usr_<hex>`) |
| `Email` | `string` | Normalized (lowercase, trimmed) email |
| `PasswordHash` | `string` | bcrypt hash |
| `TenantID` | `string` | Owning tenant |
| `PhoneNumber` | `string` | For SMS OTP |
| `FirstName`, `LastName` | `string` | Display name |
| `Role` | `string` | Single role (legacy; prefer Roles slice) |
| `LoginProvider` | `string` | Provider that created the account (set by `OAuthService.HandleCallback`); empty reads as `"local"` on tokens and `/me` |
| `IsEmailVerified` | `bool` | |
| `Require2FA` | `bool` | Per-user 2FA requirement |
| `IsTOTPEnabled` | `bool` | |
| `TOTPSecret` | `string` | Base32 encoded |
| `Metadata` | `map[string]any` | Enriched by MetadataStore |
| `Roles` | `[]string` | Enriched by RBACStore |
| `Permissions` | `[]string` | Enriched by RBACStore |
| `Tenants` | `[]Tenant` | Enriched by TenantStore |
| `CustomClaims` | `map[string]any` | From the BuildTokenClaims hook; filled by `Me`, nil from `Authenticate` |
| `CreatedAt`, `UpdatedAt` | `time.Time` | |

### `Session`

| Field | Type | Description |
|-------|------|-------------|
| `ID` | `string` | Session ID (format: `ses_<hex>`) |
| `UserID`, `TenantID` | `string` | |
| `RefreshTokenHash` | `string` | SHA-256 of refresh token |
| `ExpiresAt` | `time.Time` | |
| `RevokedAt` | `*time.Time` | Non-nil = revoked |

### `AuthTokens`

```go
type AuthTokens struct {
    AccessToken  string
    RefreshToken string
    ExpiresIn    time.Duration // access token TTL
}
```

### `Tenant`

```go
type Tenant struct {
    ID, Name  string
    IsActive  bool
    Config    map[string]any
    CreatedAt time.Time
}
```

---

## Store Interfaces

All interfaces are defined in `store.go`. Implement any or all of them against your database.

### `UserStore` (required)

```go
type UserStore interface {
    CreateUser(ctx context.Context, user User) (User, error)
    GetUserByEmail(ctx context.Context, email, tenantID string) (User, error)
    GetUserByID(ctx context.Context, id, tenantID string) (User, error)
}
```

### `SessionStore` (required)

```go
type SessionStore interface {
    CreateSession(ctx context.Context, session Session) (Session, error)
    GetSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error)
    UpdateSession(ctx context.Context, session Session) error
}
```

### Optional feature stores (type-assert at runtime)

| Interface | Methods | Used by |
|-----------|---------|---------|
| `UserPasswordStore` | `UpdatePassword`, `UpdateResetToken`, `GetUserByResetTokenHash`, `ClearResetToken` | ForgotPassword, ResetPassword, ChangePassword |
| `MagicLinkStore` | `UpdateMagicLinkToken`, `GetUserByMagicLinkTokenHash`, `ClearMagicLinkToken` | SendMagicLink, VerifyMagicLink |
| `SMSStore` | `UpdateSMSCode`, `GetUserBySMSCodeHash`, `ClearSMSCode` | SendSMSCode, VerifySMSCode |
| `TOTPStore` | `UpdateTOTPSecret` | VerifyTOTPSetup, DisableTOTP |
| `EmailVerificationStore` | `UpdateEmailVerificationToken`, `GetUserByEmailVerificationTokenHash`, `MarkEmailVerified`, `ClearEmailVerificationToken` | SendVerificationEmailToken, VerifyEmail |
| `EmailChangeStore` | `UpdateEmailChangeToken`, `GetUserByEmailChangeTokenHash`, `ApplyEmailChange`, `ClearEmailChangeToken` | RequestEmailChange, ConfirmEmailChange |
| `SessionAdminStore` | `ListSessionsForUser`, `RevokeSessionByID`, `DeleteExpiredSessions` | ListSessions, RevokeSessionByID, CleanupExpiredSessions |
| `UserMetadataStore` | `GetMetadata`, `UpdateMetadata`, `ClearMetadata` | GetMetadata, UpdateMetadata |
| `RolesPermissionsStore` | `AddRoleToUser`, `RemoveRoleFromUser`, `GetRolesForUser`, `CreateRole`, `DeleteRole`, `AddPermissionToRole`, `RemovePermissionFromRole`, `GetPermissionsForRole`, `GetPermissionsForUser`, `UserHasPermission` | CreateRole, AssignRole, UserHasPermission |
| `TenantStore` | `CreateTenant`, `GetTenantByID`, `GetAllTenants`, `UpdateTenant`, `DeleteTenant`, `AssociateUserWithTenant`, `DisassociateUserFromTenant`, `GetTenantsForUser`, `GetUsersForTenant` | CreateTenant, AddUserToTenant |
| `UserAccountStore` | `UpdateProfile`, `DeleteUser` | UpdateProfile, DeleteAccount |
| `SessionLookupStore` | `GetSessionByID` | SessionCheckOn=allcalls (`Authenticate`, `Me`) |

---

## In-Memory Stores

All provided in the core package for development, testing, and embedded deployments.

| Type | Implements |
|------|-----------|
| `MemoryUserStore` | UserStore + UserPasswordStore + MagicLinkStore + SMSStore + TOTPStore + EmailVerificationStore + EmailChangeStore |
| `MemorySessionStore` | SessionStore + SessionAdminStore |
| `MemoryMetadataStore` | UserMetadataStore |
| `MemoryRolesPermissionsStore` | RolesPermissionsStore |
| `MemoryTenantStore` | TenantStore |
| `MemoryTelemetryStore` | TelemetryStore |
| `MemoryLinkedAccounts` | LinkedAccountStore |

---

## Auth Functional Options

Pass to `auth.New(...)`:

| Option | Description |
|--------|-------------|
| `WithSecret(s string)` | JWT signing secret (min 32 bytes) |
| `WithIssuer(s string)` | Token issuer claim |
| `WithTokenTTLs(access, refresh time.Duration)` | Token lifetimes |
| `WithUserStore(UserStore)` | Custom user store |
| `WithSessionStore(SessionStore)` | Custom session store |
| `WithMetadataProvider(UserMetadataStore)` | Enable metadata |
| `WithRBACProvider(RolesPermissionsStore)` | Enable RBAC |
| `WithTenantProvider(TenantStore)` | Enable multi-tenancy |
| `WithBcryptCost(int)` | Password hashing cost, `bcrypt.MinCost`..`bcrypt.MaxCost` |
| `WithRequire2FA(bool)` | Require 2FA for all users |
| `WithTwoFactorAppName(string)` | Issuer of the TOTP provisioning URI, the reference's `twoFactor.appName`; empty keeps `Issuer` — see [TwoFactorAppName](#twofactorappname-and-the-totp-parameters) |
| `WithTokenClaimsBuilder(TokenClaimsBuilder)` | Custom JWT claims — see [Custom Claims](#custom-claims) |
| `WithMagicLinkSender(MagicLinkSender)` | Deliver magic links — see [Delivery](#delivery) |
| `WithSMSCodeSender(SMSCodeSender)` | Deliver SMS codes — see [Delivery](#delivery) |
| `WithPasswordResetSender(PasswordResetSender)` | Deliver password-reset tokens — see [Delivery](#delivery) |
| `WithEmailVerificationSender(EmailVerificationSender)` | Deliver email-verification tokens — see [Delivery](#delivery) |
| `WithEmailChangeSender(EmailChangeSender)` | Deliver email-change tokens to the new address — see [Delivery](#delivery) |
| `WithEmailChangedSender(EmailChangedSender)` | Deliver the email-changed notice to the old address — see [The email-changed notice](#the-email-changed-notice) |
| `WithTemplateStore(TemplateStore)` | Run-time overrides of the built-in mail templates — see [`TemplateStore` interface](#templatestore-interface) |
| `WithSettingsStore(SettingsStore)` | Global settings an administrator flips at run time; only `require2FA` is acted on — see [Runtime settings](#runtime-settings) |
| `WithSiteURLs(urls ...string)` | Front-end base URLs: the first is the canonical link base, all are the origin allowlist — see [Per-request link base and language](#per-request-link-base-and-language) |
| `WithLogger(func)` | Logging callback |

Pass to `NewService(...)` as `ServiceOption`:

| Option | Description |
|--------|-------------|
| `WithMetadataStore(UserMetadataStore)` | |
| `WithRolesPermissionsStore(RolesPermissionsStore)` | |
| `WithTenantStore(TenantStore)` | |

---

## Custom Claims

`Config.BuildTokenClaims` — a `TokenClaimsBuilder`, set with `WithTokenClaimsBuilder` —
adds claims to every token minted: access, refresh and the 2FA step-up token. Its
result is spread over the reference's six base claims (`sub`, `email`, `role`,
`loginProvider`, `isEmailVerified`, `isTotpEnabled`) and may override them, exactly as
the reference's `config.buildTokenPayload(user)` may (`auth.router.ts:378-384`). The
session claims `sid`, `tid`, `jti`, `typ`, `iss`, `iat` and `exp` are reserved: they are
written after the merge, so a builder value under one of those names is discarded
rather than minted.

```go
type TokenClaimsBuilder = func(ctx context.Context, user User) (map[string]any, error)
```

A builder error fails the mint: the login, refresh or step-up that needed the token
answers a generic `500` rather than issuing a token carrying fewer claims than the
deployment configured.

### Where the builder runs

| Call | Runs the builder | Why |
|------|------------------|-----|
| Every mint — `Register`, `Login`, `Refresh`, the OAuth callback, the passwordless and 2FA verifies, the step-up token | once per token | The claims go into the token |
| `Me` / `GET /me` | once | The profile mirrors the reference's `/me`, whose body is `buildPayload(user)` (`auth.router.ts:656-680`); the result is rendered under `customClaims`. A failure here is logged and `customClaims` omitted — a read does not go dark because a mint-time hook is down |
| `Authenticate` — the four adapters' `Middleware()`, `POST /link-request`, the IdP `userinfo` endpoint | never | What the builder computed is already inside the token the request carried; `CustomClaims` is nil on the user in context. The reference's `authMiddleware` draws the same line: it verifies the token and hands the route the payload as `req.user`, without `buildTokenPayload` (`auth.middleware.ts:44-61`) |

`Authenticate(ctx, accessToken)` is `Me` without the builder: it verifies the token,
runs the `SessionCheckOn=allcalls` check, loads the user and fills `Metadata`, `Roles`,
`Permissions` and `Tenants` from the optional stores (best effort, as always), and
fails with `Me`'s sentinels. A host route that needs the builder's result can call
`Auth.Me` itself.

### Building the hook from configuration

Three constructors build the hook out of configuration rather than code. They are
this port's own extension — the reference has only the in-process function
(`auth-config.model.ts:316`) — and a token minted through them is indistinguishable
on the wire from one minted through a hand-written closure. Together they decode the
consumer's `security.jwt.extraClaims` table, `{claim: {fromUserField: <field>} | {const: <value>}}`.

| Constructor | Result |
|-------------|--------|
| `StaticClaims(map[string]any) TokenClaimsBuilder` | The same claims on every token, from a copy of the map: neither later edits to the input nor edits to a result change the next token |
| `UserFieldClaims(map[string]string) (TokenClaimsBuilder, error)` | Copies `User` fields into named claims; the map is `claim → field`, the field spelled as it is on `/me` |
| `ChainClaims(...TokenClaimsBuilder) TokenClaimsBuilder` | Runs builders in order and merges: later wins on a shared name, the first error stops the chain, nil builders are skipped |

`UserFieldClaims` reads only these fields, by their `/me` names: `id`, `email`, `role`,
`tenantId`, `firstName`, `lastName`, `phoneNumber`, `isEmailVerified`, `isTotpEnabled`,
`loginProvider` (`"local"` when unset). Any other name — a credential column, a Go
spelling, an enriched collection such as `roles` — is a constructor error, so a typo
in configuration fails at startup and not on every login. So is a claim *name* that is
one of the reserved session claims (`sid`, `tid`, `jti`, `typ`, `iss`, `iat`, `exp`):
the mint would discard the mapping every time, and a mapping that can never reach a
token is a configuration error, not a claim. Mapping over a base claim (`email`,
`role`, ...) stays allowed. `StaticClaims` has no error to return, so a reserved name
there is discarded at mint time like any hook's — check the names before building.
Every mapped claim is emitted on every token, an empty field as an empty value
rather than an absent claim.

```go
fields, err := auth.UserFieldClaims(map[string]string{"tenant": "tenantId", "given": "firstName"})
if err != nil {
    log.Fatal(err) // names the unknown field and lists the allowed ones
}
a, err := auth.New(
    auth.WithTokenClaimsBuilder(auth.ChainClaims(
        fields,
        auth.StaticClaims(map[string]any{"plan": "pro"}),
    )),
)
```

### Claims webhook

`ClaimsWebhook` is a builder that asks an HTTP endpoint for the claims — the consumer's
`security.jwt.claimsWebhook {url, timeoutMs}` knob, for claims that are computed rather
than mapped. Its `Build` method has the builder's signature, so it is wired directly or
as one link of a chain.

```go
hook, err := auth.NewClaimsWebhook("https://hooks.example.com/claims", secret) // 2s timeout
a, err := auth.New(auth.WithTokenClaimsBuilder(hook.Build))
// or, after the mapped claims, with the endpoint having the last word:
a, err = auth.New(auth.WithTokenClaimsBuilder(auth.ChainClaims(fields, hook.Build)))
```

```go
type ClaimsWebhook struct {
    URL     string        // absolute http(s) URL; NewClaimsWebhook validates it
    Secret  string        // signs the body when set; never sent
    Timeout time.Duration // per request, through ctx; NewClaimsWebhook sets 2s
    Client  *http.Client  // nil = http.DefaultClient
}
```

> **This request shape is this port's own.** The reference's `buildTokenPayload` is an
> in-process function that never crosses HTTP, so there is no reference wire to
> reproduce. The envelope — headers and signature — is the family's outbound-webhook
> convention (`src/tools/webhook-sender.ts:24-33`, `54-56`), the same one the delivery
> webhook uses, so one receiver verifies both.

One request per token minted and per `GET /me`, and none for a protected route:
`POST <URL>` with `Content-Type: application/json` and

| Header | Value |
|--------|-------|
| `X-Webhook-Event` | `claims.build` (`ClaimsWebhookEvent`) |
| `X-Webhook-Delivery` | a fresh UUID per request |
| `X-Webhook-Timestamp` | when it was sent: ISO 8601, UTC, milliseconds — `2026-09-11T10:00:00.000Z` |
| `X-Webhook-Signature` | `sha256=<hex HMAC-SHA256 of the raw body, keyed by Secret>` — only when `Secret` is set; `VerifyWebhookSignature` checks it |

The body is `{"user": {…}}`, where `user` is the caller as `GET /me` renders it
(`PublicUser`: credentials omitted, `loginProvider` always present):

```json
{"user":{"sub":"usr_…","id":"usr_…","email":"ada@example.com","loginProvider":"local","tenantId":"t1","isEmailVerified":true,"isTotpEnabled":false,"createdAt":"2026-09-11T10:00:00Z"}}
```

At mint time `user` is the stored row; on `/me` it is the enriched profile, so `roles`,
`permissions`, `tenants` and `metadata` appear there and not at mint time.

The endpoint answers `2xx` with

```json
{"claims": {"plan": "pro", "org": "acme"}}
```

and the `claims` object is merged like any builder's result: it may override the six
base claims and cannot set the reserved session claims, so a compromised endpoint
cannot retype a token or rebind a session. **Anything else fails the mint** — the
route answers the generic `500` any failing builder does, and `/me` logs and omits
`customClaims`: a non-`2xx`, a transport error, the timeout (the caller's context
deadline wins when shorter), a body over 64 KiB, a body that is not JSON, a missing
or `null` `claims`, or a `claims` that is not an object. Errors name the status or
the transport failure and never the response body or the secret. Failing closed is
deliberate: a token minted without the claims the deployment configured would
authorise less, or more, than the deployment decided.

---

## OAuth 2.0 + Account Linking

### `OAuthProvider`

```go
type OAuthProvider struct {
    Name, ClientID, ClientSecret, RedirectURL string
    AuthURL, TokenURL, UserInfoURL            string
    Scopes                                    []string
    AdditionalAuthParams                      map[string]string // extra authorize-query params
    GitHubEmailsURL                           string            // "github" only; "" = UserInfoURL + "/emails"
    MapProfile func(raw map[string]any) (OAuthUserInfo, error)  // replaces the default profile mapping
    ProfileMap map[string]string                                // declarative MapProfile; see Profile mapping
}
```

The reference's `GenericOAuthProviderConfig` (`generic-oauth.strategy.ts:39-78`).
`AdditionalAuthParams` is its `additionalAuthParams`: every entry lands in the
authorization URL's query, with the reference's precedence — an entry overrides
`client_id`, `redirect_uri`, `response_type` and `scope`, while `state` (and
the PKCE `code_challenge`/`code_challenge_method` pair this port adds) always
wins over an entry.

### `NewOAuthService(providers ...OAuthProvider) *OAuthService`

### `NewOAuthServiceWithConfig(providers ...OAuthProvider) (*OAuthService, error)`

`NewOAuthService` with the configuration validated: every provider's
`ProfileMap` is compiled and the errors — one per broken provider, each naming
the provider and the expression — come back joined, with no service, so a
deployment fails at start-up rather than at the first login. `NewOAuthService`
keeps its signature and never panics: a map that does not compile is recorded
against its provider, whose `ExchangeCode` calls return that error before the
token endpoint is contacted (a 500 on the callback — a configuration error,
not a client one) while the other providers keep working.

### `GoogleProvider(clientID, clientSecret, redirectURL) OAuthProvider`
### `GitHubProvider(clientID, clientSecret, redirectURL) OAuthProvider`

The reference's two hard-coded strategies as presets. Google sends scope
`openid email profile` plus `access_type=offline` through
`AdditionalAuthParams` (`google.strategy.ts:28-29`) and maps `sub`, `email`,
`email_verified`, `name`, `picture`. GitHub sends scope `user:email`, maps
`String(id)`, `email`, `name` falling back to `login`, `avatar_url`, and when
the profile carries no email — a GitHub account with a private address — GETs
`GitHubEmailsURL` (`https://api.github.com/user/emails`) with
`Authorization: token <access_token>`, picks the entry that is both `primary`
and `verified`, else the first one, and reports its `verified` flag as
`EmailVerified` (`github.strategy.ts:54-69`). A failing emails call leaves the
email empty; it does not fail the exchange.

### `(*OAuthService).AuthorizeURL(provider, state) (string, error)`

Returns the OAuth2 authorization URL to redirect the user to.

### `(*OAuthService).ExchangeCode(ctx, provider, code) (OAuthUserInfo, error)`

Exchanges an authorization code for normalized user info. For a provider that
is neither `google` nor `github` the subject id is `id`, then `sub` — the
reference's `String(raw.id ?? raw.sub ?? '')` (`generic-oauth.strategy.ts:155`)
— then `user_id`, this port's extra last resort; a numeric id is stringified.
`email_verified` fills `EmailVerified` when it is a boolean. A provider with a
`MapProfile` or a `ProfileMap` (next section) gets that mapping instead.

### Profile mapping: `MapProfile` and `ProfileMap`

The reference's `mapProfile` hook (`generic-oauth.strategy.ts:71-77`) turns the
raw userinfo document into the `{id, email, emailVerified?, name?, picture?}`
profile, and when it is set it is what `getUserProfile` returns, in place of
the default mapping (`:151-153`). This port offers it in two forms on
`OAuthProvider`:

- **`MapProfile func(raw map[string]any) (OAuthUserInfo, error)`** — the hook
  itself. It replaces the whole mapping for that provider, the `github`
  preset's `/user/emails` fallback included. Fill `ProviderID`, `Email`,
  `Name`, `AvatarURL` and `EmailVerified`; the service sets `Provider`, and
  `Raw` when the hook left it nil. An error fails the exchange on the
  profile-failed path: 401 `OAUTH_PROFILE_FAILED` on the callback.
- **`ProfileMap map[string]string`** — the declarative form for a provider
  loaded from configuration, compiled by `NewOAuthService` and validated by
  `NewOAuthServiceWithConfig`. `nil` or empty means the default mapping.

`MapProfile` wins when both are set; the `ProfileMap` is still compiled, so a
broken one is still reported.

#### `ProfileMap` grammar

The keys are `id`, `email`, `emailVerified`, `name` and `picture`; `id` is
required and any other key is an error. Each value is an expression in this
grammar, which is this port's own (the reference takes a function):

```
expr    = alt ("??" alt)*
alt     = path | literal
path    = "$" ("." key | "[" index "]")+
key     = one or more ASCII letters, digits, "_" or "-"
index   = one or more decimal digits
literal = a double-quoted string, allowed only as the last alternative
```

Whitespace around an alternative is ignored. Anything else — `$` alone, a
single-quoted literal, a wildcard (`$.*`, `$[*]`), a filter (`$[?(...)]`), a
slice, a function call, a quoted key — is a compile error naming the
expression. A literal has no escapes, so it cannot contain a double quote.

Evaluation follows JavaScript's `??`: the alternatives are tried in order and
the first path that resolves to a value that is neither missing nor `null`
wins, so an empty string, `false` or `0` is a value and stops the chain; a
literal always resolves. A string is taken as is, a number is rendered as
JavaScript's `String()` renders it (`7001` is `"7001"`, `1.5` is `"1.5"`,
`1e21` is `"1e+21"`), a boolean becomes `"true"` or `"false"`; a value that is
an object or an array is an evaluation error. `emailVerified` must resolve to
a boolean or the strings `"true"`/`"false"` (a literal that is neither is
refused at compile time). `id` must resolve to a non-empty string; the other
four stay empty (`EmailVerified` nil) when nothing resolves. An evaluation
error takes the profile-failed path, 401 `OAUTH_PROFILE_FAILED`.

```go
// Microsoft Graph: /v1.0/me answers {id, displayName, mail, userPrincipalName},
// and mail is null for an account without a mailbox.
microsoft := auth.OAuthProvider{
    Name:         "microsoft",
    ClientID:     os.Getenv("MS_CLIENT_ID"),
    ClientSecret: os.Getenv("MS_CLIENT_SECRET"),
    RedirectURL:  "https://api.example.com/auth/oauth/microsoft/callback",
    AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
    Scopes:       []string{"openid", "email", "profile"},
    ProfileMap: map[string]string{
        "id":    "$.id",
        "email": "$.mail ?? $.userPrincipalName",
        "name":  "$.displayName",
    },
}

// A provider that wraps the profile:
// {"data":{"user":{"id":7001,"mail":null,"userPrincipalName":"…","verified":"true",
//                  "profile":{"displayName":"…","photos":[{"url":"…"}]}}}}
nested := auth.OAuthProvider{
    // …
    ProfileMap: map[string]string{
        "id":            "$.data.user.id", // 7001 becomes "7001"
        "email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
        "emailVerified": `$.data.user.verified ?? "false"`,
        "name":          "$.data.user.profile.displayName",
        "picture":       "$.data.user.profile.photos[0].url",
    },
}

svc, err := auth.NewOAuthServiceWithConfig(microsoft, nested) // a bad expression fails here
```

#### `CompileProfileMap(m map[string]string) (func(map[string]any) (OAuthUserInfo, error), error)`

The compiler behind `ProfileMap`, exported so a deployment can validate a map
it loaded from configuration — or build a `MapProfile` from one — before it
wires anything. The function it returns fills everything but `Provider`.

### `(*OAuthService).HandleCallback(ctx, authSvc, linkedAccounts, info, tenantID, linkToUserID) (User, AuthTokens, error)`

Resolves or creates a user from OAuth user info:
1. If `linkToUserID` non-empty: links provider to existing account
2. If existing link found: returns existing user
3. If email match found: auto-links and returns existing user
4. Otherwise: creates new user

### `OAuthUserInfo`

```go
type OAuthUserInfo struct {
    ProviderID, Provider, Email, Name, AvatarURL string
    EmailVerified *bool // provider's email_verified; nil = not stated
    Raw map[string]any
}
```

`EmailVerified` is the reference profile's `emailVerified?`. `HandleCallback`
does not read it yet: an account the callback creates is marked verified as
before.

### `LinkedAccountStore` interface

```go
type LinkedAccountStore interface {
    Save(ctx, OAuthLinkedAccount) error
    FindByProvider(ctx, provider, providerID) (OAuthLinkedAccount, error)
    ListForUser(ctx, userID) ([]OAuthLinkedAccount, error)
    Delete(ctx, id) error
}
```

### `MemoryLinkedAccounts`

In-memory `LinkedAccountStore`. Create with `NewMemoryLinkedAccounts()`.

### `PendingLinkStore` interface

For storing OAuth state between redirect and callback.

---

## SSE (Server-Sent Events)

### `SseHub`

Thread-safe in-process SSE broker.

```go
hub := auth.NewSseHub()

// Publish from anywhere
hub.Publish(ctx, userID, auth.SseMessage{
    Event: "notification",
    Data:  map[string]any{"message": "Hello!"},
})

// Serve to a client
http.Handle("/events", auth.ServeSSE(hub, userID))
```

### `(*SseHub).Subscribe(ctx, channel) (<-chan SseMessage, error)`
### `(*SseHub).Publish(ctx, channel, msg) error`
### `(*SseHub).Unsubscribe(channel, ch)`

### `ServeSSE(hub *SseHub, channel string) http.HandlerFunc`

Returns an HTTP handler that streams `text/event-stream` to the client. Sends a `:ping` keepalive comment every 30 seconds.

### `SseDistributor` interface

Implement for Redis/Kafka-based multi-instance SSE scaling:

```go
type SseDistributor interface {
    Publish(ctx, channel string, msg SseMessage) error
    Subscribe(ctx, channel string) (<-chan SseMessage, error)
}
```

---

## Webhooks

### `NewWebhookDispatcher(endpoints ...WebhookEndpoint) *WebhookDispatcher`

### `WebhookEndpoint`

```go
type WebhookEndpoint struct {
    ID, URL, Secret string
    Events          []string // empty = all events
}
```

### `(*WebhookDispatcher).Dispatch(ctx, Event)`

Sends the event to all matching endpoints asynchronously. Signs each request with `X-Signature-SHA256: sha256=<hmac-hex>`.

### `VerifyWebhookSignature(secret string, body []byte, sigHeader string) error`

Validates an inbound webhook signature header.

---

## Telemetry

### `TelemetryStore` interface

```go
type TelemetryStore interface {
    Record(ctx, TelemetryEvent) error
    Query(ctx, TelemetryFilter) ([]TelemetryEvent, error)
}
```

### `TelemetryEvent`

```go
type TelemetryEvent struct {
    ID, EventName, UserID, TenantID string
    IP, UserAgent                    string
    Success                          bool
    Error                            string
    Timestamp                        time.Time
    Meta                             map[string]any
}
```

### `TelemetryFilter`

Filter by `UserID`, `TenantID`, `EventName`, `Since`, `Until`, `Limit`.

### `NewMemoryTelemetryStore() *MemoryTelemetryStore`

---

## Mailer

### `MailerTransport` interface

```go
type MailerTransport interface {
    Send(ctx context.Context, msg MailMessage) error
}

type MailMessage struct {
    To, Subject string
    Body        string // HTML when IsHTML is set, plain text otherwise
    IsHTML      bool
    Text        string // plain-text alternative of an HTML Body; empty → the HTML is sent as the text
}
```

### `NewGatewayMailerTransport(cfg MailerConfig) (MailerTransport, error)`

The transport for the family's mail gateway — the request the reference's built-in
mailer sends. The contract is spelled out under
[Mail gateway contract](#mail-gateway-contract) in the Delivery section.

```go
type MailerConfig struct {
    Endpoint    string       `json:"endpoint"`              // absolute http(s) URL; anything else is a constructor error
    APIKey      string       `json:"apiKey"`                // sent as X-API-Key
    From        string       `json:"from"`
    FromName    string       `json:"fromName,omitempty"`
    Provider    string       `json:"provider,omitempty"`
    DefaultLang string       `json:"defaultLang,omitempty"` // carried, not read: locale is the mailers' knob
    Client      *http.Client `json:"-"`                     // nil → a client with a 10-second timeout
}
```

### `NewHTTPMailerTransport(endpointURL, secret string) *HTTPMailerTransport` — deprecated

POSTs a JSON-encoded `MailMessage` (PascalCase) to any HTTP endpoint with an
`X-Mailer-Secret` header — a request of this port's own that no gateway built for
the reference accepts. Kept unchanged for gateways built against it since 0.3.0 and
scheduled for removal in v1.0.0; use `NewGatewayMailerTransport`.

### `NewMailTemplater(appName string) *MailTemplater`

Returns a templater holding the reference's six built-in templates, in **English**
and **Italian**, transcribed from `awesome-node-auth`
`src/services/mailer.service.ts:19-127` (invitation: `:211-225`) — subject, HTML
and text for each. `appName` is what a template mentioning `{{.appName}}` shows;
the built-ins mention none.

| Constant | Id | Data the ready-made mailer supplies | Reference |
|----------|----|-------------------------------------|-----------|
| `TemplatePasswordReset` | `password-reset` | `link`, `token` | `mailer.service.ts:186` |
| `TemplateMagicLink` | `magic-link` | `link`, `token` | `:191` |
| `TemplateWelcome` | `welcome` | `loginUrl`, `tempPassword` — sent by the reference's `POST /register` (`auth.router.ts:719-724`: `sendWelcome(user.email, {loginUrl: <siteUrl>/login})`, or the deployment's own `config.email.sendWelcome(user.email, data)`); **this port's `POST /register` mails nothing yet**, so the id is reachable only through `RenderMail` | `:196`, `:61-89` |
| `TemplateVerifyEmail` | `verify-email` | `link`, `token` | `:201` |
| `TemplateEmailChanged` | `email-changed` | `newEmail` | `:206` |
| `TemplateInvitation` | `invitation` | `link` — no ready-made mailer, and no route in the reference calls its `sendInvitation` either | `:211` |

The 0.3.x ids `reset_password`, `magic_link`, `verify_email` and `email_change` are
**deprecated aliases**: the first three of the matching constant, `email_change` of
`TemplateVerifyEmail`, because the reference mails its verification template on
`/change-email/request` (`auth.router.ts:1027-1032`) and has no separate one. They
work everywhere an id is accepted and go away in v1.0.0.

### `(*MailTemplater).Register(locale, id, subject, html, text string)`

Adds or replaces the template rendered for `id` in `locale`. The three parts are Go
templates over the keys of `MailTemplateData` — `{{.link}}`, `{{.appName}}` … —
`html/template` for the HTML body (contextual escaping applies), `text/template` for
the subject and the text. This is how a deployment replaces a built-in, adds a
locale, or adds an id of its own without a store; a part that does not parse is
reported by the next render of that `(locale, id)`. An alias id registers under the
id it aliases.

### `(*MailTemplater).RenderMail(ctx, locale, id string, data MailTemplateData) (MailRendered, error)`

The reference's `MailerService.render` (`mailer.service.ts:149-181`), returning
`MailRendered{Subject, HTML, Text}`:

1. A stored template is looked up — through `MailTemplater.Store`, or the store the
   service put on `ctx` (`Config.Templates`) — and used only when both its
   `BaseHTML` and `BaseText` are non-empty (`:158`). A store error is returned.
2. Its translations are those for `locale`, else for `en`, else none (`:159`).
   Every `{{T.key}}` becomes `translations[key]`, or `[key]` when that is missing or
   empty (`:163`); then every remaining `{{key}}` becomes the data value for `key`,
   or `[key]` when there is none (`:165-168`) — the reference's keys per id
   (`link`, `token`; `newEmail`; `loginUrl`, `tempPassword`), plus this port's own
   only when a caller sets them; see `MailTemplateData`. The subject is
   `translations["subject"]`, else the built-in subject for the language, and is
   interpolated the same way (`:172-177`). Values are substituted raw, the HTML
   body included — no escaping, as the reference does none (`:167`). `BaseHTML` is
   your markup, but `newEmail` is what the user typed (lowercased and trimmed,
   nothing more) and `Extra` is whatever the caller passed: a stored template that
   shows them mails them verbatim, exactly as the reference's does; the built-ins,
   rendered by `html/template`, escape them.
3. Otherwise the registered template for `locale` renders — the built-in unless
   `Register` replaced it — falling back to `en`.

`locale` is used as given; the ready-made mailers pass what `resolveLang` picked
(`it`, `en`, or their `Locale`). An id with neither a usable stored template nor a
registered one is an error.

### `(*MailTemplater).Render(locale, id string, data MailTemplateData) (subject, body string, err error)`

`RenderMail` without a context and without the text body: `body` is the HTML. It
sees `MailTemplater.Store` but not a store carried by a service call.

### `MailTemplateData`

```go
type MailTemplateData struct {
    AppName  string         // appName, when non-empty — set by the templater (this port's key)
    UserName string         // name (this port's key)
    Token    string         // token
    URL      string         // link — or loginUrl when the id is welcome, the name its template reads
    Code     string         // code (this port's key)
    NewEmail string         // newEmail
    OldEmail string         // oldEmail (this port's key)
    Extra    map[string]any // any other key, formatted with fmt.Sprint — tempPassword, for instance
}
```

A registered template reads them as `{{.link}}`, `{{.token}}` …; a stored one as
`{{link}}`, `{{token}}` …. An empty field is left out rather than set to `""`, so a
stored template naming a key the mailer did not supply shows `[key]`, as it would in
the reference. The keys marked *this port's* — `appName`, `name`, `code`, `oldEmail`
— and `Extra` are never passed by the reference and are absent here too until set,
so a stored template written for it sees exactly the keys it sees there:
`{link, token}` for `password-reset`, `magic-link` and `verify-email`, `{link}` for
`invitation`, `{newEmail}` for `email-changed`, `{loginUrl, tempPassword}` for
`welcome`. A `{{loginUrl}}` in a password-reset template, or an `{{appName}}` when
the templater has no app name, renders `[loginUrl]` / `[appName]` here as there.

### `TemplateStore` interface

The reference's `ITemplateStore` (`src/interfaces/template-store.interface.ts:13-43`;
`config.templateStore`, `auth-config.model.ts:400`): run-time overrides of the
built-in mail templates, plus the UI translations the reference's UI router reads.

```go
type TemplateStore interface {
    GetMailTemplate(ctx context.Context, id string) (MailTemplate, bool, error)       // false: not stored — the reference's null
    ListMailTemplates(ctx context.Context) ([]MailTemplate, error)
    UpdateMailTemplate(ctx context.Context, id string, patch MailTemplatePatch) (MailTemplate, error) // upsert
    GetUITranslations(ctx context.Context, page string) (UITranslation, bool, error)
    ListUITranslations(ctx context.Context) ([]UITranslation, error)
    UpdateUITranslations(ctx context.Context, page string, translations map[string]map[string]string) (UITranslation, error) // set
}

type MailTemplate struct {
    ID           string                       `json:"id"`
    BaseHTML     string                       `json:"baseHtml"`
    BaseText     string                       `json:"baseText"`
    Translations map[string]map[string]string `json:"translations"` // lang -> key -> value; "subject" is the subject
}

type UITranslation struct {
    Page         string                       `json:"page"`
    Translations map[string]map[string]string `json:"translations"`
}

type MailTemplatePatch struct {
    BaseHTML     *string                      // nil keeps the stored body; a pointer to "" clears it
    BaseText     *string
    Translations map[string]map[string]string // nil keeps every language; non-nil replaces the whole map
}
```

`UpdateMailTemplate` is the reference's upsert: a missing id starts as
`{id, "", "", {}}` and the patch is spread on top (`memory-template.store.ts:16-22`)
— which is why a supplied `Translations` replaces the map rather than merging into
it; read the template and send the map back whole to change one language.
`UpdateUITranslations` sets a page wholesale (`:33-35`). Both return what is stored
afterwards. Placeholders in `BaseHTML` are substituted without HTML escaping — see
step 2 of `RenderMail` for what that means for `newEmail` and `Extra`.

`MemoryTemplateStore` (`NewMemoryTemplateStore()`) is the in-memory implementation:
safe for concurrent use, copies in and out, lists in insertion order.

### `WithTemplateStore(store TemplateStore) Option` / `Config.Templates`

Wires the store once. Every sender the service calls receives a context carrying
it, and a `MailTemplater` whose `Store` is nil — the ready-made mailers' — reads it
from there; a `MailTemplater.Store` set by hand wins, and is the way to render from
a store outside a service call.

```go
store := auth.NewMemoryTemplateStore()
html := `<h1>{{T.title}}</h1><p><a href="{{link}}">{{T.cta}}</a></p>`
text := `{{T.title}}: {{link}}`
_, _ = store.UpdateMailTemplate(ctx, auth.TemplatePasswordReset, auth.MailTemplatePatch{
    BaseHTML: &html,
    BaseText: &text,
    Translations: map[string]map[string]string{
        "en": {"subject": "Reset your {{appName}} password", "title": "Password reset", "cta": "Choose a new password"},
        "it": {"subject": "Reimposta la password", "title": "Reimposta la password", "cta": "Scegli una nuova password"},
    },
})
a, err := auth.New(
    auth.WithTemplateStore(store),
    auth.WithPasswordResetSender(auth.NewPasswordResetMailer(transport, "Example App", "https://app.example.com/auth").Send),
)
```

With that, `POST /auth/forgot-password` mails the stored template; clear either body
and the built-in is back. The UI half of the store is written through the same
interface and served once the UI router lands.

---

## Delivery

`POST /auth/magic-link/send` and `POST /auth/sms/send` answer `{"success": true}` and
nothing else: the credential they mint cannot travel in the response body, because
handing a second factor back to whoever asked for it is no second factor at all.
`SendMagicLink` and `SendSMSCode` therefore pass it to a sender you configure.

**A sender is required to use these routes.** Without one they answer
`500 {"error": "Email not configured", "code": "EMAIL_NOT_CONFIGURED"}` and
`500 {"error": "SMS is not configured", "code": "SMS_NOT_CONFIGURED"}`, matching the
reference. Nothing is stored in that case, and `Config.validate()` does not ask for a
sender — a deployment that never calls these routes needs neither.

### Sender types

```go
type MagicLinkSender func(ctx context.Context, delivery MagicLinkDelivery) error
type SMSCodeSender   func(ctx context.Context, delivery SMSCodeDelivery) error

type MagicLinkDelivery struct {
    UserID, TenantID, Email string
    Token                   string    // plaintext; the store holds only its hash
    ExpiresAt               time.Time
}

type SMSCodeDelivery struct {
    UserID, TenantID, Phone string
    Code                    string    // plaintext; the store holds only its hash
    ExpiresAt               time.Time
}
```

Each delivery carries the one credential it has to transmit and no other user
secret — no password hash, no TOTP secret, no `User`. A sender needing more about
the recipient has `UserID` and `TenantID` to read it back with.

A sender that returns an error fails the route with a generic `500` (no code, no
detail — a transport failure must not describe itself to the caller) and leaves the
stored credential in place, which is what the reference does: an undelivered token
is unguessable and expires on its own.

### Built-in senders

```go
mailer, err := auth.NewGatewayMailerTransport(auth.MailerConfig{
    Endpoint: "https://mail.example.com/send",
    APIKey:   apiKey,
    From:     "noreply@example.com",
    FromName: "Example App",
})
if err != nil {
    log.Fatal(err) // empty or non-absolute endpoint
}

a, err := auth.New(
    auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
        mailer,
        "Example App",                       // greets the recipient in the template
        "https://app.example.com/auth",      // link base; see MagicLinkURL
    ).Send),
    auth.WithSMSCodeSender(auth.SMSTransportSender(
        auth.NewHTTPSMSTransport("https://sms.example.com/send", apiKey, user, pass),
    )),
)
```

| Helper | Purpose |
|--------|---------|
| `NewMagicLinkMailer(MailerTransport, appName, baseURL) *MagicLinkMailer` | Renders the `magic-link` template (built-in or stored) and sends it, HTML and text; `.Locale` selects `en` (default) or `it` |
| `NewPasswordResetMailer(…)`, `NewEmailVerificationMailer(…)`, `NewEmailChangeMailer(…)` | The same shape for `password-reset`, `verify-email` and — as the reference does on `/change-email/request` — `verify-email` again under the confirmation link; use through `.Send` with `WithPasswordResetSender`, `WithEmailVerificationSender`, `WithEmailChangeSender` |
| `NewEmailChangedMailer(MailerTransport, appName) *EmailChangedMailer` | Renders the `email-changed` template with the new address and mails it to the old one; use through `.Send` with `WithEmailChangedSender` — see [The email-changed notice](#the-email-changed-notice) |
| `MagicLinkURL(base, token) string` | The link shape the verify route and every family client expect: `<base>/magic-link/verify?token=<token>` |
| `PasswordResetURL`, `EmailVerificationURL`, `EmailChangeConfirmURL(base, token) string` | Likewise `<base>/reset-password?token=…`, `<base>/verify-email?token=…`, `<base>/change-email/confirm?token=…` |
| `SMSTransportSender(SMSTransport) SMSCodeSender` | Adapts a transport, formatting the code with `SMSCodeMessage` |
| `SMSCodeMessage(code) string` | The family's handset text: `Your verification code is: <code>` |
| `NewGatewayMailerTransport(MailerConfig) (MailerTransport, error)` | `POST` mail gateway with the reference's JSON body and `X-API-Key` — see [Mail gateway contract](#mail-gateway-contract) |
| `NewHTTPSMSTransport(endpoint, apiKey, username, password) *HTTPSMSTransport` | `GET` gateway with credentials as query parameters and `X-API-Key` — see the caveat below |
| `NewDeliveryWebhook(url, secret) (*DeliveryWebhook, error)` | One sender for every seam, over HTTP — see [Delivery webhook](#delivery-webhook) |

```go
type SMSTransport interface {
    Send(ctx context.Context, phone, message string) error
}
```

> **`HTTPSMSTransport` puts the gateway credentials in the URL.** That is the request
> the rest of this family sends, so an existing gateway keeps working, but query
> strings reach access logs and proxies. The fix belongs at the gateway; until then,
> `WithSMSCodeSender` takes any sender, so a deployment whose provider accepts a
> safer shape supplies its own transport and never constructs this one.

### The email-changed notice

`POST /auth/change-email/confirm` applies the pending address, clears the token and
then mails the **old** address a notice — the reference's
`config.email.sendEmailChanged(oldEmail, newEmail)` (`auth.router.ts:1056-1066`,
`auth-config.model.ts:252-257`). The sender is optional and carries no credential:

```go
type EmailChangedSender func(ctx context.Context, delivery EmailChangedDelivery) error

type EmailChangedDelivery struct {
    UserID   string `json:"userId"`
    TenantID string `json:"tenantId"`
    OldEmail string `json:"oldEmail"` // the recipient: the address the account had until now
    NewEmail string `json:"newEmail"` // what the notice reports
    Lang     string `json:"lang"`     // "" from the route — the reference passes no language on confirm
}
```

Two things differ from the token senders above. There is no link, so
`NewEmailChangedMailer(transport, appName)` takes no base URL; and a failing sender
answers the generic `500` **with the change already applied** — the reference's call
sits inside the route's `try` block after `updateEmail`, so a throwing mailer reaches
`handleError` (`:1068-1069`) and nothing is rolled back. That is reproduced, not
softened: the token is spent and the address has moved when the 500 goes out.
Without a sender the route mails nothing and answers `200`, like the three token
routes. `ConfirmEmailChangeInput.Lang` exists for a caller driving the service
directly; the adapters leave it empty, as the reference's route reads only `token`.

### Mail gateway contract

`NewGatewayMailerTransport` sends exactly what the reference's built-in mailer sends
(`awesome-node-auth` `src/services/mailer.service.ts:261-291`; payload
`mailer.service.ts:133-141`; config shape `src/models/auth-config.model.ts:19-36`):

```http
POST {endpoint}
Content-Type: application/json
X-API-Key: {apiKey}

{"to": "…", "subject": "…", "html": "…", "text": "…", "from": "…", "fromName": "…", "provider": "…"}
```

- The endpoint's own path and query are kept, and the header is sent even when the
  key is blank — the reference always sets it.
- `to`, `subject`, `html`, `text` and `from` are always present. `fromName` and
  `provider` are optional in the reference and are absent, not blank, when unset.
- `html` is `MailMessage.Body` when `IsHTML` is set and `text` is `MailMessage.Text`;
  an empty `Text` sends the HTML as the text, as the reference's `sendCustom` does
  (`text ?? html`, `mailer.service.ts:246`). A plain-text `Body` goes out as `text`
  with an empty `html` — the reference has no text-only path.
- Only a `2xx` is delivered (`mailer.service.ts:280-284`). Anything else fails the
  send with an error that names the status and nothing else: the response body is
  discarded unread and the API key never appears in an error.
- The request is bounded by a 10-second client unless `MailerConfig.Client` is set.

`MailerConfig` carries the reference's key names as JSON tags, so a deployment that
already holds an `email.mailer` block for the reference can decode it and hand it
over. `DefaultLang` is carried but not read by the transport: which template set a
mail is rendered from is the mailers' `Locale`.

The older `HTTPMailerTransport` (0.3.0) sends a different body under
`X-Mailer-Secret` and is deprecated; it keeps working for gateways built against it.

### Delivery webhook

`DeliveryWebhook` is one sender for all five seams. Instead of rendering a template
and handing mail to a transport, it `POST`s the delivery itself — credential
included — to a URL you own, and whatever answers there decides how the message
reaches the recipient. It exists for a transport that is neither mail nor SMS, or
that is not reachable from this process; the consumer's `email.deliveryWebhook.url`
knob points at it.

```go
hook, err := auth.NewDeliveryWebhook("https://hooks.example.com/auth-delivery", secret)
a, err := auth.New(
    auth.WithMagicLinkSender(hook.SendMagicLink),
    auth.WithPasswordResetSender(hook.SendPasswordReset),
    auth.WithEmailVerificationSender(hook.SendEmailVerification),
    auth.WithEmailChangeSender(hook.SendEmailChange),
    auth.WithSMSCodeSender(hook.SendSMSCode),
)
```

```go
type DeliveryWebhook struct {
    URL     string        // absolute http(s) URL; NewDeliveryWebhook validates it
    Secret  string        // signs the body when set; never sent
    Timeout time.Duration // per request, through ctx; NewDeliveryWebhook sets 5s
    Client  *http.Client  // nil = http.DefaultClient
}
```

> **This request shape is this port's own.** The reference's send callbacks
> (`config.email.sendMagicLink`, `sendPasswordReset`, …) are in-process functions
> that never cross HTTP, so there is no reference wire to reproduce: the body below
> is an invention of this port. The envelope — headers and signature — is borrowed
> from the family's outbound-webhook convention
> (`src/tools/webhook-sender.ts:24-33`, `54-56`), so a receiver that already
> verifies the tools router's webhooks verifies these the same way.

One request per delivery: `POST <URL>` with `Content-Type: application/json` and

| Header | Value |
|--------|-------|
| `X-Webhook-Event` | `delivery.<kind>` — `delivery.magic-link`, `delivery.sms-code`, … |
| `X-Webhook-Delivery` | a fresh UUID per request |
| `X-Webhook-Timestamp` | when it was sent: ISO 8601, UTC, milliseconds — `2026-09-11T10:00:00.000Z` |
| `X-Webhook-Signature` | `sha256=<hex HMAC-SHA256 of the raw body, keyed by Secret>` — only when `Secret` is set |

The body is `{"kind": "<kind>", "delivery": {…}}`, where `delivery` is the matching
delivery struct in camelCase, fields in this order:

| `kind` | `delivery` |
|--------|------------|
| `magic-link` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `password-reset` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `email-verification` | `userId`, `tenantId`, `email`, `token`, `expiresAt` |
| `email-change` | `userId`, `tenantId`, `newEmail`, `token`, `expiresAt` — addressed to the new mailbox |
| `sms-code` | `userId`, `tenantId`, `phone`, `code`, `expiresAt` |

The four link-carrying kinds also carry `linkBase` and `lang` when the request
resolved them (see "Per-request link base and language" below); both are omitted
when empty, so a receiver must not rely on their presence.

```json
{"kind":"magic-link","delivery":{"userId":"usr_…","tenantId":"t1","email":"ada@example.com","token":"…","expiresAt":"2026-09-11T10:15:00Z"}}
```

`token` and `code` are the plaintext credential — the store holds only its hash — so
the receiver is trusted exactly as a sender callback is: set a `Secret` and verify
the signature before acting, with `VerifyWebhookSignature(secret, rawBody,
r.Header.Get("X-Webhook-Signature"))` in Go. `expiresAt` is RFC 3339. The
`DeliveryKind*` constants and `DeliveryWebhookRequest{Kind string; Delivery
json.RawMessage}` name the same vocabulary for a receiver written in Go: decode the
envelope, switch on `Kind`, unmarshal `Delivery` into the matching struct.

Any `2xx` answer is delivered. Anything else, a transport failure or the timeout is
an error, and the route then behaves per the seam it was wired to — the generic
`500` on `/magic-link/send`, `/sms/send`, `/send-verification-email` and
`/change-email/request`; the unconditional `200` on `/forgot-password`. There is no
retry: a route is waiting on the answer, and the stored credential expires on its
own. The error names the kind, the status and, for mail, the recipient's domain; it
never carries the token, the code, the full address or the secret, because it is
logged and inspected further than the request ever travels.

### Per-request link base and language

The reference builds every emailed link from the request that asked for it, and
so do the four adapters. Each delivery that carries a link — `MagicLinkDelivery`,
`PasswordResetDelivery`, `EmailVerificationDelivery`, `EmailChangeDelivery` —
has two extra members:

```go
LinkBase string // e.g. "https://app.example.com/auth"; "" when no site URL is configured
Lang     string // the request's emailLang body field, untouched; "" when omitted
```

`LinkBase` is resolved in three steps, each a transcription of the reference:

| Step | Export | Reference |
|------|--------|-----------|
| The site URL for the request: the `Origin` header if allowlisted, else the `Referer`'s origin if allowlisted, else the default | `(*Auth).ResolveSiteURL(r *http.Request) string` | `resolveSiteUrl`, `auth.router.ts:233-246` |
| The allowlist: `Config.SiteURLs` then `OAuthWiring.AllowedOrigins`, deduplicated in order; the default: `SiteURLs[0]`, or `OAuthWiring.SiteURL` when that is set | `Config.SiteURLs`, `WithSiteURLs(urls ...string)` | `buildAllowedOrigins` `:213-219`, `getDefaultSiteUrl` `:202-206` |
| The base under that site URL: `<siteURL><prefix>`, or `<siteURL><prefix>/ui` with `HTTPConfig.UIEnabled` | `(HTTPConfig).LinkBase(siteURL) string`; the general form is `(HTTPConfig).UILink(siteURL, path) string` | `buildUiLink` `:261-271`, `magic-link.strategy.ts:25-27` |

```go
a, err := auth.New(
    auth.WithSiteURLs("https://www.example.com", "https://app.example.com"),
    auth.WithPasswordResetSender(auth.NewPasswordResetMailer(transport, "Example App", "https://www.example.com/auth").Send),
)
cfg := auth.DefaultHTTPConfig()
cfg.UIEnabled = true // links point at <site>/auth/ui/… instead of <site>/auth/…
nethttp.MountWithConfig(mux, a, cfg)
```

With that, a `POST /auth/forgot-password` carrying `Origin: https://app.example.com`
mails `https://app.example.com/auth/ui/reset-password?token=…`; one from an origin
that is not in the list, or with no `Origin` at all, mails the link under
`https://www.example.com`. Matching is exact — no trailing-slash or case
normalisation — as the reference's `includes` is. The same allowlist and default
serve the OAuth redirect and the `/link-request` link, so `OAuthWiring.SiteURL`
becomes optional: leave it empty and the OAuth routes fall back to `SiteURLs[0]`.

**Precedence in the built-in mailers.** A delivery's `LinkBase` wins over the
mailer's `BaseURL`; its `Lang` wins over the mailer's `Locale` when it is `it` or
`en`, and anything else — including an omitted `emailLang` — defers to `Locale`
(`resolveLang`, `mailer.service.ts:255-259`). With no `SiteURLs` configured the
adapters set no `LinkBase`, so a deployment built on a static `BaseURL` keeps
mailing exactly the links it did. A custom sender reads the two members directly:
`auth.PasswordResetURL(d.LinkBase, d.Token)` is the reference's link when
`LinkBase` is set.

The service inputs carry the same two members (`ForgotPasswordInput`,
`EmailVerificationInput`, `ChangeEmailRequestInput`, `MagicLinkSendInput`) and
copy them onto the delivery untouched; a caller driving the service directly
supplies them or leaves them empty.

---

## OIDC IDP

The `IDP` type turns awesome-go-auth into a full OIDC Identity Provider.

### `NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error)`

Resolves the signing key (`IDPConfig.Signer`, or an ephemeral RSA-2048 key with
a one-time warning), the `kid` and the code store, and refuses a signer whose
public key is not RSA.

### `IDPConfig`

```go
type IDPConfig struct {
    Issuer          string
    AccessTokenTTL  time.Duration // IdP pair: 0 → 30 days
    IDTokenTTL      time.Duration // 0 → 1 hour
    Signer          crypto.Signer // nil → ephemeral RSA-2048 + one warning
    KeyID           string        // "" → DefaultIDPKeyID, "provisioner-key-1"
    PublicKeys      []JWK         // further keys published after Signer's
    RefreshTokenTTL time.Duration // IdP pair: 0 → 90 days
    Logger          func(format string, args ...any) // nil → the Service's
    Codes           AuthCodeStore // nil → NewMemoryAuthCodeStore()
    CodeTTL         time.Duration // 0 → 5 minutes
}
```

### Signing key

`Signer` is any `crypto.Signer` whose public key is RSA. The reference's
configuration is a PEM private key (`idProvider.privateKey`,
`token.service.ts:47`); here that is

```go
key, err := auth.ParseRSAPrivateKeyPEM(os.Getenv("IDP_PRIVATE_KEY")) // PKCS#8 or PKCS#1
idp, err := auth.NewIDP(auth.IDPConfig{Signer: key, KeyID: "prod-2026-09"}, svc, clients...)
```

A signer that keeps the private key elsewhere — AWS KMS, an HSM, another
process — plugs in the same way. `BuildRS256JWT` asks it for exactly one thing
per token: `Sign(rand.Reader, digest, crypto.SHA256)` with the 32-byte SHA-256
of `base64url(header).base64url(claims)`, and uses the bytes it returns as the
signature. RS256 is RSASSA-PKCS1 v1.5 over SHA-256, so the signer must answer
with that (KMS: `RSASSA_PKCS1_V1_5_SHA_256` on a `DIGEST` request), and its
`Public()` must return the matching `*rsa.PublicKey`, which is what the JWKS
document publishes.

With no `Signer` the IDP generates an RSA-2048 key in `NewIDP` and logs, once,
the reference's warning (`token.service.ts:52-57`): `auth: IdP mode: no Signer
configured — auto-generating an ephemeral RSA keypair. All tokens will be
invalidated on restart. Set IDPConfig.Signer in production.` The warning goes
to `IDPConfig.Logger`, else to the `Config.Logger` of the Service. Every token
becomes unverifiable on restart and two processes never share a key:
development only.

`KeyID` is the `kid` in the header of every signed token and in the JWKS entry
for `Signer`; empty means `DefaultIDPKeyID`, the reference's constant
`provisioner-key-1` (`token.service.ts:78`). `PublicKeys` are further `JWK`s
published after the signer's, unchanged — the previous key during a rotation,
so that tokens it signed stay verifiable until they expire. Nothing signs with
them or checks them.

### JWKS types and RS256 builders

```go
type JWK struct {
    Kty string `json:"kty"` // "RSA"
    Use string `json:"use"` // "sig"
    Alg string `json:"alg"` // "RS256"
    Kid string `json:"kid"`
    N   string `json:"n"`   // unpadded base64url, big-endian
    E   string `json:"e"`
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

func NewRSAJWK(pub *rsa.PublicKey, kid string) (JWK, error)
func (idp *IDP) JWKS() JWKS
func ParseRSAPrivateKeyPEM(pemText string) (*rsa.PrivateKey, error)
func BuildRS256JWT(signer crypto.Signer, kid string, claims map[string]any) (string, error)
```

`JWK` is the reference's interface (`jwks.service.ts:5-12`), `NewRSAJWK` its
`publicKeyToJwk` (`:168-179`; a nil key, or one with no modulus, is an error
rather than a panic, since the key was obtained elsewhere), and `JWKS()` its
`buildJwksDocument` (`:184-186`) followed by `PublicKeys`:
`{"keys":[<signer key>, <PublicKeys>...]}`, which is what the `jwks` endpoint
serves. `BuildRS256JWT` is the JWS compact serialisation with header
`{"alg":"RS256","typ":"JWT","kid":<kid>}`, usable on its own by a host that
signs something else with the same key; like `NewIDP`, it refuses a signer
whose `Public()` is not an `*rsa.PublicKey` before asking it to sign.

### `(*IDP).IssueIdPTokenPair(ctx context.Context, user User) (AuthTokens, error)`

The reference's `generateIdProviderTokenPair` (`token.service.ts:73-95`): an
RS256 access token and an RS256 refresh token under `KeyID`, both carrying the
same payload — the six base claims (`sub`, `email`, `role`, `loginProvider`,
`isEmailVerified`, `isTotpEnabled`) with `Config.BuildTokenClaims` spread over
them, the hook's `iat`, `exp` and `kid` dropped, `iss` from `IDPConfig.Issuer`
when that is set and otherwise absent — and differing only in lifetime:
`AccessTokenTTL`, 30 days by default; `RefreshTokenTTL`, 90 days by default.
`ExpiresIn` is the access lifetime.

The reference resolves the refresh lifetime in three steps —
`idProvider.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'`
(`token.service.ts:91`) — and the middle one is not reproduced:
`IDPConfig.RefreshTokenTTL` never falls back to `Config.RefreshTokenTTL`.
`Config.RefreshTokenTTL` is always set here (`DefaultConfig` fills it and
`validate` requires it), so honouring it would make the 90-day default
unreachable and tie the IdP pair silently to the session lifetime.

It is a host-level API, exactly as in the reference, where nothing calls
`generateIdProviderTokenPair` (reference-issues N35): `/login`, `/refresh` and
the OIDC `token` endpoint keep issuing the HS256 session pair, and constructing
an `IDP` changes nothing about them. Accordingly the `token` endpoint reports
`expires_in` as the lifetime of the access token it returns,
`Config.AccessTokenTTL`; `IDPConfig.AccessTokenTTL` governs only the IdP pair.
No session is created and no `sid` is written, so an IdP pair cannot be revoked
before it expires. Which pair the `token` endpoint returns is a pending design
decision (upstream plan D-15).

### Authorization-code storage

Codes issued by `authorize` and redeemed by `token` live in an `AuthCodeStore`:

```go
type AuthCode struct {
    CodeHash                           string // hashToken of the code the client holds
    UserID, TenantID, ClientID, Nonce  string
    RedirectURI                        string
    CodeChallenge, CodeChallengeMethod string // recorded, not yet verified
    Scope                              string
    ExpiresAt                          time.Time
}

type AuthCodeStore interface {
    SaveCode(ctx context.Context, code AuthCode) error
    ConsumeCode(ctx context.Context, codeHash string) (AuthCode, error)
}
```

The contract, in full in the `AuthCodeStore` doc comment:

- The store never sees the code itself, only `hashToken(code)`; a leaked table
  cannot be replayed at `token`.
- `ConsumeCode` is destructive and single-use: it returns a record exactly once
  and `ErrInvalidCode` on every later call for the same hash, including
  concurrent ones. A shared implementation must make this atomic (conditional
  delete, row lock, `DEL`-and-check), not a read followed by a delete.
- An expired record is absent: `ConsumeCode` returns `ErrInvalidCode` and may
  drop it. `token` re-checks `ExpiresAt` regardless.

`IDPConfig.Codes` left nil selects `NewMemoryAuthCodeStore()`, an in-process
map behind a mutex that sweeps expired entries on each save. That is correct
only while `authorize` and `token` are served by the same process. **A
serverless runtime or any deployment with more than one instance must supply a
shared `AuthCodeStore`** (Redis, a database table, DynamoDB with a conditional
delete) or `token` answers `invalid_grant` for every code minted by a sibling
process.

`token` also refuses a code redeemed by a `client_id` other than the one it was
issued to, and consumes it in the process.

### `IDPClient`

```go
type IDPClient struct {
    ClientID, ClientSecret string
    RedirectURIs           []string
    Name                   string
}
```

### `(*IDP).RegisterHandlers(mux *http.ServeMux, basePath string)`

Mounts these endpoints under `basePath`:

| Path | Description |
|------|-------------|
| `.well-known/openid-configuration` | OIDC discovery document |
| `jwks` | `JWKS()` as JSON: the signer's key first, then `PublicKeys` |
| `authorize` | Authorization endpoint (GET=login form, POST=credential check) |
| `token` | Token exchange (authorization_code grant) |
| `userinfo` | Bearer-token-protected user profile |

ID tokens and IdP token pairs are RS256-signed JWTs built entirely from the
standard library through `BuildRS256JWT`, under `IDPConfig.Signer` and `KeyID`.

---

## MCP Server (out of parity scope)

### `NewMCPServer(authSvc *Service) *MCPServer`

### `(*MCPServer).ServeHTTP(w, r)`

Implements `http.Handler`. Handles JSON-RPC 2.0 POST requests.

**Supported methods:**
- `tools/list` — returns available tool descriptors
- `tools/call` — executes a named tool

**Available tools:**
| Tool | Description |
|------|-------------|
| `auth_get_config` | Returns issuer, TTLs, feature flags. `require_2fa` is the static `Config.Require2FA`; `require_2fa_effective` is the policy `/2fa/disable` enforces (that term OR the stored `require2FA`), omitted when the settings store cannot be read |
| `auth_register` | Registers a new user |
| `auth_login` | Authenticates a user |
| `auth_create_tenant` | Creates a tenant |
| `auth_create_role` | Creates a role with permissions |

---

## OpenAPI

### `GenerateOpenAPISpec(info OpenAPIInfo) map[string]any`

Returns an OpenAPI 3.0.3 spec as a `map[string]any` (JSON-serializable).

```go
type OpenAPIInfo struct {
    Title, Description, Version, ServerURL string
    APIPrefix string // must match the mount; empty means DefaultAPIPrefix ("/auth")
}
```

Serve as JSON:
```go
spec := auth.GenerateOpenAPISpec(auth.OpenAPIInfo{
    Title:     "My API",
    ServerURL: "https://api.example.com",
    APIPrefix: auth.DefaultAPIPrefix,
})
json.NewEncoder(w).Encode(spec)
```

The spec describes exactly the operations the adapters mount — the current
envelope, the per-route error catalog entries, the `X-Auth-Strategy` and
`X-CSRF-Token` headers, and both the bearer and cookie security schemes. Set
`APIPrefix` to whatever you passed to `MountWithConfig`; a mismatch documents
paths the server does not serve. The wire conformance suite replays every
documented operation against every adapter, so a route added without a spec entry
(or a spec entry with no route) fails the build.

---

## Embedded UI

All files are embedded via `//go:embed` from the `ui/` directory.

### `ServeAdminUI() http.Handler`

Serves `ui/admin.html` — a single-page admin dashboard with sections for Users, Sessions, Tenants, Roles, API Keys, Telemetry, and OpenAPI reference.

### `ServeAuthUI() http.Handler`

Serves `ui/auth.html` — a complete auth UI with Login, Register, Magic Link, Forgot Password, and TOTP forms. Integrates with `auth.js`.

### `ServeAuthJS() http.Handler`

Serves `ui/auth.js` — a ~3KB vanilla JavaScript browser SDK with no dependencies. Exposes `window.AuthSDK` with methods mirroring the Go service API.

**AuthSDK methods:**
`configure`, `storeTokens`, `clearTokens`, `getAccessToken`, `isLoggedIn`, `register`, `login`, `logout`, `refresh`, `me`, `forgotPassword`, `resetPassword`, `changePassword`, `sendMagicLink`, `verifyMagicLink`, `sendSMSCode`, `verifySMSCode`, `setupTOTP`, `verifyTOTPSetup`, `verifyTOTP`, `disableTOTP`, `sendVerificationEmail`, `verifyEmail`, `requestEmailChange`, `confirmEmailChange`, `getMetadata`, `updateMetadata`, `listSessions`, `revokeSession`, `connectSSE`

---

## API Keys

### `NewAPIKeyService(bcryptCost int) *APIKeyService`

Keys are hashed with bcrypt at `bcryptCost`; zero means `bcrypt.DefaultCost`. Pass
the same value as `Config.BcryptCost` to keep both kinds of stored secret at one
cost. `Verify` never hashes — it reads the cost out of the stored hash — so a
verify-only service may pass `0` whatever cost its keys were created at.

### `(*APIKeyService).Create(ctx, store, name, serviceID, scopes, allowedIPs, expiresAt) (rawKey string, record APIKeyRecord, err error)`

Returns the raw key (shown once) and the stored record (key is hashed with bcrypt).

### `(*APIKeyService).Verify(ctx, store, rawKey, ip, requiredScopes) (APIKeyRecord, error)`

Validates key hash, active status, expiry, IP allowlist, and required scopes.

### `APIKeyMiddleware(store APIKeyStore, requiredScopes []string) func(http.Handler) http.Handler`

HTTP middleware that reads `X-Api-Key` or `Authorization: ApiKey <key>` headers.

### `APIKeyStore` interface

```go
type APIKeyStore interface {
    Save(ctx, APIKeyRecord) error
    FindByPrefix(ctx, prefix string) (APIKeyRecord, error)
    Revoke(ctx, id string) error
    UpdateLastUsed(ctx, id string, when time.Time) error
}
```

---

## Event Bus

### `NewEventBus() *EventBus`

### `(*EventBus).Subscribe(event string, handler func(Event))`

Subscribe to a specific event name or `"*"` for all events.

### `(*EventBus).Publish(ev Event)`

Delivers the event synchronously to all matching handlers. Panics in handlers are recovered and logged.

### `Event`

```go
type Event struct {
    Name, UserID, TenantID string
    Timestamp              time.Time
    Data                   map[string]any
}
```

---

## HTTP Adapters

### `adapter/nethttp`

```go
adapt := nethttp.New(svc)
mux.HandleFunc("/auth/register", adapt.Register)
mux.Handle("/auth/me", adapt.Middleware(meHandler))
```

### `adapter/chi`

```go
adapt := chi.New(svc)
r.Post("/auth/register", adapt.Register)
r.With(adapt.RequireAuth).Get("/auth/me", adapt.Me)
```

### `adapter/gin`

```go
adapt := gin.New(svc)
r.POST("/auth/register", adapt.Register)
r.GET("/auth/me", adapt.RequireAuth(), adapt.Me)
```

### `adapter/echo`

```go
adapt := echo.New(svc)
e.POST("/auth/register", adapt.Register)
e.GET("/auth/me", adapt.Me, adapt.RequireAuth())
```

All adapters provide at minimum: `Register`, `Login`, `Refresh`, `Logout`, `Me`, `ForgotPassword`, `ResetPassword`, `SendMagicLink`, `VerifyMagicLink`, `ChangePassword`, `SetupTOTP`, `VerifyTOTP`, `ListSessions`, `RequireAuth` middleware.

---

## Security Helpers

Internal helpers (unexported) available for use within the package:

| Function | Description |
|----------|-------------|
| `newID(prefix) (string, error)` | Generates `prefix_<32hex>` ID |
| `hashPassword(password, cost) (string, error)` | bcrypt at `cost`; a zero cost means `DefaultCost` |
| `verifyPassword(password, hash) bool` | bcrypt compare |
| `hashToken(token) string` | SHA-256 hex |
| `randomToken(byteLen) (string, error)` | Base64URL random bytes |
| `randomNumericCode(length) (string, error)` | Cryptographic numeric code |
| `sign(input, secret) string` | HMAC-SHA256 base64url |
| `secureEqual(a, b) bool` | Constant-time string compare |

---

## Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidCredentials` | Wrong email/password or user not found |
| `ErrUserExists` | Email already registered in tenant |
| `ErrInvalidToken` | Token invalid, expired, or tampered |
| `ErrSessionNotFound` | Refresh token session not found |
| `ErrSessionRevoked` | Session was explicitly revoked |
| `ErrWeakPassword` | Password shorter than MinPasswordLen |
| `ErrFeatureNotSupported` | Required store interface not implemented |
| `ErrEmailNotVerified` | Login attempted before email verification |
| `ErrInvalidCode` | Wrong SMS code or TOTP code |
| `ErrTwoFactorRequired` | Login requires 2FA step |
| `ErrAlreadyExists` | Resource already exists (e.g., tenant) |
| `ErrTenantNotFound` | Tenant ID not found |
| `ErrRoleNotFound` | Role not found when adding to user |
