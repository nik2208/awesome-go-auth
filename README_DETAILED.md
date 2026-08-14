# awesome-go-auth — Detailed API Reference

Complete reference for every public type, interface, function, and option in the library.

---

## Table of Contents

1. [Core Service](#core-service)
2. [Configuration](#configuration)
3. [Models](#models)
4. [Store Interfaces](#store-interfaces)
5. [In-Memory Stores](#in-memory-stores)
6. [Auth Functional Options](#auth-functional-options)
7. [OAuth 2.0 + Account Linking](#oauth-20--account-linking)
8. [SSE (Server-Sent Events)](#sse-server-sent-events)
9. [Webhooks](#webhooks)
10. [Telemetry](#telemetry)
11. [Mailer](#mailer)
12. [Delivery](#delivery)
13. [OIDC IDP](#oidc-idp)
14. [MCP Server (out of parity scope)](#mcp-server-out-of-parity-scope)
15. [OpenAPI](#openapi)
16. [Embedded UI](#embedded-ui)
17. [API Keys](#api-keys)
18. [Event Bus](#event-bus)
19. [HTTP Adapters](#http-adapters)
20. [Security Helpers](#security-helpers)
21. [Errors](#errors)

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
| `Me(ctx, accessToken) (User, error)` | Resolve token to user profile |
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
    BuildTokenClaims      func(ctx, User) (map[string]any, error)
    SendMagicLink         MagicLinkSender               // required by POST /auth/magic-link/send
    SendSMSCode           SMSCodeSender                 // required by POST /auth/sms/send
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
- `POST /send-verification-email` and `GET /verify-email` are mounted, but nothing
  delivers the token they mint: the routes persist it and answer
  `{"success": true}`, and this port has no mail sender wired into `Config`. Until
  it has one, a `strict` deployment has to send the mail itself from the token
  `SendVerificationEmailToken` returns.

### `DefaultConfig(secret string) Config`

Returns a `Config` with sensible defaults.

### `(Config).validate() error`

Called internally; ensures secret length >= 32 and TTLs > 0.

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
| `IsEmailVerified` | `bool` | |
| `Require2FA` | `bool` | Per-user 2FA requirement |
| `IsTOTPEnabled` | `bool` | |
| `TOTPSecret` | `string` | Base32 encoded |
| `Metadata` | `map[string]any` | Enriched by MetadataStore |
| `Roles` | `[]string` | Enriched by RBACStore |
| `Permissions` | `[]string` | Enriched by RBACStore |
| `Tenants` | `[]Tenant` | Enriched by TenantStore |
| `CustomClaims` | `map[string]any` | From BuildTokenClaims hook |
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
| `SessionLookupStore` | `GetSessionByID` | SessionCheckOn=allcalls (`Me`) |

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
| `WithTokenClaimsBuilder(func)` | Custom JWT claims |
| `WithMagicLinkSender(MagicLinkSender)` | Deliver magic links — see [Delivery](#delivery) |
| `WithSMSCodeSender(SMSCodeSender)` | Deliver SMS codes — see [Delivery](#delivery) |
| `WithLogger(func)` | Logging callback |

Pass to `NewService(...)` as `ServiceOption`:

| Option | Description |
|--------|-------------|
| `WithMetadataStore(UserMetadataStore)` | |
| `WithRolesPermissionsStore(RolesPermissionsStore)` | |
| `WithTenantStore(TenantStore)` | |

---

## OAuth 2.0 + Account Linking

### `OAuthProvider`

```go
type OAuthProvider struct {
    Name, ClientID, ClientSecret, RedirectURL string
    AuthURL, TokenURL, UserInfoURL            string
    Scopes                                    []string
}
```

### `NewOAuthService(providers ...OAuthProvider) *OAuthService`

### `GoogleProvider(clientID, clientSecret, redirectURL) OAuthProvider`
### `GitHubProvider(clientID, clientSecret, redirectURL) OAuthProvider`

### `(*OAuthService).AuthorizeURL(provider, state) (string, error)`

Returns the OAuth2 authorization URL to redirect the user to.

### `(*OAuthService).ExchangeCode(ctx, provider, code) (OAuthUserInfo, error)`

Exchanges an authorization code for normalized user info.

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
    Raw map[string]any
}
```

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
```

### `NewHTTPMailerTransport(endpointURL, secret string) *HTTPMailerTransport`

POSTs a JSON-encoded `MailMessage` to any HTTP endpoint. Sets `X-Mailer-Secret` header if secret is provided.

### `NewMailTemplater(appName string) *MailTemplater`

Returns a templater with built-in **English** and **Italian** templates for:
- `reset_password`
- `magic_link`
- `verify_email`
- `email_change`

### `(*MailTemplater).Render(locale, name string, data MailTemplateData) (subject, body string, err error)`

Falls back to `en/` templates when locale template is not found.

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
a, err := auth.New(
    auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
        auth.NewHTTPMailerTransport("https://mail.example.com/send", secret),
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
| `NewMagicLinkMailer(MailerTransport, appName, baseURL) *MagicLinkMailer` | Renders the built-in `magic_link` template and sends it; `.Locale` selects `en` (default) or `it` |
| `MagicLinkURL(base, token) string` | The link shape the verify route and every family client expect: `<base>/magic-link/verify?token=<token>` |
| `SMSTransportSender(SMSTransport) SMSCodeSender` | Adapts a transport, formatting the code with `SMSCodeMessage` |
| `SMSCodeMessage(code) string` | The family's handset text: `Your verification code is: <code>` |
| `NewHTTPSMSTransport(endpoint, apiKey, username, password) *HTTPSMSTransport` | `GET` gateway with credentials as query parameters and `X-API-Key` — see the caveat below |

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

### Locale

`MagicLinkMailer.Locale` is static. The reference has a per-request `emailLang` body
field on `/magic-link/send`; the port's send routes do not carry it, so threading a
locale off the wire is a request-shape change and is left to the template
configuration work.

---

## OIDC IDP

The `IDP` type turns awesome-go-auth into a full OIDC Identity Provider.

### `NewIDP(cfg IDPConfig, authSvc *Service, clients ...IDPClient) (*IDP, error)`

Generates a 2048-bit RSA key pair at startup.

### `IDPConfig`

```go
type IDPConfig struct {
    Issuer         string
    AccessTokenTTL time.Duration
    IDTokenTTL     time.Duration
}
```

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
| `jwks` | RSA public key as JWK Set |
| `authorize` | Authorization endpoint (GET=login form, POST=credential check) |
| `token` | Token exchange (authorization_code grant) |
| `userinfo` | Bearer-token-protected user profile |

ID tokens are RS256-signed JWTs built entirely from the standard library.

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
| `auth_get_config` | Returns issuer, TTLs, feature flags |
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
