# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.1.0] - Initial Release

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
