# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a security vulnerability, please open a [GitHub Security Advisory](https://github.com/nik2208/awesome-go-auth/security/advisories/new) or contact the maintainers directly.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 72 hours and aim to release a fix within 14 days for critical issues.

## Security Considerations

- **Secrets**: The `Config.Secret` must be at least 32 bytes of high-entropy random data. Never commit secrets to source control.
- **Token TTLs**: Access tokens should be short-lived (15 minutes recommended). Refresh tokens can be longer (7 days).
- **HTTPS**: Always serve the auth API over HTTPS in production.
- **HMAC Signatures**: Webhook signatures are HMAC-SHA256 over the raw request body, sent as `X-Webhook-Signature: sha256=<hex>`. Verify them using `VerifyWebhookSignature` before acting on a delivery. Deliveries retry, so a receiver must be idempotent — and must not key that idempotency on `X-Webhook-Delivery`, which is fresh on every attempt.
- **API Keys**: API key material is hashed with bcrypt before storage. The raw key is only returned at creation time.
- **TOTP**: TOTP secrets should be stored encrypted at rest in production databases.
- **Password Policy**: Minimum password length is configurable via `Config.MinPasswordLen`.
