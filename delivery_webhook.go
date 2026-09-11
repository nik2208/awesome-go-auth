package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file adds one more ready-made sender to the delivery seam of delivery.go
// and delivery_password_email.go: an HTTP webhook. Where MagicLinkMailer and the
// TokenMailers render a template and hand mail to a transport, DeliveryWebhook
// renders nothing. It POSTs the delivery itself — credential included — to a URL
// the deployment owns, and whatever answers there decides how the message
// reaches the recipient. It exists for a transport that is neither mail nor SMS,
// or that is not reachable from this process: the consumer's
// email.deliveryWebhook.url knob (config-schema.md §1.5, §3.8, "replaces the
// reference's send-callback functions for exotic transports") is wired to it.
//
// The request has no reference wire. The reference's per-flow callbacks —
// config.email.sendMagicLink, sendPasswordReset, sendVerificationEmail and the
// rest (auth-config.model.ts:228-257) — are in-process functions that never
// cross HTTP, so there is nothing to transcribe; the body shape below is this
// port's own (upstream plan, decision D-3) and README_DETAILED.md says so. What
// is borrowed is the envelope. The headers and the signature are the family's
// outbound-webhook convention, taken from the reference's WebhookSender
// (src/tools/webhook-sender.ts:24-33 for the four headers, :54-56 for the
// "sha256=<hex>" HMAC form), so a receiver already written for the tools
// router's webhooks verifies these the same way.
//
// One request, one delivery, no retry. The reference's sender retries with
// back-off because its events are fire-and-forget; a delivery is not. The route
// that minted the credential is waiting on the answer, and each seam already
// has a failure contract for a sender that errors — the generic 500, or the
// unconditional 200 on /forgot-password — so the webhook reports and the route
// decides, exactly as a callback would.

// Delivery kinds: the value of the request's "kind" field and, prefixed with
// "delivery.", of the X-Webhook-Event header.
const (
	DeliveryKindMagicLink         = "magic-link"
	DeliveryKindPasswordReset     = "password-reset"
	DeliveryKindEmailVerification = "email-verification"
	DeliveryKindEmailChange       = "email-change"
	DeliveryKindSMSCode           = "sms-code"
)

// DeliveryWebhookRequest is the body DeliveryWebhook posts. Delivery is the
// delivery struct that matches Kind — MagicLinkDelivery for
// DeliveryKindMagicLink, PasswordResetDelivery for DeliveryKindPasswordReset,
// EmailVerificationDelivery, EmailChangeDelivery, SMSCodeDelivery — encoded with
// its JSON tags, so a receiver written in Go decodes Kind, switches on it and
// unmarshals Delivery into the very type this package sent.
type DeliveryWebhookRequest struct {
	Kind     string          `json:"kind"`
	Delivery json.RawMessage `json:"delivery"`
}

// The envelope headers, named as the reference names them
// (webhook-sender.ts:24-33).
const (
	webhookEventHeader     = "X-Webhook-Event"
	webhookDeliveryHeader  = "X-Webhook-Delivery"
	webhookTimestampHeader = "X-Webhook-Timestamp"
	webhookSignatureHeader = "X-Webhook-Signature"
)

// webhookTimestampLayout is Date.prototype.toISOString's output — UTC, always
// three fractional digits, a literal Z — which is what the reference puts in
// X-Webhook-Timestamp.
const webhookTimestampLayout = "2006-01-02T15:04:05.000Z07:00"

// defaultDeliveryWebhookTimeout bounds a request whose DeliveryWebhook.Timeout
// is unset. A route is waiting on the answer, so it is short.
const defaultDeliveryWebhookTimeout = 5 * time.Second

// DeliveryWebhook is a sender for every delivery kind at once. Its five Send
// methods have the five sender signatures, so one value serves every seam:
//
//	hook, err := auth.NewDeliveryWebhook("https://hooks.example.com/auth-delivery", secret)
//	a, err := auth.New(
//		auth.WithMagicLinkSender(hook.SendMagicLink),
//		auth.WithPasswordResetSender(hook.SendPasswordReset),
//		auth.WithEmailVerificationSender(hook.SendEmailVerification),
//		auth.WithEmailChangeSender(hook.SendEmailChange),
//		auth.WithSMSCodeSender(hook.SendSMSCode),
//	)
//
// Each call POSTs one request to URL with Content-Type: application/json, the
// body {"kind": "<kind>", "delivery": {…}} (DeliveryWebhookRequest), and the
// headers
//
//	X-Webhook-Event:     delivery.<kind>
//	X-Webhook-Delivery:  <a fresh UUID per request>
//	X-Webhook-Timestamp: <ISO 8601 UTC with milliseconds>
//	X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the body>   (only when Secret is set)
//
// Any 2xx answer is delivered. Anything else, a transport failure or the timeout
// is an error, which the route the sender is wired to handles per its existing
// contract. The error names the kind, the status and, for mail, the recipient's
// domain; it never carries the token, the code, the full address or the secret,
// because an error travels further than the request does — it is logged, and it
// is host code's to inspect.
//
// The zero value is usable once URL is set; NewDeliveryWebhook additionally
// validates the URL and fills in the default timeout.
type DeliveryWebhook struct {
	// URL is the absolute http(s) address every request goes to.
	URL string
	// Secret keys the signature. Empty sends no X-Webhook-Signature header at
	// all, as the reference's sender does without one (webhook-sender.ts:31-33).
	// It is never sent.
	Secret string
	// Timeout bounds one request, connect to last byte, through the request
	// context — a shorter deadline already on ctx wins. Zero or negative means
	// 5 seconds.
	Timeout time.Duration
	// Client issues the requests. Nil means http.DefaultClient. A Client with a
	// Timeout of its own is bounded by both.
	Client *http.Client
}

// NewDeliveryWebhook builds a DeliveryWebhook for an absolute http(s) URL with
// the default 5 second timeout. secret may be empty, in which case requests are
// unsigned.
func NewDeliveryWebhook(rawURL, secret string) (*DeliveryWebhook, error) {
	if err := validateDeliveryWebhookURL(rawURL); err != nil {
		return nil, err
	}
	return &DeliveryWebhook{URL: rawURL, Secret: secret, Timeout: defaultDeliveryWebhookTimeout}, nil
}

func validateDeliveryWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("auth: delivery webhook url: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("auth: delivery webhook url %q: want an absolute http(s) URL", rawURL)
	}
	return nil
}

// SendMagicLink posts a magic-link delivery. Its signature is MagicLinkSender's.
func (w *DeliveryWebhook) SendMagicLink(ctx context.Context, delivery MagicLinkDelivery) error {
	return w.post(ctx, DeliveryKindMagicLink, delivery, emailDomain(delivery.Email))
}

// SendPasswordReset posts a password-reset delivery. Its signature is
// PasswordResetSender's.
func (w *DeliveryWebhook) SendPasswordReset(ctx context.Context, delivery PasswordResetDelivery) error {
	return w.post(ctx, DeliveryKindPasswordReset, delivery, emailDomain(delivery.Email))
}

// SendEmailVerification posts an email-verification delivery. Its signature is
// EmailVerificationSender's.
func (w *DeliveryWebhook) SendEmailVerification(ctx context.Context, delivery EmailVerificationDelivery) error {
	return w.post(ctx, DeliveryKindEmailVerification, delivery, emailDomain(delivery.Email))
}

// SendEmailChange posts an email-change delivery, addressed to the new mailbox.
// Its signature is EmailChangeSender's.
func (w *DeliveryWebhook) SendEmailChange(ctx context.Context, delivery EmailChangeDelivery) error {
	return w.post(ctx, DeliveryKindEmailChange, delivery, emailDomain(delivery.NewEmail))
}

// SendSMSCode posts an SMS-code delivery. Its signature is SMSCodeSender's.
func (w *DeliveryWebhook) SendSMSCode(ctx context.Context, delivery SMSCodeDelivery) error {
	// A phone number has no part that is safe to name, so the error carries no
	// recipient at all.
	return w.post(ctx, DeliveryKindSMSCode, delivery, "")
}

// post sends one delivery. recipient is the only thing about the addressee an
// error may carry — "@" plus the domain for mail, nothing for a phone number.
// The delivery itself never reaches an error string: not the token or code, not
// the full address. Nor does the response body, which a receiver may well fill
// with an echo of the request.
func (w *DeliveryWebhook) post(ctx context.Context, kind string, delivery any, recipient string) error {
	if w == nil {
		return errors.New("auth: delivery webhook is nil")
	}
	where := "auth: delivery webhook " + kind
	if recipient != "" {
		where += " to " + recipient
	}

	raw, err := json.Marshal(delivery)
	if err != nil {
		return fmt.Errorf("%s: encode: %w", where, err)
	}
	body, err := json.Marshal(DeliveryWebhookRequest{Kind: kind, Delivery: raw})
	if err != nil {
		return fmt.Errorf("%s: encode: %w", where, err)
	}
	deliveryID, err := newUUIDv4()
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	timeout := w.Timeout
	if timeout <= 0 {
		timeout = defaultDeliveryWebhookTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhookEventHeader, "delivery."+kind)
	req.Header.Set(webhookDeliveryHeader, deliveryID)
	req.Header.Set(webhookTimestampHeader, time.Now().UTC().Format(webhookTimestampLayout))
	if w.Secret != "" {
		req.Header.Set(webhookSignatureHeader, signWebhookBody(w.Secret, body))
	}

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error names the URL and the cause, never the body.
		return fmt.Errorf("%s: %w", where, err)
	}
	defer resp.Body.Close()
	// Drain a little so a kept-alive connection can be reused. The bytes go
	// nowhere: see the comment above about echoes.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: status %d", where, resp.StatusCode)
	}
	return nil
}

// signWebhookBody is the reference's WebhookSender.sign
// (webhook-sender.ts:54-56): "sha256=" + hex(HMAC-SHA256(secret, body)). It is
// the form VerifyWebhookSignature checks.
func signWebhookBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// emailDomain returns "@" plus the domain of an address, or "" when the address
// has none — the one part of a recipient an error may name.
func emailDomain(address string) string {
	if at := strings.LastIndex(address, "@"); at >= 0 && at < len(address)-1 {
		return address[at:]
	}
	return ""
}

// newUUIDv4 is what the reference's randomUUID() gives X-Webhook-Delivery: a
// random (version 4, variant 1) UUID in its canonical 8-4-4-4-12 spelling.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: random uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
