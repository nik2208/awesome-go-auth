package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// This file holds the delivery seam: how a minted magic link or SMS code
// reaches the person it was minted for.
//
// The two routes that need it — POST <prefix>/magic-link/send and POST
// <prefix>/sms/send — answer {"success":true} and nothing else, so the
// credential cannot travel in the response body: handing a second factor back
// to whoever asked for it is no second factor at all. Service.SendMagicLink and
// Service.SendSMSCode give it to a host-supplied sender instead.
//
// Why the sender sits on Config and not behind a store-style optional
// interface. The other optional capabilities in this package are type
// assertions on the UserStore — MagicLinkStore, SMSStore, EmailVerificationStore
// — because each asks a question about persistence: can this store keep that
// column. Delivery is not that question. Whether a deployment can send mail has
// nothing to do with which database it chose, and a UserStore that also spoke
// SMTP would be a layering mistake. Two consequences settle it:
//
//   - A missing optional store means ErrFeatureNotSupported, which the wire
//     spells NOT_IMPLEMENTED. That code already means something else on these
//     very routes — the reference emits it when the store cannot look a
//     magic-link token up (wire-contract §3) — and the spec wants
//     EMAIL_NOT_CONFIGURED and SMS_NOT_CONFIGURED here. Different cause,
//     different code; reusing the store seam would collapse them.
//   - The reference puts delivery on its config too: config.email.sendMagicLink
//     (a callback) or config.email.mailer (a transport) for mail, and the
//     config.sms block for SMS. Config.BuildTokenClaims is this package's
//     existing precedent for a host-supplied callback and these two are its
//     siblings.
//
// Neither sender is required to construct a Service: Config.validate does not
// ask for them, exactly as the reference starts fine without an email or sms
// block. A deployment that never calls the passwordless routes never needs one.
// The absence is reported when a route is actually used, as the 500 the spec
// documents.

// MagicLinkDelivery is what a MagicLinkSender is handed.
//
// It carries the plaintext magic-link token — the store only ever sees its hash
// — and deliberately nothing else that is credential material. A sender is host
// code that may log or forward what it receives, so it is given the one secret
// it has to transmit and no other: no password hash, no TOTP secret, no User.
// A sender that needs more about the recipient has UserID and TenantID to read
// it back with.
type MagicLinkDelivery struct {
	UserID   string
	TenantID string
	Email    string
	// Token is the plaintext token the matching verify route accepts.
	Token string
	// ExpiresAt is the stored expiry, Config.MagicLinkTTL from now. Verification
	// additionally allows Config.ClockSkew past it, so a message that quotes this
	// value understates the window slightly rather than overstating it.
	ExpiresAt time.Time
}

// SMSCodeDelivery is what an SMSCodeSender is handed. See MagicLinkDelivery for
// why it carries so little.
type SMSCodeDelivery struct {
	UserID   string
	TenantID string
	// Phone is the recipient's stored number. The send route refuses a user
	// without one before it gets this far (PHONE_NOT_SET), so it is never empty.
	Phone string
	// Code is the plaintext one-time code; the store holds only its hash.
	Code      string
	ExpiresAt time.Time
}

// MagicLinkSender delivers a magic link. An error fails the route with the
// reference's generic 500 — a transport failure must not describe itself to the
// caller — and leaves the stored token in place, which is what the reference
// does too: an undelivered token is unguessable and expires on its own.
type MagicLinkSender func(ctx context.Context, delivery MagicLinkDelivery) error

// SMSCodeSender delivers an SMS one-time code. See MagicLinkSender for the
// failure contract.
type SMSCodeSender func(ctx context.Context, delivery SMSCodeDelivery) error

// MagicLinkVerifyPath is the route a magic link points at, relative to the
// mount prefix.
const MagicLinkVerifyPath = "/magic-link/verify"

// MagicLinkURL builds the link the reference mails: the base with any trailing
// slash removed, then "/magic-link/verify?token=<token>"
// (magic-link.strategy.ts:23-27). Reproduced here so that a deployment writing
// its own sender does not have to guess the shape the verify route and the
// shipped clients expect.
//
// base is the address the auth routes are reachable at from a mailbox —
// "https://app.example.com/auth". The reference derives it per request from
// email.siteUrl and the request Origin (resolveSiteUrl / buildUiLink,
// wire-contract §4); this port has neither a siteUrl config field nor origin
// resolution yet, so the base is the sender's to supply. An empty base yields a
// relative link, which the reference also produces when siteUrl is unset — it
// is a misconfiguration in both, not a special case handled here.
//
// The token is interpolated raw. randomToken emits base64url, whose alphabet
// needs no query escaping, and the reference interpolates its hex token raw for
// the same reason.
func MagicLinkURL(base, token string) string {
	return strings.TrimSuffix(base, "/") + MagicLinkVerifyPath + "?token=" + token
}

// SMSCodeMessage is the text the reference texts (sms.strategy.ts:20). It is on
// a wire of its own — a real handset — so the literal is reproduced rather than
// reworded, and it lives here so a custom SMSCodeSender can reuse it instead of
// drifting from the rest of the family.
func SMSCodeMessage(code string) string {
	return "Your verification code is: " + code
}

// MagicLinkMailer is the ready-made MagicLinkSender: it renders the built-in
// magic_link template and hands the result to a MailerTransport. It is the
// port's equivalent of the reference's config.email.mailer path, where a
// deployment configures a transport instead of writing a callback.
//
// Use it as a sender through its Send method:
//
//	auth.WithMagicLinkSender(auth.NewMagicLinkMailer(
//		auth.NewHTTPMailerTransport(endpoint, secret),
//		"Example App",
//		"https://app.example.com/auth",
//	).Send)
type MagicLinkMailer struct {
	// Transport delivers the rendered message. Required.
	Transport MailerTransport
	// BaseURL is what MagicLinkURL builds the link under.
	BaseURL string
	// Locale selects the built-in template set: "en" (the default) or "it". An
	// unknown locale falls back to English, as MailTemplater.Render does.
	//
	// It is static because the reference's per-request override (the emailLang
	// body field) has no counterpart on these routes yet: the port's send
	// requests do not carry the field, so threading a locale from the wire is a
	// change to the request shape and belongs with the rest of the template
	// configuration.
	Locale string
	// Templates renders subject and body. NewMagicLinkMailer fills this in.
	Templates *MailTemplater
}

// NewMagicLinkMailer builds a MagicLinkMailer with the built-in templates.
// appName is the name those templates greet the recipient with.
func NewMagicLinkMailer(transport MailerTransport, appName, baseURL string) *MagicLinkMailer {
	return &MagicLinkMailer{
		Transport: transport,
		BaseURL:   baseURL,
		Templates: NewMailTemplater(appName),
	}
}

// Send renders and delivers the magic-link mail. Its signature is
// MagicLinkSender's.
func (m *MagicLinkMailer) Send(ctx context.Context, delivery MagicLinkDelivery) error {
	if m == nil || m.Transport == nil {
		return errors.New("auth: magic link mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	// The address stands in for the recipient's name: the delivery carries no
	// name, and the reference's own magic-link template greets nobody at all.
	subject, body, err := templates.Render(m.Locale, "magic_link", MailTemplateData{
		UserName: delivery.Email,
		Token:    delivery.Token,
		URL:      MagicLinkURL(m.BaseURL, delivery.Token),
	})
	if err != nil {
		return err
	}
	return m.Transport.Send(ctx, MailMessage{
		To:      delivery.Email,
		Subject: subject,
		Body:    body,
		IsHTML:  true,
	})
}

// SMSTransportSender adapts an SMSTransport into an SMSCodeSender, formatting
// the code with SMSCodeMessage. It is the SMS counterpart of MagicLinkMailer.
func SMSTransportSender(transport SMSTransport) SMSCodeSender {
	return func(ctx context.Context, delivery SMSCodeDelivery) error {
		if transport == nil {
			return errors.New("auth: sms sender has no transport")
		}
		return transport.Send(ctx, delivery.Phone, SMSCodeMessage(delivery.Code))
	}
}
