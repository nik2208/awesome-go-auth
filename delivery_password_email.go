package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// This file extends the delivery seam of delivery.go to the three §2 routes that
// mint a credential and, until now, had nowhere to send it:
//
//	POST <prefix>/forgot-password        → PasswordResetSender
//	POST <prefix>/send-verification-email → EmailVerificationSender
//	POST <prefix>/change-email/request   → EmailChangeSender
//
// The shape is delivery.go's, for delivery.go's reasons: func types rather than
// interfaces, a delivery struct carrying the plaintext token and nothing else
// that is credential material, the sender on Config rather than behind a
// UserStore assertion, no sender required by Config.validate, and store-first-
// then-send so a failed send leaves an unguessable token that expires on its own.
//
// What differs from magic-link and SMS is what an *unconfigured* deployment sees,
// and the difference is the reference's, not a simplification:
//
//   - /magic-link/send checks its config before the lookup and throws
//     EMAIL_NOT_CONFIGURED (magic-link.strategy.ts:12-14), so the port answers
//     500 there.
//   - These three routes check nothing. Each one prefers a config callback,
//     falls back to config.email.mailer, and when neither exists sends no mail
//     and still answers 200 {"success":true} (auth.router.ts:787-792, 956-961,
//     1027-1032; wire-contract §2 "Mailer dispatch order": "if neither exists, no
//     email is sent and the route still succeeds").
//
// So none of the three has a NOT_CONFIGURED sentinel: a nil sender is silence,
// not an error, and wiring one is purely additive for an existing deployment.
// The three routes behave exactly as they did before this file existed until a
// sender is supplied.
//
// A *failing* sender is a different matter. The reference's send calls sit inside
// the route's try block, so a throwing mailer reaches handleError and produces
// the generic code-less 500 (auth.router.ts:796-798). That is reproduced on
// /send-verification-email and /change-email/request, which are authenticated and
// have no anti-enumeration duty. It is deliberately *not* reproduced on
// /forgot-password — see ErrDeliveryFailed and Auth.ForgotPassword.

// ErrDeliveryFailed marks a send that failed after the credential was already
// stored. It is joined to the transport's own error rather than replacing it, so
// a caller can still read the cause, and it exists for exactly one reason:
// /forgot-password has to tell a delivery failure apart from a store failure in
// order to swallow the first and report the second (Auth.ForgotPassword).
//
// It maps to no catalog entry of its own. HTTPErrorFor does not know it, so it
// falls through to the generic 500 — which is what the reference answers for a
// throwing mailer, and what the two authenticated routes therefore answer.
var ErrDeliveryFailed = errors.New("auth: delivery failed after the credential was stored")

// PasswordResetDelivery is what a PasswordResetSender is handed.
//
// Like MagicLinkDelivery it carries the plaintext token — the store holds only
// its hash — plus the address the mail goes to and the ids a sender needs to read
// anything else back with. No User, no password hash: a sender is host code that
// may log what it receives.
type PasswordResetDelivery struct {
	UserID   string
	TenantID string
	// Email is the stored address of the account the reset was requested for,
	// not the address as the request spelled it. An unknown address never
	// reaches a sender at all: the route is silent about who is registered.
	Email string
	// Token is the plaintext token POST <prefix>/reset-password accepts.
	Token string
	// ExpiresAt is the stored expiry, Config.ResetTokenTTL from now (1 hour, as
	// in the reference). Verification allows Config.ClockSkew past it, so a
	// message quoting this value understates the window rather than overstating
	// it.
	ExpiresAt time.Time
}

// EmailVerificationDelivery is what an EmailVerificationSender is handed. The
// route behind it is authenticated, so Email is the caller's own stored address.
type EmailVerificationDelivery struct {
	UserID   string
	TenantID string
	Email    string
	// Token is the plaintext token GET <prefix>/verify-email accepts.
	Token     string
	ExpiresAt time.Time
}

// EmailChangeDelivery is what an EmailChangeSender is handed.
//
// NewEmail is the only address here, and it is the recipient: this message
// verifies that the new mailbox exists, so it goes to the new mailbox
// (auth.router.ts:1027-1032 mails newEmail; wire-contract §2 "sent to the new
// address"). The current address is deliberately absent — the delivery carries
// only what the message needs, and a sender that wants the old address has
// UserID to read it back with.
//
// The reference also mails the *old* address a notice once the change is applied
// (config.email.sendEmailChanged from /change-email/confirm,
// auth.router.ts:1060-1066). This port has no sender for that notice and no
// template for it either — MailTemplater's email_change template is the
// confirm-the-new-address mail, not the notice — so the gap is recorded here
// rather than filled by inventing one. It belongs with a template addition.
type EmailChangeDelivery struct {
	UserID   string
	TenantID string
	// NewEmail is the pending address the message goes to.
	NewEmail string
	// Token is the plaintext token POST <prefix>/change-email/confirm accepts.
	Token     string
	ExpiresAt time.Time
}

// PasswordResetSender delivers a password-reset token.
//
// An error does NOT fail POST <prefix>/forgot-password: that route answers 200
// {"success":true} whatever happens. See Auth.ForgotPassword.
type PasswordResetSender func(ctx context.Context, delivery PasswordResetDelivery) error

// EmailVerificationSender delivers an email-verification token. An error fails
// the route with the reference's generic 500 and leaves the stored token in
// place, as MagicLinkSender does.
type EmailVerificationSender func(ctx context.Context, delivery EmailVerificationDelivery) error

// EmailChangeSender delivers an email-change token to the pending address. See
// EmailVerificationSender for the failure contract.
type EmailChangeSender func(ctx context.Context, delivery EmailChangeDelivery) error

// The routes the three tokens are spent on, relative to the mount prefix.
const (
	PasswordResetPath      = "/reset-password"
	EmailVerificationPath  = "/verify-email"
	EmailChangeConfirmPath = "/change-email/confirm"
)

// PasswordResetURL, EmailVerificationURL and EmailChangeConfirmURL build the
// links the reference mails, so a deployment writing its own sender does not have
// to guess the shape.
//
// base is the address the auth routes are reachable at from a mailbox. The
// reference derives it per request (resolveSiteUrl / buildUiLink, wire-contract
// §4); this port has neither a siteUrl config field nor origin resolution yet, so
// the base is the sender's to supply, exactly as for MagicLinkURL.
//
// One caveat carries over from the reference and is worth knowing before these
// links reach a real mailbox: /reset-password and /change-email/confirm are
// POST-only routes, so a browser following either link lands on something it
// cannot GET (wire-contract §2 notes the same about the reference with its UI
// disabled). A deployment points base at the front end that owns those two pages;
// /verify-email is a GET and works directly.
func PasswordResetURL(base, token string) string {
	return tokenLink(base, PasswordResetPath, token)
}

// EmailVerificationURL builds the verify-email link.
func EmailVerificationURL(base, token string) string {
	return tokenLink(base, EmailVerificationPath, token)
}

// EmailChangeConfirmURL builds the change-email confirmation link.
func EmailChangeConfirmURL(base, token string) string {
	return tokenLink(base, EmailChangeConfirmPath, token)
}

// -----------------------------------------------------------------------------
// service side
// -----------------------------------------------------------------------------

// deliverPasswordReset, deliverEmailVerification and deliverEmailChange are the
// three send steps, called after the token hash is stored.
//
// A nil sender returns nil: on these routes an unconfigured deployment sends
// nothing and still succeeds. A failing sender returns an error joining
// ErrDeliveryFailed and the transport's own, which is what lets /forgot-password
// swallow one failure mode without swallowing store failures too.
func (s *Service) deliverPasswordReset(ctx context.Context, user User, token string, expiresAt time.Time) error {
	if s.cfg.SendPasswordReset == nil {
		return nil
	}
	err := s.cfg.SendPasswordReset(ctx, PasswordResetDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver password reset: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

func (s *Service) deliverEmailVerification(ctx context.Context, user User, token string, expiresAt time.Time) error {
	if s.cfg.SendEmailVerification == nil {
		return nil
	}
	err := s.cfg.SendEmailVerification(ctx, EmailVerificationDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver email verification: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

func (s *Service) deliverEmailChange(ctx context.Context, user User, newEmail, token string, expiresAt time.Time) error {
	if s.cfg.SendEmailChange == nil {
		return nil
	}
	err := s.cfg.SendEmailChange(ctx, EmailChangeDelivery{
		UserID:    user.ID,
		TenantID:  user.TenantID,
		NewEmail:  newEmail,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("auth: deliver email change: %w: %w", ErrDeliveryFailed, err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// ready-made mailers
// -----------------------------------------------------------------------------

// TokenMailer is the shared body of the three ready-made senders below and the
// port's equivalent of the reference's config.email.mailer path, where a
// deployment configures a transport instead of writing a callback. It is
// MagicLinkMailer's shape, factored out because three copies of it would be three
// places for a template name or a Content-Type to drift.
type TokenMailer struct {
	// Transport delivers the rendered message. Required.
	Transport MailerTransport
	// BaseURL is what the URL builders above build the link under.
	BaseURL string
	// Locale selects the built-in template set: "en" (the default) or "it". An
	// unknown locale falls back to English, as MailTemplater.Render does.
	//
	// It is static for the same reason MagicLinkMailer.Locale is: the reference's
	// per-request override is the emailLang body field, which these routes accept
	// on the wire and no adapter threads any further yet.
	Locale string
	// Templates renders subject and body. The constructors fill this in.
	Templates *MailTemplater
}

func newTokenMailer(transport MailerTransport, appName, baseURL string) TokenMailer {
	return TokenMailer{Transport: transport, BaseURL: baseURL, Templates: NewMailTemplater(appName)}
}

// send renders one of the built-in templates and hands the result to the
// transport. The recipient address stands in for the recipient's name: a delivery
// carries no name, and the built-in templates greet the value they are given.
func (m TokenMailer) send(ctx context.Context, template, to, token, link string) error {
	if m.Transport == nil {
		return errors.New("auth: mailer has no transport")
	}
	templates := m.Templates
	if templates == nil {
		templates = NewMailTemplater("")
	}
	subject, body, err := templates.Render(m.Locale, template, MailTemplateData{
		UserName: to,
		Token:    token,
		URL:      link,
	})
	if err != nil {
		return err
	}
	return m.Transport.Send(ctx, MailMessage{To: to, Subject: subject, Body: body, IsHTML: true})
}

// PasswordResetMailer is the ready-made PasswordResetSender: it renders the
// built-in reset_password template and hands the result to a MailerTransport.
//
// Use it as a sender through its Send method:
//
//	auth.WithPasswordResetSender(auth.NewPasswordResetMailer(
//		auth.NewHTTPMailerTransport(endpoint, secret),
//		"Example App",
//		"https://app.example.com/auth",
//	).Send)
type PasswordResetMailer struct{ TokenMailer }

// NewPasswordResetMailer builds a PasswordResetMailer with the built-in
// templates. appName is the name those templates greet the recipient with.
func NewPasswordResetMailer(transport MailerTransport, appName, baseURL string) *PasswordResetMailer {
	return &PasswordResetMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the reset mail. Its signature is
// PasswordResetSender's.
func (m *PasswordResetMailer) Send(ctx context.Context, delivery PasswordResetDelivery) error {
	if m == nil {
		return errors.New("auth: password reset mailer is nil")
	}
	return m.send(ctx, "reset_password", delivery.Email, delivery.Token, PasswordResetURL(m.BaseURL, delivery.Token))
}

// EmailVerificationMailer is the ready-made EmailVerificationSender, rendering
// the built-in verify_email template. See PasswordResetMailer for the usage
// shape.
type EmailVerificationMailer struct{ TokenMailer }

// NewEmailVerificationMailer builds an EmailVerificationMailer with the built-in
// templates.
func NewEmailVerificationMailer(transport MailerTransport, appName, baseURL string) *EmailVerificationMailer {
	return &EmailVerificationMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the verification mail. Its signature is
// EmailVerificationSender's.
func (m *EmailVerificationMailer) Send(ctx context.Context, delivery EmailVerificationDelivery) error {
	if m == nil {
		return errors.New("auth: email verification mailer is nil")
	}
	return m.send(ctx, "verify_email", delivery.Email, delivery.Token, EmailVerificationURL(m.BaseURL, delivery.Token))
}

// EmailChangeMailer is the ready-made EmailChangeSender. It mails the pending
// address and renders the built-in email_change template.
//
// The reference has no template of its own here: it reuses its verification
// sender and verification template for this mail (wire-contract §2, "there is no
// dedicated change-email template"). This port ships email_change already, in en
// and it, and nothing called it until now — so the better-worded template wins.
// The choice is invisible on the wire: the route answers {"success":true} either
// way, and only the mail body differs.
type EmailChangeMailer struct{ TokenMailer }

// NewEmailChangeMailer builds an EmailChangeMailer with the built-in templates.
func NewEmailChangeMailer(transport MailerTransport, appName, baseURL string) *EmailChangeMailer {
	return &EmailChangeMailer{newTokenMailer(transport, appName, baseURL)}
}

// Send renders and delivers the email-change mail to the new address. Its
// signature is EmailChangeSender's.
func (m *EmailChangeMailer) Send(ctx context.Context, delivery EmailChangeDelivery) error {
	if m == nil {
		return errors.New("auth: email change mailer is nil")
	}
	return m.send(ctx, "email_change", delivery.NewEmail, delivery.Token, EmailChangeConfirmURL(m.BaseURL, delivery.Token))
}
