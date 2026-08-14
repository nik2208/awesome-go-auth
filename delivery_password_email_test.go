package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests for the §2 half of the delivery seam. The wire answers are pinned once
// for all four adapters in adapter/internal/wiretest; what is asserted here is
// what only the root package can see — the sentinel, the plaintext the sender is
// handed, and the ready-made mailers.

// passwordEmailSpy records the three §2 deliveries.
type passwordEmailSpy struct {
	resets        []PasswordResetDelivery
	verifications []EmailVerificationDelivery
	changes       []EmailChangeDelivery
	// fail, when set, is what every sender returns.
	fail error
	// inspect, when set, runs inside the sender, before it returns. It is how the
	// store-then-send order is observed: whatever the store holds at that moment
	// is what the sender could have mailed.
	inspect func()
}

func (s *passwordEmailSpy) sendPasswordReset(_ context.Context, d PasswordResetDelivery) error {
	s.resets = append(s.resets, d)
	if s.inspect != nil {
		s.inspect()
	}
	return s.fail
}

func (s *passwordEmailSpy) sendEmailVerification(_ context.Context, d EmailVerificationDelivery) error {
	s.verifications = append(s.verifications, d)
	if s.inspect != nil {
		s.inspect()
	}
	return s.fail
}

func (s *passwordEmailSpy) sendEmailChange(_ context.Context, d EmailChangeDelivery) error {
	s.changes = append(s.changes, d)
	if s.inspect != nil {
		s.inspect()
	}
	return s.fail
}

// newPasswordEmailSvc builds a service with the three §2 senders wired to spy and
// nothing else, so a case that leaves one out is testing the unconfigured path.
func newPasswordEmailSvc(t *testing.T, spy *passwordEmailSpy) *Service {
	t.Helper()
	cfg := DefaultConfig("pwemaildelivery12345678901234567")
	if spy != nil {
		cfg.SendPasswordReset = spy.sendPasswordReset
		cfg.SendEmailVerification = spy.sendEmailVerification
		cfg.SendEmailChange = spy.sendEmailChange
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// newPasswordEmailAuth builds the Auth wrapper — the HTTP surface — with the same
// senders. /forgot-password's swallow lives there, not on the service.
func newPasswordEmailAuth(t *testing.T, spy *passwordEmailSpy, opts ...Option) *Auth {
	t.Helper()
	base := []Option{
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		// The fixtures below go through Register, and nothing here looks at the
		// hash itself.
		WithBcryptCost(testBcryptCost),
	}
	if spy != nil {
		base = append(base,
			WithPasswordResetSender(spy.sendPasswordReset),
			WithEmailVerificationSender(spy.sendEmailVerification),
			WithEmailChangeSender(spy.sendEmailChange),
		)
	}
	a, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	return a
}

// seedUnverifiedUser is seedUser with the verified flag off, which is the only
// state /send-verification-email will act on.
func seedUnverifiedUser(t *testing.T, svc *Service, email string) User {
	t.Helper()
	id, err := newID("usr")
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	user, err := svc.users.CreateUser(context.Background(), User{
		ID: id, Email: email, TenantID: "t1", CreatedAt: svc.now(),
	})
	if err != nil {
		t.Fatalf("seed %s: %v", email, err)
	}
	return user
}

// TestConfigValidateDoesNotRequireTheSectionTwoSenders is
// TestConfigValidateDoesNotRequireSenders for the three new ones. Their absence
// is not even a runtime failure here: it is silence.
func TestConfigValidateDoesNotRequireTheSectionTwoSenders(t *testing.T) {
	cfg := DefaultConfig("nopwemailsenders123456789012345678")
	if cfg.SendPasswordReset != nil || cfg.SendEmailVerification != nil || cfg.SendEmailChange != nil {
		t.Fatal("DefaultConfig must wire no senders")
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a config with no senders must still validate: %v", err)
	}
	if _, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore()); err != nil {
		t.Fatalf("a service with no senders must still build: %v", err)
	}
}

func TestSectionTwoSenderOptionsRejectNil(t *testing.T) {
	if _, err := New(WithPasswordResetSender(nil)); err == nil {
		t.Error("WithPasswordResetSender(nil) must fail")
	}
	if _, err := New(WithEmailVerificationSender(nil)); err == nil {
		t.Error("WithEmailVerificationSender(nil) must fail")
	}
	if _, err := New(WithEmailChangeSender(nil)); err == nil {
		t.Error("WithEmailChangeSender(nil) must fail")
	}
}

// -----------------------------------------------------------------------------
// what the senders receive
// -----------------------------------------------------------------------------

// The delivered token is spent through ResetPassword rather than compared to
// anything: the only interesting question is whether the recipient of that mail
// can complete the flow.
func TestForgotPasswordDeliversTheTokenResetPasswordAccepts(t *testing.T) {
	spy := &passwordEmailSpy{}
	svc := newPasswordEmailSvc(t, spy)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedUser(t, svc, "resetdeliver@example.com")

	returned, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if len(spy.resets) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(spy.resets))
	}
	got := spy.resets[0]
	if got.Token != returned {
		t.Errorf("delivered token %q, returned %q: the recipient got a different credential", got.Token, returned)
	}
	if got.Email != user.Email || got.UserID != user.ID || got.TenantID != "t1" {
		t.Errorf("delivery = %+v, want %s/%s/t1", got, user.Email, user.ID)
	}
	if !got.ExpiresAt.Equal(now.Add(svc.cfg.ResetTokenTTL)) {
		t.Errorf("expiry = %v, want %v", got.ExpiresAt, now.Add(svc.cfg.ResetTokenTTL))
	}
	if stored := storedUser(t, svc, user.ID).ResetTokenHash; stored != hashToken(got.Token) {
		t.Errorf("stored hash %q does not match the delivered token", stored)
	} else if stored == got.Token {
		t.Error("the plaintext token was stored")
	}

	// The round trip: only ResetPassword can say the delivered token is the real
	// one.
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{Token: got.Token, NewPassword: "deliveredpw1"}); err != nil {
		t.Fatalf("the delivered token was refused by ResetPassword: %v", err)
	}
}

func TestSendVerificationEmailDeliversTheTokenVerifyEmailAccepts(t *testing.T) {
	spy := &passwordEmailSpy{}
	svc := newPasswordEmailSvc(t, spy)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedUnverifiedUser(t, svc, "verifydeliver@example.com")

	returned, err := svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: user.ID, TenantID: "t1"})
	if err != nil {
		t.Fatalf("send verification email: %v", err)
	}
	if len(spy.verifications) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(spy.verifications))
	}
	got := spy.verifications[0]
	if got.Token != returned {
		t.Errorf("delivered token %q, returned %q", got.Token, returned)
	}
	if got.Email != user.Email || got.UserID != user.ID || got.TenantID != "t1" {
		t.Errorf("delivery = %+v, want %s/%s/t1", got, user.Email, user.ID)
	}
	if !got.ExpiresAt.Equal(now.Add(svc.cfg.EmailVerificationTTL)) {
		t.Errorf("expiry = %v, want %v", got.ExpiresAt, now.Add(svc.cfg.EmailVerificationTTL))
	}
	if stored := storedUser(t, svc, user.ID).EmailVerificationTokenHash; stored != hashToken(got.Token) {
		t.Errorf("stored hash %q does not match the delivered token", stored)
	}

	if err := svc.VerifyEmail(context.Background(), VerifyEmailInput{Token: got.Token}); err != nil {
		t.Fatalf("the delivered token was refused by VerifyEmail: %v", err)
	}
}

// The recipient here is the *new* address, and the round trip proves the token
// resolves the pending change rather than merely existing.
func TestRequestEmailChangeDeliversToTheNewAddress(t *testing.T) {
	spy := &passwordEmailSpy{}
	svc := newPasswordEmailSvc(t, spy)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedUser(t, svc, "changedeliver@example.com")

	returned, err := svc.RequestEmailChange(context.Background(), ChangeEmailRequestInput{
		UserID: user.ID, TenantID: "t1", NewEmail: "changedelivernew@example.com",
	})
	if err != nil {
		t.Fatalf("request email change: %v", err)
	}
	if len(spy.changes) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(spy.changes))
	}
	got := spy.changes[0]
	if got.NewEmail != "changedelivernew@example.com" {
		t.Errorf("mailed %q, want the new address", got.NewEmail)
	}
	if got.Token != returned {
		t.Errorf("delivered token %q, returned %q", got.Token, returned)
	}
	if got.UserID != user.ID || got.TenantID != "t1" {
		t.Errorf("delivery = %+v, want %s/t1", got, user.ID)
	}
	if !got.ExpiresAt.Equal(now.Add(svc.cfg.EmailChangeTTL)) {
		t.Errorf("expiry = %v, want %v", got.ExpiresAt, now.Add(svc.cfg.EmailChangeTTL))
	}

	if err := svc.ConfirmEmailChange(context.Background(), ConfirmEmailChangeInput{Token: got.Token}); err != nil {
		t.Fatalf("the delivered token was refused by ConfirmEmailChange: %v", err)
	}
	if got := storedUser(t, svc, user.ID).Email; got != "changedelivernew@example.com" {
		t.Errorf("address = %q, want the new one", got)
	}
}

// -----------------------------------------------------------------------------
// store first, then send
// -----------------------------------------------------------------------------

// Each sender reads the row it was called about while the call is still in
// flight. A hash already there is the ordering; the reference stores first too
// (auth.router.ts:784 then :787-792, :953 then :956-961, :1024 then :1027-1032).
func TestSectionTwoDeliveryStoresBeforeItSends(t *testing.T) {
	t.Run("forgot password", func(t *testing.T) {
		spy := &passwordEmailSpy{}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUser(t, svc, "resetorder@example.com")
		var seen string
		spy.inspect = func() { seen = storedUser(t, svc, user.ID).ResetTokenHash }

		if _, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"}); err != nil {
			t.Fatalf("forgot password: %v", err)
		}
		if seen == "" {
			t.Error("the sender was called before the token was stored")
		}
	})

	t.Run("send verification email", func(t *testing.T) {
		spy := &passwordEmailSpy{}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUnverifiedUser(t, svc, "verifyorder@example.com")
		var seen string
		spy.inspect = func() { seen = storedUser(t, svc, user.ID).EmailVerificationTokenHash }

		if _, err := svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: user.ID, TenantID: "t1"}); err != nil {
			t.Fatalf("send verification email: %v", err)
		}
		if seen == "" {
			t.Error("the sender was called before the token was stored")
		}
	})

	t.Run("change email request", func(t *testing.T) {
		spy := &passwordEmailSpy{}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUser(t, svc, "changeorder@example.com")
		var seenHash, seenPending string
		spy.inspect = func() {
			stored := storedUser(t, svc, user.ID)
			seenHash, seenPending = stored.EmailChangeTokenHash, stored.PendingEmail
		}

		if _, err := svc.RequestEmailChange(context.Background(), ChangeEmailRequestInput{
			UserID: user.ID, TenantID: "t1", NewEmail: "changeorderednew@example.com",
		}); err != nil {
			t.Fatalf("request email change: %v", err)
		}
		if seenHash == "" || seenPending != "changeorderednew@example.com" {
			t.Errorf("at send time the store held hash %q and pending %q", seenHash, seenPending)
		}
	})
}

// -----------------------------------------------------------------------------
// a failed send
// -----------------------------------------------------------------------------

// The service reports a failed send, wrapping both ErrDeliveryFailed and the
// transport's own error, and leaves the credential stored. All three behave the
// same way here; the difference is what the HTTP surface then does with it.
func TestSectionTwoDeliveryFailureKeepsTheCredential(t *testing.T) {
	t.Run("forgot password", func(t *testing.T) {
		spy := &passwordEmailSpy{fail: errors.New("mail gateway unreachable")}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUser(t, svc, "resetfail@example.com")

		_, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"})
		if !errors.Is(err, ErrDeliveryFailed) || !errors.Is(err, spy.fail) {
			t.Fatalf("err = %v, want it to wrap both ErrDeliveryFailed and the transport failure", err)
		}
		if storedUser(t, svc, user.ID).ResetTokenHash == "" {
			t.Error("the stored token was rolled back; the reference leaves it in place")
		}
	})

	t.Run("send verification email", func(t *testing.T) {
		spy := &passwordEmailSpy{fail: errors.New("mail gateway unreachable")}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUnverifiedUser(t, svc, "verifyfail@example.com")

		_, err := svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: user.ID, TenantID: "t1"})
		if !errors.Is(err, ErrDeliveryFailed) || !errors.Is(err, spy.fail) {
			t.Fatalf("err = %v, want it to wrap both ErrDeliveryFailed and the transport failure", err)
		}
		if storedUser(t, svc, user.ID).EmailVerificationTokenHash == "" {
			t.Error("the stored token was rolled back")
		}
		// The two authenticated routes answer the reference's generic 500 for this.
		if envelope := SendVerificationEmailHTTPError(err); envelope != HTTPErrInternal {
			t.Errorf("wire envelope = %+v, want the generic 500 %+v", envelope, HTTPErrInternal)
		}
	})

	t.Run("change email request", func(t *testing.T) {
		spy := &passwordEmailSpy{fail: errors.New("mail gateway unreachable")}
		svc := newPasswordEmailSvc(t, spy)
		user := seedUser(t, svc, "changefail@example.com")

		_, err := svc.RequestEmailChange(context.Background(), ChangeEmailRequestInput{
			UserID: user.ID, TenantID: "t1", NewEmail: "changefailnew@example.com",
		})
		if !errors.Is(err, ErrDeliveryFailed) || !errors.Is(err, spy.fail) {
			t.Fatalf("err = %v, want it to wrap both ErrDeliveryFailed and the transport failure", err)
		}
		stored := storedUser(t, svc, user.ID)
		if stored.EmailChangeTokenHash == "" || stored.PendingEmail != "changefailnew@example.com" {
			t.Error("the pending change was rolled back")
		}
		if stored.Email != "changefail@example.com" {
			t.Errorf("address = %q: a failed send must not move the address", stored.Email)
		}
		if envelope := ChangeEmailRequestHTTPError(err); envelope != HTTPErrInternal {
			t.Errorf("wire envelope = %+v, want the generic 500 %+v", envelope, HTTPErrInternal)
		}
	})
}

// TestSectionTwoDeliveryFailureIsAlwaysTheGenericFiveHundred closes the hole the
// case above leaves open. It asserts the same thing — a failed send is the
// reference's generic code-less 500 — but with transport errors that are library
// sentinels rather than an anonymous errors.New, which is the only shape that can
// actually go wrong.
//
// The delivery wrapper joins ErrDeliveryFailed to the transport's error instead of
// replacing it, deliberately, so a caller can read the cause. That means errors.Is
// in these two mappers can see straight through to whatever the host sender
// returned, and a sender is host code: one that reads the store back through the
// UserID the delivery carries — which is what the delivery carries it for — will
// propagate exactly these values. A mail gateway may not choose this route's wire
// answer.
func TestSectionTwoDeliveryFailureIsAlwaysTheGenericFiveHundred(t *testing.T) {
	// Every sentinel either mapper would otherwise match, plus one that neither
	// does, to pin that the generic answer is unconditional.
	transports := []struct {
		name string
		err  error
	}{
		{"ErrUserExists", ErrUserExists},
		{"ErrAlreadyExists", ErrAlreadyExists},
		{"ErrInvalidCredentials", ErrInvalidCredentials},
		{"ErrFeatureNotSupported", ErrFeatureNotSupported},
		{"an anonymous transport error", errors.New("mail gateway unreachable")},
	}

	for _, tc := range transports {
		t.Run("send verification email/"+tc.name, func(t *testing.T) {
			spy := &passwordEmailSpy{fail: fmt.Errorf("smtp: %w", tc.err)}
			svc := newPasswordEmailSvc(t, spy)
			user := seedUnverifiedUser(t, svc, "verifysentinel@example.com")

			_, err := svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: user.ID, TenantID: "t1"})
			if !errors.Is(err, ErrDeliveryFailed) {
				t.Fatalf("err = %v, want it to wrap ErrDeliveryFailed", err)
			}
			if envelope := SendVerificationEmailHTTPError(err); envelope != HTTPErrInternal {
				t.Errorf("a sender that failed with %s answered %+v; a failed send is the generic 500 %+v",
					tc.name, envelope, HTTPErrInternal)
			}
		})

		t.Run("change email request/"+tc.name, func(t *testing.T) {
			spy := &passwordEmailSpy{fail: fmt.Errorf("smtp: %w", tc.err)}
			svc := newPasswordEmailSvc(t, spy)
			user := seedUser(t, svc, "changesentinel@example.com")

			_, err := svc.RequestEmailChange(context.Background(), ChangeEmailRequestInput{
				UserID: user.ID, TenantID: "t1", NewEmail: "changesentinelnew@example.com",
			})
			if !errors.Is(err, ErrDeliveryFailed) {
				t.Fatalf("err = %v, want it to wrap ErrDeliveryFailed", err)
			}
			if envelope := ChangeEmailRequestHTTPError(err); envelope != HTTPErrInternal {
				t.Errorf("a sender that failed with %s answered %+v; a failed send is the generic 500 %+v",
					tc.name, envelope, HTTPErrInternal)
			}
		})
	}
}

// TestAuthForgotPasswordSwallowsADeliveryFailure is the divergence from the
// reference, asserted at the layer that owns it. The service reported the failure
// (above); the HTTP surface refuses to let it change the answer, because a 500
// only for an address that exists is the enumeration oracle the route exists to
// deny (auth.router.ts:796-798, wire-contract §2 "Anti-enumeration caveat").
func TestAuthForgotPasswordSwallowsADeliveryFailure(t *testing.T) {
	spy := &passwordEmailSpy{fail: errors.New("mail gateway unreachable")}
	var logged []string
	a := newPasswordEmailAuth(t, spy, WithLogger(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}))
	if _, _, err := a.Register(context.Background(), RegisterInput{
		Email: "authresetfail@example.com", Password: "password1", TenantID: "t1",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	token, err := a.ForgotPassword(context.Background(), ForgotPasswordInput{
		Email: "authresetfail@example.com", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("Auth.ForgotPassword surfaced a delivery failure: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty: the swallowed path must look like the unknown-address path", token)
	}
	if len(spy.resets) != 1 {
		t.Fatalf("the sender was called %d times, want 1", len(spy.resets))
	}
	// The token is still spendable: swallowing the report does not discard the
	// credential, so a later resend or a manual delivery still works.
	stored, err := a.Service().users.GetUserByID(context.Background(), spy.resets[0].UserID, "t1")
	if err != nil {
		t.Fatalf("read back the user: %v", err)
	}
	if stored.ResetTokenHash != hashToken(spy.resets[0].Token) {
		t.Error("the stored hash does not match the token the sender was handed")
	}

	// Swallowed on the wire, but not in silence: the log is the only signal a
	// deployment with a dead mail gateway can get, since every request still
	// answers 200. Same arrangement as the link-token delivery's swallow.
	var reported string
	for _, line := range logged {
		if strings.Contains(line, "password reset delivery failed") {
			reported = line
		}
	}
	if reported == "" {
		t.Errorf("the swallowed delivery failure was never logged; lines = %q", logged)
	}
	if !strings.Contains(reported, "mail gateway unreachable") {
		t.Errorf("log line %q does not carry the transport's cause", reported)
	}
	// And it does not name the address: the route's job is not to say who is
	// registered, which holds for the log as much as for the body.
	if strings.Contains(reported, "authresetfail@example.com") {
		t.Errorf("log line %q names the address the route refuses to confirm", reported)
	}

	// The reason the swallow exists, pinned at the layer that performs it. This is
	// the deviation the README registers as "forgot-password: unconditional 200 on
	// delivery failure", and its whole justification is that a broken mailer must
	// not tell an attacker which addresses are registered. So with the same failing
	// sender wired, a known address and an unknown one have to come back
	// indistinguishable — same value, same nil error — because everything the route
	// can put on the wire is derived from exactly that pair. Whoever revisits the
	// swallow: if this stops holding, the divergence has lost its argument and the
	// README entry is wrong, not this test.
	unknownToken, unknownErr := a.ForgotPassword(context.Background(), ForgotPasswordInput{
		Email: "nobodyhere@example.com", TenantID: "t1",
	})
	if unknownToken != token || unknownErr != nil {
		t.Errorf("unknown address = (%q, %v), known address with a failing sender = (%q, <nil>): the two must be indistinguishable",
			unknownToken, unknownErr, token)
	}
	if len(spy.resets) != 1 {
		t.Errorf("the sender was called %d times, want 1: an unknown address must mint and send nothing", len(spy.resets))
	}

	// A store failure is NOT swallowed: that oracle is the reference's and stays.
	// coreOnlyStore cannot persist a reset token, so an existing address errors.
	bare, err := New(
		WithUserStore(coreOnlyStore{NewMemoryUserStore()}),
		WithSessionStore(NewMemorySessionStore()),
		WithBcryptCost(testBcryptCost),
	)
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	if _, _, err := bare.Register(context.Background(), RegisterInput{
		Email: "authresetstore@example.com", Password: "password1", TenantID: "t1",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := bare.ForgotPassword(context.Background(), ForgotPasswordInput{
		Email: "authresetstore@example.com", TenantID: "t1",
	}); !errors.Is(err, ErrFeatureNotSupported) {
		t.Errorf("err = %v, want a store failure to still be reported", err)
	}
}

// coreOnlyStore is a UserStore and nothing else, so UpdateResetToken is out of
// reach — the store-failure branch of /forgot-password.
type coreOnlyStore struct{ inner *MemoryUserStore }

func (s coreOnlyStore) CreateUser(ctx context.Context, user User) (User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s coreOnlyStore) GetUserByEmail(ctx context.Context, email, tenantID string) (User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s coreOnlyStore) GetUserByID(ctx context.Context, id, tenantID string) (User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

// -----------------------------------------------------------------------------
// an unconfigured deployment
// -----------------------------------------------------------------------------

// No sender is silence, not an error: the reference's three routes send nothing
// and still succeed when neither a callback nor a mailer is configured
// (wire-contract §2 "Mailer dispatch order"). The credential is still minted and
// stored, so a deployment that delivers it out of band keeps working exactly as it
// did before the seam existed.
func TestSectionTwoDeliveryUnconfiguredIsSilentNotAnError(t *testing.T) {
	svc := newPasswordEmailSvc(t, nil)

	reset := seedUser(t, svc, "resetnosender@example.com")
	token, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: reset.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("forgot password with no sender: %v", err)
	}
	if token == "" || storedUser(t, svc, reset.ID).ResetTokenHash != hashToken(token) {
		t.Error("no reset token was minted for an unconfigured deployment")
	}

	verify := seedUnverifiedUser(t, svc, "verifynosender@example.com")
	token, err = svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: verify.ID, TenantID: "t1"})
	if err != nil {
		t.Fatalf("send verification email with no sender: %v", err)
	}
	if token == "" || storedUser(t, svc, verify.ID).EmailVerificationTokenHash != hashToken(token) {
		t.Error("no verification token was minted for an unconfigured deployment")
	}

	change := seedUser(t, svc, "changenosender@example.com")
	token, err = svc.RequestEmailChange(context.Background(), ChangeEmailRequestInput{
		UserID: change.ID, TenantID: "t1", NewEmail: "changenosendernew@example.com",
	})
	if err != nil {
		t.Fatalf("request email change with no sender: %v", err)
	}
	if token == "" || storedUser(t, svc, change.ID).EmailChangeTokenHash != hashToken(token) {
		t.Error("no email-change token was minted for an unconfigured deployment")
	}
}

// The three senders are independent of each other and of the two from PR #40:
// wiring one must not make the others a precondition of anything.
func TestSectionTwoSendersAreIndependent(t *testing.T) {
	spy := &passwordEmailSpy{}
	cfg := DefaultConfig("onlyonesender1234567890123456789")
	cfg.SendPasswordReset = spy.sendPasswordReset
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	user := seedUnverifiedUser(t, svc, "onlyreset@example.com")
	if _, err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: user.Email, TenantID: "t1"}); err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if len(spy.resets) != 1 {
		t.Fatalf("the wired sender was called %d times, want 1", len(spy.resets))
	}
	if _, err := svc.SendVerificationEmailToken(context.Background(), EmailVerificationInput{UserID: user.ID, TenantID: "t1"}); err != nil {
		t.Fatalf("an unwired sender must not fail the route: %v", err)
	}
	if len(spy.verifications) != 0 {
		t.Errorf("the unwired sender was called: %+v", spy.verifications)
	}
	// And the magic-link half is still unconfigured, which only its own route
	// cares about.
	if _, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{Email: user.Email, TenantID: "t1"}); !errors.Is(err, ErrEmailNotConfigured) {
		t.Errorf("magic link err = %v, want ErrEmailNotConfigured", err)
	}
}

// -----------------------------------------------------------------------------
// literals and ready-made mailers
// -----------------------------------------------------------------------------

// The three link shapes, alongside MagicLinkURL's. The trailing-slash rule and
// the raw token interpolation are shared, which is the point of tokenLink.
func TestSectionTwoURLShapes(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"reset", PasswordResetURL("https://app.example.com/auth", "tok"), "https://app.example.com/auth/reset-password?token=tok"},
		{"reset trailing slash", PasswordResetURL("https://app.example.com/auth/", "tok"), "https://app.example.com/auth/reset-password?token=tok"},
		{"reset no base", PasswordResetURL("", "tok"), "/reset-password?token=tok"},
		{"verify", EmailVerificationURL("https://app.example.com/auth", "tok"), "https://app.example.com/auth/verify-email?token=tok"},
		{"change", EmailChangeConfirmURL("https://app.example.com/auth", "tok"), "https://app.example.com/auth/change-email/confirm?token=tok"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// The three ready-made mailers render the templates that shipped with
// MailTemplater and were, until now, called by nothing.
func TestSectionTwoMailersRenderTheBuiltInTemplates(t *testing.T) {
	t.Run("password reset", func(t *testing.T) {
		transport := &recordingMailer{}
		mailer := NewPasswordResetMailer(transport, "Example App", "https://app.example.com/auth")
		if err := mailer.Send(context.Background(), PasswordResetDelivery{Email: "r@example.com", Token: "tok123"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		assertMailed(t, transport, "r@example.com", "Example App - Password Reset",
			"https://app.example.com/auth/reset-password?token=tok123")
	})

	t.Run("email verification", func(t *testing.T) {
		transport := &recordingMailer{}
		mailer := NewEmailVerificationMailer(transport, "Example App", "https://app.example.com/auth")
		if err := mailer.Send(context.Background(), EmailVerificationDelivery{Email: "v@example.com", Token: "tok123"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		assertMailed(t, transport, "v@example.com", "Example App - Verify Your Email",
			"https://app.example.com/auth/verify-email?token=tok123")
	})

	// The recipient is the new address, and the template is email_change — the one
	// the reference does not have, so it reuses its verification template instead.
	t.Run("email change", func(t *testing.T) {
		transport := &recordingMailer{}
		mailer := NewEmailChangeMailer(transport, "Example App", "https://app.example.com/auth")
		if err := mailer.Send(context.Background(), EmailChangeDelivery{NewEmail: "new@example.com", Token: "tok123"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		assertMailed(t, transport, "new@example.com", "Example App - Confirm Email Change",
			"https://app.example.com/auth/change-email/confirm?token=tok123")
	})
}

func assertMailed(t *testing.T, transport *recordingMailer, to, subject, link string) {
	t.Helper()
	if len(transport.sent) != 1 {
		t.Fatalf("transport was called %d times, want 1", len(transport.sent))
	}
	msg := transport.sent[0]
	if msg.To != to {
		t.Errorf("To = %q, want %q", msg.To, to)
	}
	if msg.Subject != subject {
		t.Errorf("Subject = %q, want %q", msg.Subject, subject)
	}
	if !msg.IsHTML {
		t.Error("the built-in templates are HTML")
	}
	if !strings.Contains(msg.Body, link) {
		t.Errorf("body does not carry the link %q: %s", link, msg.Body)
	}
}

// An "it" locale picks the Italian template set; an unknown one falls back to
// English rather than failing to send, as MailTemplater.Render does.
func TestSectionTwoMailerLocale(t *testing.T) {
	for locale, wantSubject := range map[string]string{
		"it": "Example App - Reimposta Password",
		"en": "Example App - Password Reset",
		"":   "Example App - Password Reset",
		"de": "Example App - Password Reset",
	} {
		transport := &recordingMailer{}
		mailer := NewPasswordResetMailer(transport, "Example App", "https://app.example.com/auth")
		mailer.Locale = locale
		if err := mailer.Send(context.Background(), PasswordResetDelivery{Email: "l@example.com", Token: "t"}); err != nil {
			t.Fatalf("locale %q: %v", locale, err)
		}
		if got := transport.sent[0].Subject; got != wantSubject {
			t.Errorf("locale %q subject = %q, want %q", locale, got, wantSubject)
		}
	}
}

// A mailer with no transport fails rather than reporting a delivery that did not
// happen — the same contract MagicLinkMailer has.
func TestSectionTwoMailersWithoutATransport(t *testing.T) {
	var reset PasswordResetMailer
	if err := reset.Send(context.Background(), PasswordResetDelivery{Email: "x@example.com"}); err == nil {
		t.Error("a password reset mailer with no transport must fail")
	}
	var verify EmailVerificationMailer
	if err := verify.Send(context.Background(), EmailVerificationDelivery{Email: "x@example.com"}); err == nil {
		t.Error("an email verification mailer with no transport must fail")
	}
	var change EmailChangeMailer
	if err := change.Send(context.Background(), EmailChangeDelivery{NewEmail: "x@example.com"}); err == nil {
		t.Error("an email change mailer with no transport must fail")
	}
}

// The mailers are usable as senders, which is the only signature that matters:
// this fails to compile if a Send method drifts from its func type.
func TestSectionTwoMailersSatisfyTheSenderTypes(t *testing.T) {
	transport := &recordingMailer{}
	if _, err := New(
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		WithPasswordResetSender(NewPasswordResetMailer(transport, "App", "https://app.example.com/auth").Send),
		WithEmailVerificationSender(NewEmailVerificationMailer(transport, "App", "https://app.example.com/auth").Send),
		WithEmailChangeSender(NewEmailChangeMailer(transport, "App", "https://app.example.com/auth").Send),
	); err != nil {
		t.Fatalf("wiring the ready-made mailers: %v", err)
	}
}
