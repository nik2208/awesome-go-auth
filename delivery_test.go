package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// noopDelivery installs senders that do nothing.
//
// Delivery is a configuration precondition of the send routes now, so a service
// built for a test about something else still has to satisfy it — otherwise
// every pre-existing magic-link and SMS test fails with EMAIL_NOT_CONFIGURED
// for a reason that has nothing to do with what it asserts. The tests below
// build their own service when the precondition is the thing under test.
func noopDelivery(cfg *Config) {
	cfg.SendMagicLink = func(context.Context, MagicLinkDelivery) error { return nil }
	cfg.SendSMSCode = func(context.Context, SMSCodeDelivery) error { return nil }
}

// deliverySpy records what a sender was handed instead of delivering it.
type deliverySpy struct {
	magicLinks []MagicLinkDelivery
	smsCodes   []SMSCodeDelivery
	// fail, when set, is what both senders return.
	fail error
}

func (d *deliverySpy) sendMagicLink(_ context.Context, delivery MagicLinkDelivery) error {
	d.magicLinks = append(d.magicLinks, delivery)
	return d.fail
}

func (d *deliverySpy) sendSMSCode(_ context.Context, delivery SMSCodeDelivery) error {
	d.smsCodes = append(d.smsCodes, delivery)
	return d.fail
}

// newDeliverySvc builds a service whose senders record. Pass nil for a sender
// to leave that half of the seam unconfigured.
func newDeliverySvc(t *testing.T, spy *deliverySpy, configureEmail, configureSMS bool) *Service {
	t.Helper()
	cfg := DefaultConfig("delivery1234567890123456789012345")
	if configureEmail {
		cfg.SendMagicLink = spy.sendMagicLink
	}
	if configureSMS {
		cfg.SendSMSCode = spy.sendSMSCode
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

// seedPhoneUser puts a user with a phone number straight into the store. Like
// seedUser it avoids Register, whose bcrypt cost dominates this package's test
// binary, and nothing here needs a password.
func seedPhoneUser(t *testing.T, svc *Service, email, phone string) User {
	t.Helper()
	id, err := newID("usr")
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	user, err := svc.users.CreateUser(context.Background(), User{
		ID: id, Email: email, TenantID: "t1", PhoneNumber: phone,
		IsEmailVerified: true, CreatedAt: svc.now(),
	})
	if err != nil {
		t.Fatalf("seed %s: %v", email, err)
	}
	return user
}

// storedUser reads a seeded user back, so an assertion about what was persisted
// does not have to trust the value the service returned.
func storedUser(t *testing.T, svc *Service, id string) User {
	t.Helper()
	user, err := svc.users.GetUserByID(context.Background(), id, "t1")
	if err != nil {
		t.Fatalf("read back user %q: %v", id, err)
	}
	return user
}

// TestConfigValidateDoesNotRequireSenders pins that the seam is a runtime
// precondition, not a startup one: the reference starts fine without an email or
// sms block, and a deployment that never calls the passwordless routes must not
// be forced to configure a transport it will not use.
func TestConfigValidateDoesNotRequireSenders(t *testing.T) {
	cfg := DefaultConfig("nosenders12345678901234567890123")
	if err := cfg.validate(); err != nil {
		t.Fatalf("a config with no senders must still validate: %v", err)
	}
	if _, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore()); err != nil {
		t.Fatalf("a service with no senders must still build: %v", err)
	}
}

// TestSendMagicLinkWithoutASender covers the documented 500. The address is one
// the store *does* have, so this is not the anti-enumeration path.
func TestSendMagicLinkWithoutASender(t *testing.T) {
	spy := &deliverySpy{}
	svc := newDeliverySvc(t, spy, false, true)
	user := seedUser(t, svc, "nomailer@example.com")

	token, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{Email: user.Email, TenantID: "t1"})
	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("err = %v, want ErrEmailNotConfigured", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}
	// Nothing may be stored: a link minted for a deployment that cannot send it
	// is a live credential nobody asked to create.
	if stored := storedUser(t, svc, user.ID).MagicLinkTokenHash; stored != "" {
		t.Errorf("a token was stored anyway: %q", stored)
	}
	if HTTPErrorFor(err) != HTTPErrEmailNotConfigured {
		t.Errorf("wire envelope = %+v, want %+v", HTTPErrorFor(err), HTTPErrEmailNotConfigured)
	}
}

// TestSendMagicLinkWithoutASenderOutranksTheSilence is the ordering the
// reference fixes by checking its config before the lookup
// (magic-link.strategy.ts:12-14 precedes :15). An unknown address normally
// answers 200 to avoid confirming who is registered; a deployment that cannot
// send mail answers 500 for that address too, because the misconfiguration is
// not the caller's business to be shielded from.
func TestSendMagicLinkWithoutASenderOutranksTheSilence(t *testing.T) {
	svc := newDeliverySvc(t, &deliverySpy{}, false, true)
	_, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{
		Email: "nobody@example.com", TenantID: "t1",
	})
	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("err = %v, want ErrEmailNotConfigured — the config check must precede the lookup", err)
	}
}

func TestSendMagicLinkDeliversThePlaintextToken(t *testing.T) {
	spy := &deliverySpy{}
	svc := newDeliverySvc(t, spy, true, false)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedUser(t, svc, "delivered@example.com")

	token, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{Email: user.Email, TenantID: "t1"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(spy.magicLinks) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(spy.magicLinks))
	}
	got := spy.magicLinks[0]
	if got.Token != token {
		t.Errorf("delivered token %q, returned %q: the recipient got a different credential", got.Token, token)
	}
	if got.Email != user.Email || got.UserID != user.ID || got.TenantID != "t1" {
		t.Errorf("delivery = %+v, want %s/%s/t1", got, user.Email, user.ID)
	}
	if !got.ExpiresAt.Equal(now.Add(svc.cfg.MagicLinkTTL)) {
		t.Errorf("expiry = %v, want %v", got.ExpiresAt, now.Add(svc.cfg.MagicLinkTTL))
	}
	// The delivered token is the one the store will accept, and the store holds
	// only its hash.
	stored := storedUser(t, svc, user.ID).MagicLinkTokenHash
	if stored != hashToken(got.Token) {
		t.Errorf("stored hash %q does not match the delivered token", stored)
	}
	if stored == got.Token {
		t.Error("the plaintext token was stored")
	}
}

// TestSendMagicLinkKeepsTheTokenWhenDeliveryFails pins the reference's order:
// store, then send. A failed send leaves a stored token nobody received, which
// is harmless — it is unguessable and expires on its own — and the caller is
// told, so the route can answer 500 rather than claim success.
func TestSendMagicLinkKeepsTheTokenWhenDeliveryFails(t *testing.T) {
	transportDown := errors.New("mail gateway unreachable")
	spy := &deliverySpy{fail: transportDown}
	svc := newDeliverySvc(t, spy, true, false)
	user := seedUser(t, svc, "faileddelivery@example.com")

	_, err := svc.SendMagicLink(context.Background(), MagicLinkSendInput{Email: user.Email, TenantID: "t1"})
	if !errors.Is(err, transportDown) {
		t.Fatalf("err = %v, want it to wrap the transport failure", err)
	}
	if storedUser(t, svc, user.ID).MagicLinkTokenHash == "" {
		t.Error("the stored token was rolled back; the reference leaves it in place")
	}
	// A transport failure must not describe itself to the caller: the reference
	// answers a generic 500 with no code for anything that is not one of its own
	// coded errors (auth.router.ts:189-196).
	if envelope := HTTPErrorFor(err); envelope != HTTPErrInternal {
		t.Errorf("wire envelope = %+v, want the generic 500 %+v", envelope, HTTPErrInternal)
	}
}

func TestSendSMSCodeWithoutASender(t *testing.T) {
	spy := &deliverySpy{}
	svc := newDeliverySvc(t, spy, true, false)
	user := seedPhoneUser(t, svc, "nosms@example.com", "+15555550100")

	code, err := svc.SendSMSCode(context.Background(), SMSCodeSendInput{UserID: user.ID, TenantID: "t1"})
	if !errors.Is(err, ErrSMSNotConfigured) {
		t.Fatalf("err = %v, want ErrSMSNotConfigured", err)
	}
	if code != "" {
		t.Errorf("code = %q, want empty", code)
	}
	if stored := storedUser(t, svc, user.ID).SMSCodeHash; stored != "" {
		t.Errorf("a code was stored anyway: %q", stored)
	}
	if HTTPErrorFor(err) != HTTPErrSMSNotConfigured {
		t.Errorf("wire envelope = %+v, want %+v", HTTPErrorFor(err), HTTPErrSMSNotConfigured)
	}
}

func TestSendSMSCodeDeliversThePlaintextCode(t *testing.T) {
	spy := &deliverySpy{}
	svc := newDeliverySvc(t, spy, false, true)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedPhoneUser(t, svc, "smsdelivered@example.com", "+15555550101")

	code, err := svc.SendSMSCode(context.Background(), SMSCodeSendInput{UserID: user.ID, TenantID: "t1"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(spy.smsCodes) != 1 {
		t.Fatalf("sender was called %d times, want 1", len(spy.smsCodes))
	}
	got := spy.smsCodes[0]
	if got.Code != code {
		t.Errorf("delivered code %q, returned %q", got.Code, code)
	}
	if got.Phone != "+15555550101" {
		t.Errorf("phone = %q, want the stored number", got.Phone)
	}
	if got.UserID != user.ID || got.TenantID != "t1" {
		t.Errorf("delivery = %+v, want %s/t1", got, user.ID)
	}
	if !got.ExpiresAt.Equal(now.Add(svc.cfg.SMSCodeTTL)) {
		t.Errorf("expiry = %v, want %v", got.ExpiresAt, now.Add(svc.cfg.SMSCodeTTL))
	}
	if stored := storedUser(t, svc, user.ID).SMSCodeHash; stored != hashToken(got.Code) {
		t.Errorf("stored hash %q does not match the delivered code", stored)
	}
}

// A user with no phone number is still silent, and silent means no delivery
// attempt at all: the code is never minted, so there is nothing to send.
func TestSendSMSCodeWithoutAPhoneNumberDoesNotDeliver(t *testing.T) {
	spy := &deliverySpy{}
	svc := newDeliverySvc(t, spy, false, true)
	user := seedUser(t, svc, "smsnophone@example.com")

	code, err := svc.SendSMSCode(context.Background(), SMSCodeSendInput{UserID: user.ID, TenantID: "t1"})
	if err != nil || code != "" {
		t.Fatalf("send = %q, %v; want empty and no error", code, err)
	}
	if len(spy.smsCodes) != 0 {
		t.Errorf("sender was called for a user with no number: %+v", spy.smsCodes)
	}
}

func TestSendSMSCodeKeepsTheCodeWhenDeliveryFails(t *testing.T) {
	gatewayDown := errors.New("sms gateway 503")
	spy := &deliverySpy{fail: gatewayDown}
	svc := newDeliverySvc(t, spy, false, true)
	user := seedPhoneUser(t, svc, "smsfailed@example.com", "+15555550102")

	_, err := svc.SendSMSCode(context.Background(), SMSCodeSendInput{UserID: user.ID, TenantID: "t1"})
	if !errors.Is(err, gatewayDown) {
		t.Fatalf("err = %v, want it to wrap the gateway failure", err)
	}
	if storedUser(t, svc, user.ID).SMSCodeHash == "" {
		t.Error("the stored code was rolled back")
	}
	if envelope := HTTPErrorFor(err); envelope != HTTPErrInternal {
		t.Errorf("wire envelope = %+v, want the generic 500 %+v", envelope, HTTPErrInternal)
	}
}

// TestSMSConfiguredReportsTheSeam pins the predicate /sms/send prechecks with.
func TestSMSConfiguredReportsTheSeam(t *testing.T) {
	bare, err := New(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if bare.SMSConfigured() {
		t.Error("SMSConfigured is true with no sender wired")
	}

	wired, err := New(
		WithUserStore(NewMemoryUserStore()),
		WithSessionStore(NewMemorySessionStore()),
		WithSMSCodeSender(func(context.Context, SMSCodeDelivery) error { return nil }),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !wired.SMSConfigured() {
		t.Error("SMSConfigured is false with a sender wired")
	}
}

// A nil sender is a configuration mistake worth catching at startup, since the
// alternative is a 500 on first use that looks exactly like no sender at all.
func TestSenderOptionsRejectNil(t *testing.T) {
	if _, err := New(WithMagicLinkSender(nil)); err == nil {
		t.Error("WithMagicLinkSender(nil) must fail")
	}
	if _, err := New(WithSMSCodeSender(nil)); err == nil {
		t.Error("WithSMSCodeSender(nil) must fail")
	}
}

// -----------------------------------------------------------------------------
// literals and ready-made senders
// -----------------------------------------------------------------------------

// TestMagicLinkURLShape pins the link the reference mails
// (magic-link.strategy.ts:23-27). The verify route and every shipped client are
// built against this shape.
func TestMagicLinkURLShape(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"https://app.example.com/auth", "https://app.example.com/auth/magic-link/verify?token=tok"},
		// The reference strips exactly one trailing slash before appending.
		{"https://app.example.com/auth/", "https://app.example.com/auth/magic-link/verify?token=tok"},
		{"https://app.example.com/auth/ui", "https://app.example.com/auth/ui/magic-link/verify?token=tok"},
		// An unset base yields a relative link, as the reference does with no
		// siteUrl configured. It is a misconfiguration in both, not a fallback.
		{"", "/magic-link/verify?token=tok"},
	}
	for _, tc := range cases {
		if got := MagicLinkURL(tc.base, "tok"); got != tc.want {
			t.Errorf("MagicLinkURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

// TestSMSCodeMessageLiteral pins the text that reaches a handset
// (sms.strategy.ts:20).
func TestSMSCodeMessageLiteral(t *testing.T) {
	if got := SMSCodeMessage("123456"); got != "Your verification code is: 123456" {
		t.Errorf("SMSCodeMessage = %q", got)
	}
}

type recordingMailer struct {
	sent []MailMessage
	fail error
}

func (m *recordingMailer) Send(_ context.Context, msg MailMessage) error {
	m.sent = append(m.sent, msg)
	return m.fail
}

func TestMagicLinkMailerRendersAndSends(t *testing.T) {
	transport := &recordingMailer{}
	mailer := NewMagicLinkMailer(transport, "Example App", "https://app.example.com/auth")

	err := mailer.Send(context.Background(), MagicLinkDelivery{
		Email: "mailed@example.com", Token: "tok123", UserID: "usr_1", TenantID: "t1",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(transport.sent) != 1 {
		t.Fatalf("transport was called %d times, want 1", len(transport.sent))
	}
	msg := transport.sent[0]
	if msg.To != "mailed@example.com" {
		t.Errorf("To = %q", msg.To)
	}
	if !msg.IsHTML {
		t.Error("the built-in templates are HTML")
	}
	if msg.Subject != "Example App - Magic Link Login" {
		t.Errorf("Subject = %q", msg.Subject)
	}
	link := "https://app.example.com/auth/magic-link/verify?token=tok123"
	if !strings.Contains(msg.Body, link) {
		t.Errorf("body does not carry the link %q: %s", link, msg.Body)
	}
}

// An "it" locale picks the Italian template set; anything unknown falls back to
// English rather than failing to send.
func TestMagicLinkMailerLocale(t *testing.T) {
	for locale, wantSubject := range map[string]string{
		"it": "Example App - Magic Link Accesso",
		"en": "Example App - Magic Link Login",
		"":   "Example App - Magic Link Login",
		"de": "Example App - Magic Link Login",
	} {
		transport := &recordingMailer{}
		mailer := NewMagicLinkMailer(transport, "Example App", "https://app.example.com/auth")
		mailer.Locale = locale
		if err := mailer.Send(context.Background(), MagicLinkDelivery{Email: "l@example.com", Token: "t"}); err != nil {
			t.Fatalf("locale %q: %v", locale, err)
		}
		if got := transport.sent[0].Subject; got != wantSubject {
			t.Errorf("locale %q subject = %q, want %q", locale, got, wantSubject)
		}
	}
}

func TestMagicLinkMailerWithoutATransport(t *testing.T) {
	var mailer MagicLinkMailer
	if err := mailer.Send(context.Background(), MagicLinkDelivery{Email: "x@example.com"}); err == nil {
		t.Error("a mailer with no transport must fail rather than silently succeed")
	}
}

type recordingSMS struct {
	phones   []string
	messages []string
	fail     error
}

func (s *recordingSMS) Send(_ context.Context, phone, message string) error {
	s.phones = append(s.phones, phone)
	s.messages = append(s.messages, message)
	return s.fail
}

func TestSMSTransportSenderFormatsTheCode(t *testing.T) {
	transport := &recordingSMS{}
	sender := SMSTransportSender(transport)

	if err := sender(context.Background(), SMSCodeDelivery{Phone: "+15555550103", Code: "424242"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(transport.phones) != 1 || transport.phones[0] != "+15555550103" {
		t.Errorf("phones = %v", transport.phones)
	}
	if transport.messages[0] != "Your verification code is: 424242" {
		t.Errorf("message = %q", transport.messages[0])
	}
}

func TestSMSTransportSenderWithoutATransport(t *testing.T) {
	if err := SMSTransportSender(nil)(context.Background(), SMSCodeDelivery{}); err == nil {
		t.Error("a nil transport must fail rather than silently succeed")
	}
}

// TestHTTPSMSTransportRequestShape pins the gateway contract the rest of the
// family speaks: GET, credentials and payload as query parameters, API key in an
// X-API-Key header (sms.service.ts:16-46). A deployment's existing gateway is
// built to accept exactly this.
func TestHTTPSMSTransportRequestShape(t *testing.T) {
	type captured struct {
		method string
		path   string
		query  map[string]string
		apiKey string
	}
	var got captured
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.apiKey = r.Header.Get("X-API-Key")
		got.query = make(map[string]string)
		for key, values := range r.URL.Query() {
			got.query[key] = values[0]
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// The endpoint carries a parameter of its own; it has to survive.
	transport := NewHTTPSMSTransport(server.URL+"/send?account=acct1", "key-abc", "gwuser", "gwpass")
	if err := transport.Send(context.Background(), "+15555550104", "hello"); err != nil {
		t.Fatalf("send: %v", err)
	}

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if got.path != "/send" {
		t.Errorf("path = %q", got.path)
	}
	if got.apiKey != "key-abc" {
		t.Errorf("X-API-Key = %q", got.apiKey)
	}
	for key, want := range map[string]string{
		"username": "gwuser",
		"password": "gwpass",
		"phone":    "+15555550104",
		"message":  "hello",
		"account":  "acct1",
	} {
		if got.query[key] != want {
			t.Errorf("query %s = %q, want %q", key, got.query[key], want)
		}
	}
}

// The header is sent even when the key is blank: a gateway that keys on its
// presence must not see the request change shape because a deployment left the
// value empty, which is how the reference behaves.
func TestHTTPSMSTransportAlwaysSendsTheAPIKeyHeader(t *testing.T) {
	present := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Api-Key"]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPSMSTransport(server.URL, "", "u", "p")
	if err := transport.Send(context.Background(), "+1", "m"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !present {
		t.Error("X-API-Key was omitted for an empty key")
	}
}

// 2xx only, as the reference has it: a 3xx or a 204-shaped success from a
// misbehaving gateway must not read as delivered.
func TestHTTPSMSTransportRejectsNon2xx(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusBadRequest, http.StatusInternalServerError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		transport := NewHTTPSMSTransport(server.URL, "k", "u", "p")
		err := transport.Send(context.Background(), "+1", "m")
		server.Close()
		if err == nil {
			t.Errorf("status %d was accepted as delivered", status)
		}
	}
}

func TestHTTPSMSTransportRejectsAnUnparseableEndpoint(t *testing.T) {
	transport := NewHTTPSMSTransport("http://[::1", "k", "u", "p")
	if err := transport.Send(context.Background(), "+1", "m"); err == nil {
		t.Error("an unparseable endpoint must fail")
	}
}
