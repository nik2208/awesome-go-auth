package wiretest

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the passwordless entry points and the TOTP second
// factor: wire-contract §3.
//
// The credential the send routes mint never reaches the response, so the
// assertions come at it from two sides: the body is pinned to exactly
// {"success":true}, and the store is read directly to prove the route really
// did mint and persist something. A handler that returned 200 without calling
// the service passes the first and fails the second.

const testTenant = "t1"

// phoneUserStore gives every user a phone number on the id and email lookups.
// The port has no add-phone route yet (that is item 4 of the umbrella issue),
// and /sms/send branches on the stored number, so the store is where the fact
// has to come from.
type phoneUserStore struct {
	*auth.MemoryUserStore
	phone string
}

func (s phoneUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
	if err == nil {
		user.PhoneNumber = s.phone
	}
	return user, err
}

func (s phoneUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByEmail(ctx, email, tenantID)
	if err == nil {
		user.PhoneNumber = s.phone
	}
	return user, err
}

// require2FAUserStore flags require2FA on the id lookup only. Login reads the
// user by email and therefore still succeeds, which is exactly the case
// /2fa/disable has to handle: a flag set after the caller's token was issued.
// A handler that trusted the token's user instead of re-reading would let the
// disable through.
type require2FAUserStore struct {
	*auth.MemoryUserStore
}

func (s require2FAUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	user, err := s.MemoryUserStore.GetUserByID(ctx, id, tenantID)
	if err == nil {
		user.Require2FA = true
	}
	return user, err
}

// totpCode is an independent RFC 6238 implementation. Generating the code with
// the library's own helper would make every TOTP assertion here tautological.
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode totp secret %q: %v", secret, err)
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		uint32(sum[offset+3])&0xff
	return fmt.Sprintf("%06d", truncated%1000000)
}

// bearer marks a request as a bearer client and, when a token is given,
// authenticates it.
func bearer(req *http.Request, accessToken string) *http.Request {
	req.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	return req
}

// csrfMirror replays a response's cookies and mirrors the CSRF one into the
// double-submit header, the way a browser client does.
func csrfMirror(req *http.Request, rec *httptest.ResponseRecorder) *http.Request {
	Replay(req, rec)
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, auth.CSRFTokenCookieName) && c.Value != "" {
			req.Header.Set(auth.CSRFHeaderName, c.Value)
		}
	}
	return req
}

func storedUser(t *testing.T, store *auth.MemoryUserStore, id string) auth.User {
	t.Helper()
	user, err := store.GetUserByID(context.Background(), id, testTenant)
	if err != nil {
		t.Fatalf("read back user %q: %v", id, err)
	}
	return user
}

func tempTokenFor(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	token, err := env.Auth.IssueTempToken(context.Background(), user)
	if err != nil {
		t.Fatalf("issue temp token: %v", err)
	}
	return token
}

// -----------------------------------------------------------------------------
// magic link
// -----------------------------------------------------------------------------

func testMagicLink(t *testing.T, mount Mounter) {
	t.Run("send stores a link and answers with nothing else", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		user, _ := env.Seed("magic@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "magic@example.com", "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		if storedUser(t, store, user.ID).MagicLinkTokenHash == "" {
			t.Fatal("no magic-link token was stored: the route answered without doing anything")
		}
	})

	t.Run("send is silent about an unknown address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "nobody@example.com", "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	// Code-less on purpose: the reference answers this one inline.
	t.Run("send without an address", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"tenantId": testTenant}))
		AssertError(t, rec, http.StatusBadRequest, "email is required", "")
	})

	t.Run("send in 2fa mode without a tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{"mode": auth.StepUpMode}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("send in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	// The address is the tempToken's, not the body's: otherwise anyone holding a
	// step-up token could have the link mailed somewhere else.
	t.Run("send in 2fa mode ignores the body address", func(t *testing.T) {
		store := auth.NewMemoryUserStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		subject, _ := env.Seed("subject@example.com")
		other, _ := env.Seed("other@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/send", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, subject),
			"email":     "other@example.com",
			"tenantId":  testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if storedUser(t, store, subject.ID).MagicLinkTokenHash == "" {
			t.Error("the step-up subject got no magic link")
		}
		if storedUser(t, store, other.ID).MagicLinkTokenHash != "" {
			t.Error("the body address got a magic link: the 2fa branch must ignore it")
		}
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicverify@example.com")
		token := magicLinkToken(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicbearer@example.com")
		token := magicLinkToken(t, env, user)

		rec := env.Do(bearer(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("verify with an unusable token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": "bogus"}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid magic link token", auth.CodeInvalidMagicLink)
	})

	t.Run("verify burns the link", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magiconce@example.com")
		token := magicLinkToken(t, env, user)

		AssertStatus(t, env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token})), http.StatusOK)
		replay := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{"token": token}))
		AssertError(t, replay, http.StatusUnauthorized, "Invalid magic link token", auth.CodeInvalidMagicLink)
	})

	t.Run("verify in 2fa mode without a tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode": auth.StepUpMode, "token": "irrelevant",
		}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("verify in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token", "token": "irrelevant",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("verify in 2fa mode issues tokens", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("magicstepup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, user),
			"token":     magicLinkToken(t, env, user),
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})

	// A link that belongs to somebody else must not complete the challenge, and
	// must not issue anything.
	t.Run("verify in 2fa mode refuses another user's link", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		subject, _ := env.Seed("stepupsubject@example.com")
		stranger, _ := env.Seed("stranger@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/magic-link/verify", map[string]any{
			"mode":      auth.StepUpMode,
			"tempToken": tempTokenFor(t, env, subject),
			"token":     magicLinkToken(t, env, stranger),
		}))

		AssertError(t, rec, http.StatusUnauthorized, "Token mismatch", auth.CodeTokenMismatch)
		AssertNoCookie(t, rec, hostAccess)
		AssertNoCookie(t, rec, hostRefresh)
	})
}

// magicLinkToken mints a link through the service. The send route drops the
// token — there is no mail transport in the port — so a test that wants to
// verify a link has to ask for one directly.
func magicLinkToken(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	token, err := env.Auth.SendMagicLink(context.Background(), auth.MagicLinkSendInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil {
		t.Fatalf("send magic link: %v", err)
	}
	if token == "" {
		t.Fatal("send magic link returned no token")
	}
	return token
}

// -----------------------------------------------------------------------------
// SMS OTP
// -----------------------------------------------------------------------------

func newPhoneEnv(t *testing.T, mount Mounter) (*Env, *auth.MemoryUserStore) {
	t.Helper()
	backing := auth.NewMemoryUserStore()
	store := phoneUserStore{MemoryUserStore: backing, phone: "+15555550100"}
	return NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store)), backing
}

func testSMSOTP(t *testing.T, mount Mounter) {
	t.Run("send by address stores a code and answers with nothing else", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("sms@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"email": "sms@example.com", "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if storedUser(t, store, user.ID).SMSCodeHash == "" {
			t.Fatal("no SMS code was stored: the route answered without doing anything")
		}
	})

	t.Run("send by id", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsid@example.com")

		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if storedUser(t, store, user.ID).SMSCodeHash == "" {
			t.Fatal("no SMS code was stored")
		}
	})

	// The asymmetry is the reference's: an unknown address is answered with
	// silence, an unknown id with a 404.
	t.Run("send to an unknown address is silent", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"email": "nobody@example.com", "tenantId": testTenant,
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
	})

	t.Run("send to an unknown id", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": "usr_missing", "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusNotFound, "User not found", "")
	})

	t.Run("send without an id or an address", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"tenantId": testTenant}))
		AssertError(t, rec, http.StatusBadRequest, "userId or email is required", "")
	})

	t.Run("send to a user with no phone number", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("nophone@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"userId": user.ID, "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusBadRequest, "User does not have a phone number configured", auth.CodePhoneNotSet)
	})

	t.Run("send in 2fa mode without a tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{"mode": auth.StepUpMode}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("send in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("send in 2fa mode", func(t *testing.T) {
		env, store := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsstepup@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/sms/send", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, user),
		}))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if storedUser(t, store, user.ID).SMSCodeHash == "" {
			t.Fatal("no SMS code was stored for the step-up subject")
		}
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsverify@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": code, "tenantId": testTenant,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsbearer@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(bearer(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": code, "tenantId": testTenant,
		}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	t.Run("verify with the wrong code", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smswrong@example.com")
		smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"userId": user.ID, "code": "000000", "tenantId": testTenant,
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired SMS code", "")
	})

	t.Run("verify without an id", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{"code": "123456"}))
		AssertError(t, rec, http.StatusBadRequest, "userId is required", "")
	})

	t.Run("verify in 2fa mode without a tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "code": "123456",
		}))
		AssertError(t, rec, http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
	})

	t.Run("verify in 2fa mode with an unusable tempToken", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": "not-a-token", "code": "123456",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired temp token", auth.CodeInvalidTempToken)
	})

	t.Run("verify in 2fa mode issues tokens", func(t *testing.T) {
		env, _ := newPhoneEnv(t, mount)
		user, _ := env.Seed("smsstepupverify@example.com")
		code := smsCode(t, env, user)

		rec := env.Do(env.Request(http.MethodPost, "/sms/verify", map[string]any{
			"mode": auth.StepUpMode, "tempToken": tempTokenFor(t, env, user), "code": code,
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
	})
}

// smsCode mints a code through the service: the send route drops it, because
// the port has no SMS transport to hand it to.
func smsCode(t *testing.T, env *Env, user auth.User) string {
	t.Helper()
	code, err := env.Auth.SendSMSCode(context.Background(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil {
		t.Fatalf("send sms code: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("sms code = %q, want six digits", code)
	}
	return code
}

// -----------------------------------------------------------------------------
// TOTP
// -----------------------------------------------------------------------------

func testTwoFactor(t *testing.T, mount Mounter) {
	t.Run("setup returns the enrolment material and nothing else", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("setup2fa@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		// No success envelope, and no qrCode: the reference's PNG data URL needs
		// a QR encoder this port does not carry.
		AssertKeys(t, body, "secret", "otpauthUrl")
		secret, _ := body["secret"].(string)
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil || secret == "" {
			t.Fatalf("secret = %q, want base32", secret)
		}
		want := "otpauth://totp/setup2fa@example.com?algorithm=SHA1&digits=6&issuer=awesome-go-auth&period=30&secret=" + secret
		if body["otpauthUrl"] != want {
			t.Fatalf("otpauthUrl = %v, want %q", body["otpauthUrl"], want)
		}
	})

	t.Run("setup is a fresh secret every call", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("setuptwice@example.com")
		first := Body(t, env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"]
		second := Body(t, env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"]
		if first == second {
			t.Fatal("two setups returned the same secret")
		}
	})

	// 403 with no code, as everywhere else behind the access-token middleware.
	t.Run("setup without a credential", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), ""))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	// Inherited ordering difference, pinned so it stays a decision. The
	// reference checks the access token first and the CSRF header second
	// (auth.middleware.ts:29-32 then :33-42), so a cookie client with neither
	// hears "No access token provided". This port runs CSRF as a middleware in
	// front of the auth middleware, so it hears CSRF_INVALID instead. Same
	// status, and the three enrolment routes are the first unsafe authenticated
	// routes in the port, which is why it only becomes visible here.
	t.Run("a cookie client with no credential is answered by CSRF first", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPost, "/2fa/setup", nil))
		AssertError(t, rec, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	t.Run("verify-setup enables the factor", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("enrol@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		me := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		AssertStatus(t, me, http.StatusOK)
		if Body(t, me)["isTotpEnabled"] != true {
			t.Fatalf("isTotpEnabled = %v after enrolment", Body(t, me)["isTotpEnabled"])
		}
	})

	// 400 here, 401 on /2fa/verify, both code-less: the two routes disagree in
	// the reference.
	t.Run("verify-setup with the wrong code", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("enrolbad@example.com")
		secret, _ := Body(t, env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), tokens.AccessToken)))["secret"].(string)

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
			"token": "000000", "secret": secret,
		}), tokens.AccessToken))
		AssertError(t, rec, http.StatusBadRequest, "Invalid TOTP code", "")
	})

	t.Run("verify in cookie mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepuptotp@example.com")
		secret := enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": totpCode(t, secret, time.Now()),
		}))

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertCookieAttrs(t, Cookie(t, rec, hostAccess), accessCookieSpec())
		AssertCookieAttrs(t, Cookie(t, rec, hostRefresh), refreshCookieSpec())
	})

	t.Run("verify in bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepuptotpbearer@example.com")
		secret := enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": totpCode(t, secret, time.Now()),
		}), ""))

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "accessToken", "refreshToken")
		assertNonEmptyString(t, body, "accessToken")
		assertNonEmptyString(t, body, "refreshToken")
		AssertNoCookies(t, rec)
	})

	// The documented inconsistency: the same failure the magic-link and SMS
	// routes report as INVALID_TEMP_TOKEN is INVALID_ACCESS_TOKEN here, and an
	// absent tempToken lands in the same place because this route has no
	// missing-token branch at all.
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{name: "an unusable tempToken", body: map[string]any{"tempToken": "not-a-token", "totpCode": "123456"}},
		{name: "no tempToken at all", body: map[string]any{"totpCode": "123456"}},
	} {
		t.Run("verify with "+tc.name, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig())
			rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", tc.body))
			AssertError(t, rec, http.StatusUnauthorized, "Invalid or expired access token", auth.CodeInvalidAccessToken)
		})
	}

	t.Run("verify with the wrong code", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("stepupbadcode@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": "000000",
		}))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid TOTP code", "")
		AssertNoCookie(t, rec, hostAccess)
	})

	t.Run("verify for a user who never enrolled", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, _ := env.Seed("neverenrolled@example.com")
		rec := env.Do(env.Request(http.MethodPost, "/2fa/verify", map[string]any{
			"tempToken": tempTokenFor(t, env, user), "totpCode": "123456",
		}))
		AssertError(t, rec, http.StatusBadRequest, "User not found or 2FA not set up", "")
	})

	t.Run("disable", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("disable2fa@example.com")
		enrolTOTP(t, env, tokens.AccessToken)

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		me := env.Do(bearer(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), tokens.AccessToken))
		if Body(t, me)["isTotpEnabled"] != false {
			t.Fatal("the factor survived /2fa/disable")
		}
	})

	t.Run("disable refuses a user who must keep 2FA", func(t *testing.T) {
		store := require2FAUserStore{MemoryUserStore: auth.NewMemoryUserStore()}
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(store))
		_, tokens := env.Seed("mustkeep@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required for your account", auth.CodeTwoFactorRequired)
	})

	t.Run("disable refuses under a system-wide policy", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithRequire2FA(true))
		_, tokens := env.Seed("policy@example.com")

		rec := env.Do(bearer(env.Request(http.MethodPost, "/2fa/disable", nil), tokens.AccessToken))
		AssertError(t, rec, http.StatusForbidden, "Cannot disable 2FA: required by system policy", auth.CodeTwoFactorRequired)
	})

	// The enrolment routes are the only three in this section behind the auth
	// middleware, so they are the only three a cookie client must double-submit
	// for. The four send/verify routes are unauthenticated and exempt, which the
	// cases above rely on by never sending a CSRF header.
	t.Run("setup is CSRF-protected for cookie clients", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("csrf2fa@example.com")
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("csrf2fa@example.com")))

		bare := env.Do(Replay(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertError(t, bare, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)

		mirrored := env.Do(csrfMirror(env.Request(http.MethodPost, "/2fa/setup", nil), login))
		AssertStatus(t, mirrored, http.StatusOK)
		AssertKeys(t, Body(t, mirrored), "secret", "otpauthUrl")
	})
}

// enrolTOTP walks the stateless enrolment: /2fa/setup hands out a secret, the
// client proves it can generate a code from it, and only then is it stored.
func enrolTOTP(t *testing.T, env *Env, accessToken string) string {
	t.Helper()
	setup := env.Do(bearer(env.Request(http.MethodPost, "/2fa/setup", nil), accessToken))
	AssertStatus(t, setup, http.StatusOK)
	secret, _ := Body(t, setup)["secret"].(string)
	if secret == "" {
		t.Fatal("setup returned no secret")
	}
	verify := env.Do(bearer(env.Request(http.MethodPost, "/2fa/verify-setup", map[string]any{
		"token": totpCode(t, secret, time.Now()), "secret": secret,
	}), accessToken))
	AssertStatus(t, verify, http.StatusOK)
	AssertKeys(t, Body(t, verify), "success")
	return secret
}

// -----------------------------------------------------------------------------
// the mode switch
// -----------------------------------------------------------------------------

// testStepUpModeDefault pins the client-pinned invariant from issue #22: `mode`
// is optional and only the exact string "2fa" selects the step-up branch. One
// shipped client sends mode:"login" and another omits the field, so every value
// that is not "2fa" — absent, "login", empty, wrongly cased, garbage — has to
// reach the identical branch.
//
// Each route is probed with a body that fails differently in the two branches:
// the login branch gets far enough to answer for the credential it was given,
// while the step-up branch stops at the missing tempToken. A handler that
// mistook any of these values for "2fa" answers 400 TEMP_TOKEN_REQUIRED and
// fails here.
func testStepUpModeDefault(t *testing.T, mount Mounter) {
	loginModes := []struct {
		name string
		mode any
	}{
		{name: "absent", mode: nil},
		{name: "login", mode: "login"},
		{name: "empty", mode: ""},
		{name: "wrongly cased", mode: "2FA"},
		{name: "garbage", mode: "banana"},
	}

	routes := []struct {
		name  string
		route string
		body  func(env *Env) map[string]any
		// login is the answer the login branch gives this body.
		status  int
		message string
		code    string
	}{
		{
			name:  "magic-link/send",
			route: "/magic-link/send",
			body: func(*Env) map[string]any {
				return map[string]any{"tenantId": testTenant}
			},
			status: http.StatusBadRequest, message: "email is required",
		},
		{
			name:  "magic-link/verify",
			route: "/magic-link/verify",
			body: func(*Env) map[string]any {
				return map[string]any{"token": "bogus"}
			},
			status: http.StatusUnauthorized, message: "Invalid magic link token", code: auth.CodeInvalidMagicLink,
		},
		{
			name:  "sms/send",
			route: "/sms/send",
			body: func(*Env) map[string]any {
				return map[string]any{"tenantId": testTenant}
			},
			status: http.StatusBadRequest, message: "userId or email is required",
		},
		{
			name:  "sms/verify",
			route: "/sms/verify",
			body: func(*Env) map[string]any {
				return map[string]any{"code": "123456"}
			},
			status: http.StatusBadRequest, message: "userId is required",
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, mode := range loginModes {
				t.Run(mode.name, func(t *testing.T) {
					env := NewEnv(t, mount, auth.DefaultHTTPConfig())
					body := route.body(env)
					if mode.mode != nil {
						body["mode"] = mode.mode
					}
					AssertError(t, env.Do(env.Request(http.MethodPost, route.route, body)), route.status, route.message, route.code)
				})
			}

			t.Run("2fa selects the step-up branch", func(t *testing.T) {
				env := NewEnv(t, mount, auth.DefaultHTTPConfig())
				body := route.body(env)
				body["mode"] = auth.StepUpMode
				AssertError(t, env.Do(env.Request(http.MethodPost, route.route, body)),
					http.StatusBadRequest, "tempToken is required for 2FA mode", auth.CodeTempTokenRequired)
			})
		})
	}
}
