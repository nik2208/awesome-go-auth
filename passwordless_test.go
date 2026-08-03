package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestStepUpErrorCatalogLiterals pins the wire strings of the passwordless and
// 2FA envelopes. Every one of them is read by a client, and several carry no
// code on purpose — an accidental code is as much a break as a wrong one.
func TestStepUpErrorCatalogLiterals(t *testing.T) {
	codes := map[string]string{
		CodeTempTokenRequired:  "TEMP_TOKEN_REQUIRED",
		CodeInvalidTempToken:   "INVALID_TEMP_TOKEN",
		CodeInvalidAccessToken: "INVALID_ACCESS_TOKEN",
		CodeInvalidMagicLink:   "INVALID_MAGIC_LINK",
		CodeTokenMismatch:      "TOKEN_MISMATCH",
		CodePhoneNotSet:        "PHONE_NOT_SET",
	}
	for got, want := range codes {
		if got != want {
			t.Errorf("code %q must be %q", got, want)
		}
	}

	entries := map[HTTPError]struct {
		status  int
		message string
		code    string
	}{
		HTTPErrTempTokenRequired: {400, "tempToken is required for 2FA mode", "TEMP_TOKEN_REQUIRED"},
		HTTPErrInvalidTempToken:  {401, "Invalid or expired temp token", "INVALID_TEMP_TOKEN"},
		// The same failure, one route apart: /2fa/verify says INVALID_ACCESS_TOKEN
		// where its siblings say INVALID_TEMP_TOKEN.
		HTTPErrInvalidStepUpToken:        {401, "Invalid or expired access token", "INVALID_ACCESS_TOKEN"},
		HTTPErrEmailRequired:             {400, "email is required", ""},
		HTTPErrUserIDOrEmailRequired:     {400, "userId or email is required", ""},
		HTTPErrUserIDRequired:            {400, "userId is required", ""},
		HTTPErrPhoneNotSet:               {400, "User does not have a phone number configured", "PHONE_NOT_SET"},
		HTTPErrInvalidSMSCode:            {401, "Invalid or expired SMS code", ""},
		HTTPErrInvalidMagicLink:          {401, "Invalid magic link token", "INVALID_MAGIC_LINK"},
		HTTPErrTokenMismatch:             {401, "Token mismatch", "TOKEN_MISMATCH"},
		HTTPErrInvalidTOTPCode:           {401, "Invalid TOTP code", ""},
		HTTPErrInvalidTOTPSetupCode:      {400, "Invalid TOTP code", ""},
		HTTPErrTOTPNotSetUp:              {400, "User not found or 2FA not set up", ""},
		HTTPErrTwoFactorRequiredForUser:  {403, "Cannot disable 2FA: required for your account", "2FA_REQUIRED"},
		HTTPErrTwoFactorRequiredByPolicy: {403, "Cannot disable 2FA: required by system policy", "2FA_REQUIRED"},
	}
	for got, want := range entries {
		if got.Status != want.status || got.Message != want.message || got.Code != want.code {
			t.Errorf("catalog entry %+v drifted from %d %q %q", got, want.status, want.message, want.code)
		}
	}
}

// TestTwoFactorModeIsExact pins the client-pinned invariant: only the literal
// "2fa" selects the step-up branch.
func TestTwoFactorModeIsExact(t *testing.T) {
	if !TwoFactorMode("2fa") {
		t.Error(`"2fa" must select the step-up branch`)
	}
	for _, mode := range []string{"", "login", "2FA", "2Fa", " 2fa", "2fa ", "twofactor"} {
		if TwoFactorMode(mode) {
			t.Errorf("mode %q must take the login branch", mode)
		}
	}
}

func TestStepUpErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		got  HTTPError
		want HTTPError
	}{
		{"magic link invalid", MagicLinkVerifyHTTPError(ErrInvalidToken), HTTPErrInvalidMagicLink},
		{"magic link store missing", MagicLinkVerifyHTTPError(ErrFeatureNotSupported), HTTPErrNotImplemented},
		{"sms wrong code", SMSVerifyHTTPError(ErrInvalidCode), HTTPErrInvalidSMSCode},
		// An unknown user is a bad credential here, not a 404: the reference
		// resolves the user inside the strategy, where a miss and a wrong code are
		// the same `return false` (sms.strategy.ts:24-25 -> auth.router.ts:1277).
		{"sms unknown user", SMSVerifyHTTPError(ErrInvalidCredentials), HTTPErrInvalidSMSCode},
		{"totp wrong code", TOTPVerifyHTTPError(ErrInvalidCode), HTTPErrInvalidTOTPCode},
		{"totp not enrolled", TOTPVerifyHTTPError(ErrInvalidCredentials), HTTPErrTOTPNotSetUp},
		{"totp setup wrong code", TOTPSetupHTTPError(ErrInvalidCode), HTTPErrInvalidTOTPSetupCode},
		{"totp setup store missing", TOTPSetupHTTPError(ErrFeatureNotSupported), HTTPErrNotImplemented},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
}

// seedUser puts a user straight into the store. It deliberately avoids
// Register: this package's test binary is already close to the default 10-minute
// go test timeout, almost all of it bcrypt, and none of the assertions below
// involve a password.
func seedUser(t *testing.T, svc *Service, email string) User {
	t.Helper()
	id, err := newID("usr")
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	user, err := svc.users.CreateUser(context.Background(), User{
		ID: id, Email: email, TenantID: "t1", IsEmailVerified: true, CreatedAt: svc.now(),
	})
	if err != nil {
		t.Fatalf("seed %s: %v", email, err)
	}
	return user
}

func TestTempTokenRoundTrip(t *testing.T) {
	svc := newTestSvc(t)
	user := seedUser(t, svc, "temp@example.com")

	token, err := svc.IssueTempToken(context.Background(), user)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	subject, err := svc.VerifyTempToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if subject.UserID != user.ID || subject.TenantID != "t1" {
		t.Fatalf("subject = %+v, want %s/t1", subject, user.ID)
	}
}

// TestTempTokenExpiresWithItsTTL pins the 5-minute lifetime. A step-up token
// that outlived its challenge would be a standing bypass of the second factor.
func TestTempTokenExpiresWithItsTTL(t *testing.T) {
	svc := newTestSvc(t)
	now := time.Now()
	svc.now = func() time.Time { return now }
	user := seedUser(t, svc, "tempexp@example.com")

	token, err := svc.IssueTempToken(context.Background(), user)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	svc.now = func() time.Time { return now.Add(4 * time.Minute) }
	if _, err := svc.VerifyTempToken(token); err != nil {
		t.Fatalf("still inside the 5 minute window: %v", err)
	}
	svc.now = func() time.Time { return now.Add(5*time.Minute + svc.cfg.ClockSkew + time.Second) }
	if _, err := svc.VerifyTempToken(token); err != ErrInvalidToken {
		t.Fatalf("expired temp token = %v, want ErrInvalidToken", err)
	}
}

// TestTempTokenIsNotASessionCredential is the deliberate deviation from the
// reference, which mints its tempToken as an ordinary access token and so lets
// each pass as the other. Typing the token is invisible on the wire; dropping
// the type would silently restore the confusion.
func TestTempTokenIsNotASessionCredential(t *testing.T) {
	svc := newTestSvc(t)
	user := seedUser(t, svc, "tempscope@example.com")
	tokens, err := svc.newSessionTokens(context.Background(), user)
	if err != nil {
		t.Fatalf("session tokens: %v", err)
	}

	if _, err := svc.VerifyTempToken(tokens.AccessToken); err != ErrInvalidToken {
		t.Errorf("an access token passed as a step-up token: %v", err)
	}
	temp, err2 := svc.IssueTempToken(context.Background(), user)
	if err2 != nil {
		t.Fatalf("issue: %v", err2)
	}
	if _, err := svc.Me(context.Background(), temp); err != ErrInvalidToken {
		t.Errorf("a step-up token authenticated a protected route: %v", err)
	}
}

func TestStepUpSubjectReportsTheRouteEnvelope(t *testing.T) {
	a, err := New(WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	user := seedUser(t, a.Service(), "stepup@example.com")

	if _, herr, ok := a.StepUpSubject("", HTTPErrTempTokenRequired, HTTPErrInvalidTempToken); ok || herr != HTTPErrTempTokenRequired {
		t.Errorf("missing token = %+v ok=%v", herr, ok)
	}
	if _, herr, ok := a.StepUpSubject("   ", HTTPErrTempTokenRequired, HTTPErrInvalidTempToken); ok || herr != HTTPErrTempTokenRequired {
		t.Errorf("blank token = %+v ok=%v", herr, ok)
	}
	if _, herr, ok := a.StepUpSubject("nonsense", HTTPErrTempTokenRequired, HTTPErrInvalidTempToken); ok || herr != HTTPErrInvalidTempToken {
		t.Errorf("unusable token = %+v ok=%v", herr, ok)
	}
	// /2fa/verify passes the same envelope twice: it has no missing-token branch.
	if _, herr, ok := a.StepUpSubject("", HTTPErrInvalidStepUpToken, HTTPErrInvalidStepUpToken); ok || herr != HTTPErrInvalidStepUpToken {
		t.Errorf("2fa/verify missing token = %+v ok=%v", herr, ok)
	}

	token, err := a.IssueTempToken(context.Background(), user)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	subject, herr, ok := a.StepUpSubject(token, HTTPErrTempTokenRequired, HTTPErrInvalidTempToken)
	if !ok || herr != (HTTPError{}) || subject.UserID != user.ID {
		t.Fatalf("valid token = %+v %+v ok=%v", subject, herr, ok)
	}
}

func TestStartTOTPEnrolmentIsStatelessAndFresh(t *testing.T) {
	svc := newTestSvc(t)
	user := seedUser(t, svc, "enrol@example.com")
	ctx := context.Background()

	first, err := svc.StartTOTPEnrolment(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	// The issuer label is Config.Issuer; the parameters are spelled out so that a
	// client cannot enrol against a different step or digit count than
	// validateTOTPCode checks.
	want := "otpauth://totp/enrol@example.com?algorithm=SHA1&digits=6&issuer=awesome-go-auth&period=30&secret=" + first.Secret
	if first.OTPAuthURL != want {
		t.Fatalf("otpauth url = %q, want %q", first.OTPAuthURL, want)
	}

	second, err := svc.StartTOTPEnrolment(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("enrol again: %v", err)
	}
	if second.Secret == first.Secret {
		t.Error("a second setup returned the same secret")
	}
	// Nothing is persisted until /2fa/verify-setup returns the secret.
	stored, err := svc.users.GetUserByID(ctx, user.ID, "t1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.TOTPSecret != "" || stored.IsTOTPEnabled {
		t.Errorf("enrolment persisted state: secret=%q enabled=%v", stored.TOTPSecret, stored.IsTOTPEnabled)
	}
}

func TestStartTOTPEnrolmentUnknownUser(t *testing.T) {
	svc := newTestSvc(t)
	if _, err := svc.StartTOTPEnrolment(context.Background(), "usr_missing", "t1"); err != ErrInvalidCredentials {
		t.Fatalf("unknown user = %v, want ErrInvalidCredentials", err)
	}
}

// The enrolment routes are the only three in this section the reference puts
// behind its auth middleware, and CSRF enforcement lives there.
func TestPasswordlessRoutesAreCSRFExempt(t *testing.T) {
	exempt := []string{"/magic-link/send", "/magic-link/verify", "/sms/send", "/sms/verify", "/2fa/verify"}
	enforced := []string{"/2fa/setup", "/2fa/verify-setup", "/2fa/disable"}
	prefix := DefaultAPIPrefix

	for _, route := range exempt {
		req := httptest.NewRequest(http.MethodPost, prefix+route, nil)
		if csrfEnforced(req, prefix) {
			t.Errorf("%s must not be CSRF-checked: it has no auth gate", route)
		}
	}
	for _, route := range enforced {
		req := httptest.NewRequest(http.MethodPost, prefix+route, nil)
		if !csrfEnforced(req, prefix) {
			t.Errorf("%s must be CSRF-checked: it sits behind the auth middleware", route)
		}
	}
}
