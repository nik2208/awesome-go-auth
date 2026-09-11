package auth

import (
	"context"
	"encoding/base32"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The exported parameters, as literals. The constants exist so that the URI and
// the verifier read one value; this pins what that value is, so a change to it
// is a visible act rather than a drift both sides follow together.
func TestTOTPParametersAreTheReferenceDefaults(t *testing.T) {
	if TOTPAlgorithm != "SHA1" || TOTPDigits != 6 || TOTPPeriod != 30*time.Second || TOTPSkew != 1 {
		t.Fatalf("TOTP parameters = %q/%d/%s/±%d, want SHA1/6/30s/±1",
			TOTPAlgorithm, TOTPDigits, TOTPPeriod, TOTPSkew)
	}
}

// RFC 6238 Appendix B, SHA1 column, truncated to six digits. The vectors are
// computed by the RFC, not by this package, so they are what makes the
// algorithm, digit count and period assertions non-circular: a verifier that
// silently moved to SHA256, eight digits or a 60-second step would fail here
// while the round-trip tests below still passed.
func TestValidateTOTPCode_RFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		at   int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		if !validateTOTPCode(secret, tc.code, time.Unix(tc.at, 0)) {
			t.Errorf("RFC 6238 vector at T=%d: %q was refused", tc.at, tc.code)
		}
		if got, _ := generateTOTPCode(secret, tc.at/int64(TOTPPeriod/time.Second)); got != tc.code {
			t.Errorf("generateTOTPCode at T=%d = %q, want %q", tc.at, got, tc.code)
		}
	}
}

// TOTPSkew is the whole tolerance: a code from one step either side is a valid
// code, a code from two steps either side is not.
func TestValidateTOTPCode_SkewIsExactlyTOTPSkew(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Unix(1234567890, 0)
	counter := now.Unix() / int64(TOTPPeriod/time.Second)
	for offset := int64(-TOTPSkew - 1); offset <= TOTPSkew+1; offset++ {
		code, ok := generateTOTPCode(secret, counter+offset)
		if !ok {
			t.Fatalf("generateTOTPCode at offset %d failed", offset)
		}
		want := offset >= -TOTPSkew && offset <= TOTPSkew
		if got := validateTOTPCode(secret, code, now); got != want {
			t.Errorf("a code from %+d steps away: accepted=%v, want %v", offset, got, want)
		}
	}
}

// totpEnrolmentURI runs an enrolment against a service built from cfg and
// returns the URI it handed back together with the secret in it.
func totpEnrolmentURI(t *testing.T, cfg Config, email string) (uri, secret string) {
	t.Helper()
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	user := seedUser(t, svc, email)
	setup, err := svc.StartTOTPEnrolment(context.Background(), user.ID, "t1")
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return setup.OTPAuthURL, setup.Secret
}

// The issuer of the provisioning URI: Config.TwoFactorAppName when set,
// Config.Issuer when not (deviation totp-issuer-defaults-to-config-issuer). It
// appears twice, as the label prefix and as the issuer parameter, in otplib's
// issuer:account form — the form the reference's totp.toURI emits (@otplib/uri
// 13.4.1 generateTOTP builds the label as `${issuer}:${label}` and
// encodeURIComponent-escapes each colon-separated piece).
func TestTOTPProvisioningURIIssuer(t *testing.T) {
	t.Run("TwoFactorAppName set", func(t *testing.T) {
		cfg := testConfig("totpissuer1234567890123456789012")
		cfg.TwoFactorAppName = "Example App"
		uri, secret := totpEnrolmentURI(t, cfg, "appname@example.com")
		want := "otpauth://totp/Example%20App:appname%40example.com?algorithm=SHA1&digits=6&issuer=Example%20App&period=30&secret=" + secret
		if uri != want {
			t.Fatalf("otpauth url = %q, want %q", uri, want)
		}
	})

	t.Run("TwoFactorAppName empty falls back to Issuer", func(t *testing.T) {
		cfg := testConfig("totpissuer1234567890123456789012")
		cfg.Issuer = "acme-auth"
		uri, secret := totpEnrolmentURI(t, cfg, "fallback@example.com")
		want := "otpauth://totp/acme-auth:fallback%40example.com?algorithm=SHA1&digits=6&issuer=acme-auth&period=30&secret=" + secret
		if uri != want {
			t.Fatalf("otpauth url = %q, want %q", uri, want)
		}
	})

	// A name is carried verbatim, so the reference's own fallback is one
	// WithTwoFactorAppName call away — that is what makes the default the only
	// difference.
	t.Run("the reference's fallback is reproducible", func(t *testing.T) {
		a, err := New(WithTwoFactorAppName("awesome-node-auth"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := a.service.cfg.totpIssuer(); got != "awesome-node-auth" {
			t.Fatalf("issuer = %q", got)
		}
		if got := DefaultConfig("01234567890123456789012345678901").totpIssuer(); got != "awesome-go-auth" {
			t.Fatalf("default issuer = %q, want Config.Issuer", got)
		}
	})
}

// The URI is built from the same constants the verifier reads, so a code an
// authenticator app derives from the URI's parameters is a code the server
// accepts — the whole reason the constants are shared.
func TestTOTPProvisioningURICarriesTheVerifierParameters(t *testing.T) {
	uri := totpProvisioningURI("SECRET", "user@example.com", "issuer")
	for _, param := range []string{
		"algorithm=" + TOTPAlgorithm,
		"digits=" + strconv.Itoa(TOTPDigits),
		"period=" + strconv.Itoa(int(TOTPPeriod/time.Second)),
	} {
		if !strings.Contains(uri, "&"+param+"&") && !strings.Contains(uri, "?"+param+"&") {
			t.Errorf("uri %q lacks %s", uri, param)
		}
	}
	// No issuer at all: bare label, no issuer parameter, as otplib emits.
	if got, want := totpProvisioningURI("SECRET", "user@example.com", ""),
		"otpauth://totp/user%40example.com?algorithm=SHA1&digits=6&period=30&secret=SECRET"; got != want {
		t.Errorf("no issuer: %q, want %q", got, want)
	}
	// A colon inside the issuer stays bare in the label, because otplib splits
	// the whole `issuer:label` on ":" before escaping and joins it back with
	// bare colons; in the issuer parameter it is escaped like anything else.
	if got, want := totpProvisioningURI("SECRET", "user@example.com", "acme:vote"),
		"otpauth://totp/acme:vote:user%40example.com?algorithm=SHA1&digits=6&issuer=acme%3Avote&period=30&secret=SECRET"; got != want {
		t.Errorf("colon in issuer: %q, want %q", got, want)
	}
}

func TestGenerateTOTPSecret_NonEmpty(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
}

func TestGenerateTOTPSecret_Uniqueness(t *testing.T) {
	a, _ := generateTOTPSecret()
	b, _ := generateTOTPSecret()
	if a == b {
		t.Fatal("TOTP secrets should be unique")
	}
}

func TestValidateTOTPCode_Valid(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	code, ok := generateTOTPCode(secret, now.Unix()/int64(TOTPPeriod/time.Second))
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	if !validateTOTPCode(secret, code, now) {
		t.Fatal("valid TOTP code should pass validation")
	}
}

func TestValidateTOTPCode_NonNumeric(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "abcdef", time.Now()) {
		t.Fatal("non-numeric code should fail")
	}
}

func TestValidateTOTPCode_WrongLength_Short(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "12345", time.Now()) {
		t.Fatal("5-digit code should fail")
	}
}

func TestValidateTOTPCode_WrongLength_Long(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "1234567", time.Now()) {
		t.Fatal("7-digit code should fail")
	}
}

func TestValidateTOTPCode_WindowTolerance_Prev(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	step := int64(TOTPPeriod / time.Second)
	prevCode, ok := generateTOTPCode(secret, now.Unix()/step-1)
	if !ok {
		t.Fatal("generateTOTPCode for prev step failed")
	}
	if !validateTOTPCode(secret, prevCode, now) {
		t.Fatal("previous step code should be accepted within tolerance window")
	}
}

func TestValidateTOTPCode_WindowTolerance_Next(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	step := int64(TOTPPeriod / time.Second)
	nextCode, ok := generateTOTPCode(secret, now.Unix()/step+1)
	if !ok {
		t.Fatal("generateTOTPCode for next step failed")
	}
	if !validateTOTPCode(secret, nextCode, now) {
		t.Fatal("next step code should be accepted within tolerance window")
	}
}

func TestGenerateTOTPCode_InvalidSecret(t *testing.T) {
	_, ok := generateTOTPCode("!!!INVALID!!!", 0)
	if ok {
		t.Fatal("expected failure for invalid base32 secret")
	}
}

func TestValidateTOTPCode_InvalidSecret(t *testing.T) {
	if validateTOTPCode("!!!INVALID!!!", "123456", time.Now()) {
		t.Fatal("invalid secret should fail validation")
	}
}

func TestGenerateTOTPCode_SameCounterSameCode(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code1, ok1 := generateTOTPCode(secret, 1000)
	code2, ok2 := generateTOTPCode(secret, 1000)
	if !ok1 || !ok2 {
		t.Fatal("generateTOTPCode failed")
	}
	if code1 != code2 {
		t.Fatal("same counter should produce same code (deterministic)")
	}
}

func TestGenerateTOTPCode_DifferentCountersDifferentCodes(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code1, ok1 := generateTOTPCode(secret, 1000)
	code2, ok2 := generateTOTPCode(secret, 2000)
	if !ok1 || !ok2 {
		t.Fatal("generateTOTPCode failed")
	}
	if code1 == code2 {
		t.Fatal("different counters should (very likely) produce different codes")
	}
}

func TestGenerateTOTPCode_SixDigits(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code, ok := generateTOTPCode(secret, 1234)
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	if len(code) != TOTPDigits {
		t.Fatalf("expected %d-digit code, got %q", TOTPDigits, code)
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Fatalf("code should contain only digits: %q", code)
		}
	}
}
