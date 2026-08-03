package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// This file holds the vocabulary the passwordless entry points (magic link,
// SMS OTP) and the TOTP second factor share: the step-up token, the mode
// switch, the error catalog entries those routes emit and the route-specific
// sentinel mappings. It sits in the root package for the same reason wire.go
// does — eight routes across four adapters is thirty-two chances for a literal
// to drift, and every one of these literals is on the wire.
//
// The shapes are wire-contract §3 (awesome-node-auth@cc01e997). Deviations are
// called out where they exist.

// StepUpMode is the only value of the `mode` field the routes special-case.
const StepUpMode = "2fa"

// TwoFactorMode reports whether a magic-link or SMS request asked for the
// second-factor branch.
//
// The comparison is literal and case-sensitive because the reference's is
// (`mode === '2fa'`, auth.router.ts:1087, :1134, :1192, :1255): "login", the
// empty string, and anything else all take the login branch. That is what makes
// the two shipped clients interchangeable — Angular sends mode:"login", Flutter
// omits the field — so loosening this comparison silently reroutes one of them.
func TwoFactorMode(mode string) bool { return mode == StepUpMode }

// Error codes for this section of the contract.
const (
	CodeTempTokenRequired = "TEMP_TOKEN_REQUIRED"
	CodeInvalidTempToken  = "INVALID_TEMP_TOKEN"
	// CodeInvalidAccessToken is what /2fa/verify answers for a bad step-up
	// token where its siblings answer INVALID_TEMP_TOKEN. See
	// HTTPErrInvalidStepUpToken.
	CodeInvalidAccessToken = "INVALID_ACCESS_TOKEN"
	CodeInvalidMagicLink   = "INVALID_MAGIC_LINK"
	CodeTokenMismatch      = "TOKEN_MISMATCH"
	CodePhoneNotSet        = "PHONE_NOT_SET"
)

// The catalog entries these routes write. Several carry no code: the reference
// answers those inline rather than through its AuthError path, and the omission
// is exact, not an oversight (wire-contract §3, "Shared mechanics").
var (
	HTTPErrTempTokenRequired = HTTPError{Status: http.StatusBadRequest, Message: "tempToken is required for 2FA mode", Code: CodeTempTokenRequired}
	HTTPErrInvalidTempToken  = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired temp token", Code: CodeInvalidTempToken}

	// HTTPErrInvalidStepUpToken is /2fa/verify's answer to the failure the
	// magic-link and SMS routes answer with HTTPErrInvalidTempToken. The
	// reference verifies the tempToken there through verifyAccessToken and lets
	// its AuthError through unchanged (auth.router.ts:862 vs :1096, :1144,
	// :1201, :1264), so the same failure has two codes depending on the 2FA
	// method. It is reproduced rather than harmonised: a client that special-
	// cases TOTP today would break if this route started agreeing with its
	// siblings.
	HTTPErrInvalidStepUpToken = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired access token", Code: CodeInvalidAccessToken}

	HTTPErrEmailRequired         = HTTPError{Status: http.StatusBadRequest, Message: "email is required"}
	HTTPErrUserIDOrEmailRequired = HTTPError{Status: http.StatusBadRequest, Message: "userId or email is required"}
	HTTPErrUserIDRequired        = HTTPError{Status: http.StatusBadRequest, Message: "userId is required"}
	HTTPErrPhoneNotSet           = HTTPError{Status: http.StatusBadRequest, Message: "User does not have a phone number configured", Code: CodePhoneNotSet}

	HTTPErrInvalidSMSCode = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid or expired SMS code"}

	// HTTPErrInvalidMagicLink covers both of the reference's magic-link
	// failures. The reference splits them — INVALID_MAGIC_LINK for a token it
	// cannot find, MAGIC_LINK_EXPIRED for one past its TTL
	// (magic-link.strategy.ts:41-49) — but Service.VerifyMagicLink collapses
	// the two into ErrInvalidToken, so the expiry code is not reachable from
	// here. Splitting the sentinel is the fix; both are 401 either way.
	HTTPErrInvalidMagicLink = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid magic link token", Code: CodeInvalidMagicLink}
	HTTPErrTokenMismatch    = HTTPError{Status: http.StatusUnauthorized, Message: "Token mismatch", Code: CodeTokenMismatch}

	// The two "Invalid TOTP code" entries differ only in status: /2fa/verify
	// answers 401 (auth.router.ts:869-872), /2fa/verify-setup answers 400
	// (:847-850).
	HTTPErrInvalidTOTPCode      = HTTPError{Status: http.StatusUnauthorized, Message: "Invalid TOTP code"}
	HTTPErrInvalidTOTPSetupCode = HTTPError{Status: http.StatusBadRequest, Message: "Invalid TOTP code"}
	HTTPErrTOTPNotSetUp         = HTTPError{Status: http.StatusBadRequest, Message: "User not found or 2FA not set up"}

	HTTPErrTwoFactorRequiredForUser  = HTTPError{Status: http.StatusForbidden, Message: "Cannot disable 2FA: required for your account", Code: CodeTwoFactorRequired}
	HTTPErrTwoFactorRequiredByPolicy = HTTPError{Status: http.StatusForbidden, Message: "Cannot disable 2FA: required by system policy", Code: CodeTwoFactorRequired}
)

// tokenTypeTemp marks the step-up token.
//
// The reference mints its tempToken as an ordinary access token with a 5-minute
// lifetime and no claim distinguishing it (token.service.ts:20-24), which means
// a full access token also passes as a tempToken and a tempToken authenticates
// any protected route for five minutes. This port types it instead: the token
// is opaque to every client, so the type claim is not on the wire, and the
// confusion the reference's sharing allows is not worth reproducing. The
// consequence — a step-up token cannot be used as a session credential, or vice
// versa — is [UNTESTED] in the reference and no shipped client depends on it.
const tokenTypeTemp = "temp"

// TempTokenSubject is the identity a step-up token names. It is deliberately
// not a User: the routes that accept a tempToken re-read the user from the
// store, as the reference does, so a flag set since the token was minted is
// honoured.
type TempTokenSubject struct {
	UserID   string
	TenantID string
}

// IssueTempToken mints the step-up token a 2FA challenge hands the client. Its
// lifetime is Config.TempTokenTTL, 5 minutes by default, matching the
// reference's hardcoded '5m'.
func (s *Service) IssueTempToken(ctx context.Context, user User) (string, error) {
	token, _, err := s.issueToken(ctx, user, "", tokenTypeTemp, s.cfg.TempTokenTTL)
	return token, err
}

// VerifyTempToken resolves the identity a step-up token names, or
// ErrInvalidToken.
func (s *Service) VerifyTempToken(token string) (TempTokenSubject, error) {
	claims, err := s.parseToken(token, tokenTypeTemp)
	if err != nil {
		return TempTokenSubject{}, err
	}
	return TempTokenSubject{UserID: claims.Sub, TenantID: claims.Tid}, nil
}

// FindUser resolves a user by id, or by email when no id is given. The
// passwordless routes need it because they have to tell "no such user" apart
// from "that user has no phone number" — two different statuses in the contract
// — and the send calls answer both with silence.
func (s *Service) FindUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	return s.resolveUser(ctx, userID, email, tenantID)
}

// TOTPSetup is the enrolment material POST /2fa/setup hands back. Enrolment is
// stateless in the reference and stateless here: nothing is persisted until the
// client returns the secret to /2fa/verify-setup together with a code that
// verifies against it.
//
// The reference also returns a `qrCode` PNG data URL. It is absent here: the
// root package is stdlib plus golang.org/x/crypto and a QR encoder is neither.
// A client renders OTPAuthURL itself, which is what the Rust port of this
// family does too.
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauthUrl"`
}

// StartTOTPEnrolment mints an enrolment secret and its provisioning URI.
func (s *Service) StartTOTPEnrolment(ctx context.Context, userID, tenantID string) (TOTPSetup, error) {
	user, err := s.users.GetUserByID(ctx, userID, tenantID)
	if err != nil {
		return TOTPSetup{}, ErrInvalidCredentials
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		return TOTPSetup{}, err
	}
	return TOTPSetup{Secret: secret, OTPAuthURL: totpProvisioningURI(secret, user.Email, s.cfg.Issuer)}, nil
}

// totpProvisioningURI renders the otpauth:// URI an authenticator app scans.
// The parameters are spelled out rather than left to the app's defaults so that
// a client rendering the URI as a QR code cannot enrol against a different step
// or digit count than validateTOTPCode checks.
//
// The issuer label is Config.Issuer. The reference has a dedicated
// twoFactor.appName for it; adding that config field belongs with the rest of
// the config alignment.
func totpProvisioningURI(secret, account, issuer string) string {
	params := url.Values{}
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("issuer", issuer)
	params.Set("period", "30")
	params.Set("secret", secret)
	return "otpauth://totp/" + url.PathEscape(account) + "?" + params.Encode()
}

// MagicLinkVerifyHTTPError maps a Service.VerifyMagicLink failure. See
// HTTPErrInvalidMagicLink for why the expiry code does not appear.
func MagicLinkVerifyHTTPError(err error) HTTPError {
	if errors.Is(err, ErrInvalidToken) {
		return HTTPErrInvalidMagicLink
	}
	return HTTPErrorFor(err)
}

// SMSVerifyHTTPError maps a Service.VerifySMSCode failure.
//
// ErrInvalidCredentials means the userId or tempToken named a user the store
// does not have, and that is 401 "Invalid or expired SMS code", not 404.
// The reference looks the user up inside the strategy, where a miss is
// indistinguishable from a bad code: sms.strategy.ts:24-25 returns false for an
// unknown id, and the router turns false into
// 401 {"error":"Invalid or expired SMS code"} (auth.router.ts:1275-1279). Its
// 404 (:1281-1284) sits *after* that check and only fires if the user vanished
// between the verify and the follow-up findById — a race this port cannot
// reproduce, because Service.VerifySMSCode does both in one call. Answering 404
// here would both change the status a client sees for a stale userId and turn an
// unauthenticated route into a user-existence oracle the reference does not
// have.
func SMSVerifyHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrInvalidCredentials):
		return HTTPErrInvalidSMSCode
	default:
		return HTTPErrorFor(err)
	}
}

// TOTPVerifyHTTPError maps a Service.VerifyTOTP failure (POST /2fa/verify).
func TOTPVerifyHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCode):
		return HTTPErrInvalidTOTPCode
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrTOTPNotSetUp
	default:
		return HTTPErrorFor(err)
	}
}

// TOTPSetupHTTPError maps a Service.VerifyTOTPSetup failure (POST
// /2fa/verify-setup), where a bad code is a 400 rather than the 401 the
// step-up route answers.
func TOTPSetupHTTPError(err error) HTTPError {
	if errors.Is(err, ErrInvalidCode) {
		return HTTPErrInvalidTOTPSetupCode
	}
	return HTTPErrorFor(err)
}

// StepUpSubject resolves the tempToken a 2FA-mode request carries, reporting
// the envelope to write when it cannot.
//
// The two error arguments are what keeps the reference's inconsistency
// reproducible without spreading it through the handlers: the magic-link and
// SMS routes pass HTTPErrTempTokenRequired and HTTPErrInvalidTempToken, while
// /2fa/verify passes HTTPErrInvalidStepUpToken for both — it has no
// missing-token branch at all, so an absent tempToken simply fails
// verification there.
func (a *Auth) StepUpSubject(tempToken string, missing, invalid HTTPError) (TempTokenSubject, HTTPError, bool) {
	if strings.TrimSpace(tempToken) == "" {
		return TempTokenSubject{}, missing, false
	}
	subject, err := a.service.VerifyTempToken(tempToken)
	if err != nil {
		return TempTokenSubject{}, invalid, false
	}
	return subject, HTTPError{}, true
}

// TwoFactorPolicy reports whether the deployment requires a second factor of
// every user. It is the port's equivalent of the reference's settingsStore
// require2FA flag, which is what /2fa/disable refuses on.
func (a *Auth) TwoFactorPolicy() bool { return a.service.cfg.Require2FA }

// IssueTempToken delegates to Service.IssueTempToken.
func (a *Auth) IssueTempToken(ctx context.Context, user User) (string, error) {
	return a.service.IssueTempToken(ctx, user)
}

// FindUser delegates to Service.FindUser.
func (a *Auth) FindUser(ctx context.Context, userID, email, tenantID string) (User, error) {
	return a.service.FindUser(ctx, userID, email, tenantID)
}

// SendMagicLink delegates to Service.SendMagicLink.
func (a *Auth) SendMagicLink(ctx context.Context, in MagicLinkSendInput) (string, error) {
	return a.service.SendMagicLink(ctx, in)
}

// VerifyMagicLink delegates to Service.VerifyMagicLink.
func (a *Auth) VerifyMagicLink(ctx context.Context, in MagicLinkVerifyInput) (User, AuthTokens, error) {
	return a.service.VerifyMagicLink(ctx, in)
}

// SendSMSCode delegates to Service.SendSMSCode.
func (a *Auth) SendSMSCode(ctx context.Context, in SMSCodeSendInput) (string, error) {
	return a.service.SendSMSCode(ctx, in)
}

// VerifySMSCode delegates to Service.VerifySMSCode.
func (a *Auth) VerifySMSCode(ctx context.Context, in SMSCodeVerifyInput) (User, AuthTokens, error) {
	return a.service.VerifySMSCode(ctx, in)
}

// StartTOTPEnrolment delegates to Service.StartTOTPEnrolment.
func (a *Auth) StartTOTPEnrolment(ctx context.Context, userID, tenantID string) (TOTPSetup, error) {
	return a.service.StartTOTPEnrolment(ctx, userID, tenantID)
}

// VerifyTOTPSetup delegates to Service.VerifyTOTPSetup.
func (a *Auth) VerifyTOTPSetup(ctx context.Context, userID, tenantID, secret, code string) error {
	return a.service.VerifyTOTPSetup(ctx, userID, tenantID, secret, code)
}

// VerifyTOTP delegates to Service.VerifyTOTP.
func (a *Auth) VerifyTOTP(ctx context.Context, userID, tenantID, code string) (User, AuthTokens, error) {
	return a.service.VerifyTOTP(ctx, userID, tenantID, code)
}

// DisableTOTP delegates to Service.DisableTOTP.
func (a *Auth) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	return a.service.DisableTOTP(ctx, userID, tenantID)
}
