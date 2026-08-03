package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// This file holds the wire conventions for the password-management and
// email-verification group: forgot-password, reset-password, change-password,
// send-verification-email, GET verify-email, change-email/request and
// change-email/confirm.
//
// The shapes are wire-contract §2, extracted from awesome-node-auth@cc01e997
// (src/router/auth.router.ts:777-1071). The catalog, the mappers and the inline
// validations live in the root package for the same reason the rest of wire.go
// does: four adapters serve these routes and none of them may answer
// differently.
//
// Two properties of this group are load-bearing and easy to lose:
//
//   - /forgot-password answers 200 {"success":true} for an unknown address,
//     because leaking which addresses exist is the failure mode the route was
//     written to avoid (auth.router.ts:794-795).
//   - /change-email/request deliberately does the opposite: it answers 409 to an
//     authenticated caller naming an address in use (auth.router.ts:1005-1009).
//     The asymmetry is the reference's, and harmonising either side would change
//     behaviour a shipped client already relies on.
//
// None of these routes issues or clears a token, so bearer-vs-cookie delivery
// does not apply: the only bearer-mode difference is that the auth gate and the
// CSRF check treat a bearer caller as a non-cookie client.

// CodePasswordRequired is the one coded error in this group. Every other failure
// here is code-less in the reference, and a client is documented not to
// pattern-match on an absent code.
const CodePasswordRequired = "PASSWORD_REQUIRED"

// The §2 error catalog. Messages are the reference's own strings, down to the
// "UserStore does not implement …" wording it uses for an incapable store.
var (
	// HTTPErrResetTokenStoreMissing and the two below it are 500, not 501: the
	// reference reports a store that cannot perform the flow as an internal
	// error (auth.router.ts:805-808, 937-940, 1000-1003, 1042-1045). A client
	// that treats 501 as "feature absent" and 500 as "server broken" therefore
	// has to see 500 here, which is why these routes do not go through
	// HTTPErrorFor's ErrFeatureNotSupported → 501 mapping.
	HTTPErrResetTokenStoreMissing        = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement findByResetToken"}
	HTTPErrEmailVerificationStoreMissing = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement email verification"}
	HTTPErrChangeEmailStoreMissing       = HTTPError{Status: http.StatusInternalServerError, Message: "UserStore does not implement change-email"}

	HTTPErrInvalidResetToken       = HTTPError{Status: http.StatusBadRequest, Message: "Invalid reset token"}
	HTTPErrInvalidVerifyToken      = HTTPError{Status: http.StatusBadRequest, Message: "Invalid verification token"}
	HTTPErrInvalidEmailChangeToken = HTTPError{Status: http.StatusBadRequest, Message: "Invalid email-change token"}
	HTTPErrVerifyTokenRequired     = HTTPError{Status: http.StatusBadRequest, Message: "Token is required"}
	HTTPErrEmailAlreadyVerified    = HTTPError{Status: http.StatusBadRequest, Message: "Email is already verified"}

	// HTTPErrCurrentPasswordIncorrect is a 401 with no code, unlike the coded
	// INVALID_CREDENTIALS a failed login returns. Reproduced as-is even though it
	// is a known hazard: /change-password is absent from the Angular
	// interceptor's no-retry list, so a wrong current password costs a pointless
	// refresh-and-replay round trip (wire-contract §2, [MISMATCH]).
	HTTPErrCurrentPasswordIncorrect = HTTPError{Status: http.StatusUnauthorized, Message: "Current password is incorrect"}
	HTTPErrNewPasswordRequired      = HTTPError{Status: http.StatusBadRequest, Message: "New password is required"}

	// HTTPErrEmailInUse carries no code, so a client cannot branch on it — only
	// on the 409 status.
	HTTPErrEmailInUse = HTTPError{Status: http.StatusConflict, Message: "Email address is already in use"}

	HTTPErrPasswordRequired = HTTPError{
		Status:  http.StatusForbidden,
		Message: "You must set a password before you can change your email address.",
		Code:    CodePasswordRequired,
	}
)

// ForgotPasswordHTTPError maps a Service.ForgotPassword failure.
//
// Every failure is a bare 500: the reference has no error branch on this route
// at all, so a throwing store reaches handleError and becomes
// {"error":"Internal server error"} (auth.router.ts:796-798). ErrFeatureNotSupported
// is included on purpose — a store that cannot persist a reset token is a
// deployment fault, not a feature the caller can be told about, and answering
// 501 would tell an anonymous caller something the 200-always rule is there to
// hide.
func ForgotPasswordHTTPError(error) HTTPError { return HTTPErrInternal }

// ResetPasswordHTTPError maps a Service.ResetPassword failure.
func ResetPasswordHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrResetTokenStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidResetToken
	case errors.Is(err, ErrWeakPassword):
		// Port-only: the reference applies no password policy on this route.
		return HTTPErrWeakPassword
	default:
		return HTTPErrInternal
	}
}

// ChangePasswordHTTPError maps a Service.ChangePassword failure.
//
// ErrInvalidCredentials becomes 401 "Current password is incorrect" rather than
// the reference's 404 "User not found", because the service returns the same
// sentinel for both and the auth middleware resolved this user from the store
// moments earlier: a wrong password is the reachable case, a row that vanished
// in between is not.
func ChangePasswordHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrCurrentPasswordIncorrect
	case errors.Is(err, ErrWeakPassword):
		// Port-only: the reference applies no password policy on this route.
		return HTTPErrWeakPassword
	default:
		return HTTPErrInternal
	}
}

// SendVerificationEmailHTTPError maps a Service.SendVerificationEmailToken failure.
func SendVerificationEmailHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrEmailVerificationStoreMissing
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrUserNotFound
	default:
		return HTTPErrInternal
	}
}

// VerifyEmailHTTPError maps a Service.VerifyEmail failure.
func VerifyEmailHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrEmailVerificationStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidVerifyToken
	default:
		return HTTPErrInternal
	}
}

// ChangeEmailRequestHTTPError maps a Service.RequestEmailChange failure.
func ChangeEmailRequestHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrChangeEmailStoreMissing
	case errors.Is(err, ErrUserExists), errors.Is(err, ErrAlreadyExists):
		// Not the catalog's 409 USER_EXISTS: this route's 409 is code-less and
		// says "Email address is already in use".
		return HTTPErrEmailInUse
	case errors.Is(err, ErrInvalidCredentials):
		return HTTPErrUserNotFound
	default:
		return HTTPErrInternal
	}
}

// ChangeEmailConfirmHTTPError maps a Service.ConfirmEmailChange failure.
func ChangeEmailConfirmHTTPError(err error) HTTPError {
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		return HTTPErrChangeEmailStoreMissing
	case errors.Is(err, ErrInvalidToken):
		return HTTPErrInvalidEmailChangeToken
	default:
		return HTTPErrInternal
	}
}

// ChangePasswordInlineError reproduces the reference's inline validation on
// /change-password: an account with no stored password that submits neither
// field gets 400 "New password is required" (auth.router.ts:922-925). An account
// that does have a password never reaches it — a missing current password fails
// the comparison instead.
func ChangePasswordInlineError(user User, currentPassword, newPassword string) (HTTPError, bool) {
	if user.PasswordHash == "" && currentPassword == "" && newPassword == "" {
		return HTTPErrNewPasswordRequired, true
	}
	return HTTPError{}, false
}

// ChangeEmailInlineError reproduces the reference's PASSWORD_REQUIRED guard on
// /change-email/request: an account whose only credential is the address itself
// may not move that address (auth.router.ts:1015-1021).
//
// The reference runs this check after the 409 and 404 branches; here it runs
// before them, because the service persists the pending change in the same call
// that would report those two failures and there is no point at which the guard
// could still run without leaving a token behind. The status and code are
// therefore exact, and only the precedence between two simultaneous failures
// differs.
func ChangeEmailInlineError(user User) (HTTPError, bool) {
	if user.PasswordHash == "" {
		return HTTPErrPasswordRequired, true
	}
	return HTTPError{}, false
}

// VerifyEmailToken reads the token GET /verify-email carries. It is a query
// parameter, not a body field, and the route is the only GET in this group.
func VerifyEmailToken(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

// DecodeOptionalJSON decodes a JSON request body into dst, tolerating an absent
// or empty one, and writes the error envelope when the body is present but
// malformed.
//
// Every route in this group accepts an empty body: the reference runs
// express.json(), which leaves req.body as {} rather than failing, and the
// Flutter client posts /send-verification-email with no body at all. Rejecting a
// malformed body with 400 INVALID_BODY is the port's own convention, already
// applied by /register and /login.
func DecodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r == nil || r.Body == nil {
		return true
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		WriteHTTPError(w, HTTPErrInvalidBody)
		return false
	}
	return true
}

// ForgotPassword delegates to Service.ForgotPassword. The returned reset token
// is the credential the host application has to deliver: this port has no mail
// sender wired into Config, so no adapter route emails it and no adapter route
// puts it in a response body.
func (a *Auth) ForgotPassword(ctx context.Context, in ForgotPasswordInput) (string, error) {
	return a.service.ForgotPassword(ctx, in)
}

// ResetPassword delegates to Service.ResetPassword.
func (a *Auth) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	return a.service.ResetPassword(ctx, in)
}

// ChangePassword delegates to Service.ChangePassword.
func (a *Auth) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	return a.service.ChangePassword(ctx, in)
}

// SendVerificationEmailToken delegates to Service.SendVerificationEmailToken. An
// empty token with no error means the address is already verified.
func (a *Auth) SendVerificationEmailToken(ctx context.Context, in EmailVerificationInput) (string, error) {
	return a.service.SendVerificationEmailToken(ctx, in)
}

// VerifyEmail delegates to Service.VerifyEmail.
func (a *Auth) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	return a.service.VerifyEmail(ctx, in)
}

// RequestEmailChange delegates to Service.RequestEmailChange.
func (a *Auth) RequestEmailChange(ctx context.Context, in ChangeEmailRequestInput) (string, error) {
	return a.service.RequestEmailChange(ctx, in)
}

// ConfirmEmailChange delegates to Service.ConfirmEmailChange.
func (a *Auth) ConfirmEmailChange(ctx context.Context, in ConfirmEmailChangeInput) error {
	return a.service.ConfirmEmailChange(ctx, in)
}
