package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The two entry points of POST /login answer the same 2FA account differently
// when the step-up token cannot be minted, and both answers are deliberate:
//
//   - Service.Login is the compatibility wrapper. Its contract is the sentinel,
//     so it reports ErrTwoFactorRequired whenever a second factor is required —
//     the decision, not the token — and mints nothing.
//   - LoginWithChallenge exists to hand over the token. It surfaces the failure
//     rather than returning a challenge whose TempToken is empty, which a client
//     would take for a step-up credential and be refused with on every §3 route.
//
// A failing Config.BuildTokenClaims is the reachable way to break minting from
// outside the package: issueToken wraps a hook error as an ordinary error
// (token.go:66-71), which is neither of login's sentinels.

var errClaimsHookDown = errors.New("claims hook down")

// brokenClaimsService returns a service whose BuildTokenClaims hook fails only
// after breakHook is called.
//
// It cannot fail from the start: seeding an account goes through Register and
// enrolment reads its access token, and both mint through the same hook. Arming
// it afterwards is what puts the failure exactly where the test wants it — the
// challenge mint inside a login that has already verified the password.
func brokenClaimsService(t *testing.T) (svc *Service, breakHook func()) {
	t.Helper()
	broken := false
	cfg := testConfig("claimshookdown123456789012345678")
	cfg.BuildTokenClaims = func(_ context.Context, _ User) (map[string]any, error) {
		if broken {
			return nil, errClaimsHookDown
		}
		return nil, nil
	}
	svc, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("brokenClaimsService: %v", err)
	}
	return svc, func() { broken = true }
}

// enrolTOTPUser registers a user and completes TOTP enrolment, so login is gated
// on a factor the account really holds rather than on Config.Require2FA.
func enrolTOTPUser(t *testing.T, svc *Service, email string) User {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	user, _, err := svc.Register(ctx, RegisterInput{Email: email, Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	secret, err := svc.SetupTOTP(ctx, user.ID, user.TenantID)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, ok := generateTOTPCode(secret, now.Unix()/30)
	if !ok {
		t.Fatal("failed to generate totp code")
	}
	if err := svc.VerifyTOTPSetup(ctx, user.ID, user.TenantID, secret, code); err != nil {
		t.Fatalf("verify totp setup: %v", err)
	}
	return user
}

// The sentinel is the wrapper's whole contract, and it has to survive a
// deployment whose token minting is broken: a 2FA account is a 2FA account
// whether or not a challenge could be built for it. Reaching the sentinel
// through the built challenge would answer this login with the hook error, i.e.
// 500 where the caller has always had 403 2FA_REQUIRED.
func TestLogin_SentinelDoesNotDependOnMintingTheChallenge(t *testing.T) {
	svc, breakHook := brokenClaimsService(t)
	user := enrolTOTPUser(t, svc, "sentinel2fa@example.com")
	breakHook()

	_, tokens, err := svc.Login(context.Background(), LoginInput{
		Email: user.Email, Password: "password1", TenantID: user.TenantID,
	})
	if err != ErrTwoFactorRequired {
		t.Fatalf("Login = %v, want ErrTwoFactorRequired", err)
	}
	if errors.Is(err, errClaimsHookDown) {
		t.Fatal("Login surfaced the claims hook failure instead of the sentinel")
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Fatal("a challenged login must issue no session")
	}
	// The other half of the compatibility claim: what a direct caller's
	// WriteServiceError puts on the wire.
	if got := HTTPErrorFor(err); got != HTTPErrTwoFactorRequired {
		t.Fatalf("HTTPErrorFor = %+v, want %+v", got, HTTPErrTwoFactorRequired)
	}
}

// LoginWithChallenge has no sentinel to fall back on and must not invent a
// challenge it could not mint.
func TestLoginWithChallenge_MintFailureIsReported(t *testing.T) {
	svc, breakHook := brokenClaimsService(t)
	user := enrolTOTPUser(t, svc, "mintfail@example.com")
	breakHook()

	result, err := svc.LoginWithChallenge(context.Background(), LoginInput{
		Email: user.Email, Password: "password1", TenantID: user.TenantID,
	})
	if !errors.Is(err, errClaimsHookDown) {
		t.Fatalf("LoginWithChallenge = %v, want the claims hook failure", err)
	}
	if errors.Is(err, ErrTwoFactorRequired) {
		t.Fatal("the sentinel would spell 403 2FA_REQUIRED, telling a client to step up with a token it was never given")
	}
	if result.Challenge != nil {
		t.Fatalf("a challenge was returned anyway: tempToken = %q", result.Challenge.TempToken)
	}
	if got := HTTPErrorFor(err); got != HTTPErrInternal {
		t.Fatalf("HTTPErrorFor = %+v, want %+v", got, HTTPErrInternal)
	}
}

// The control: with no second factor in play the same broken hook fails the
// session mint, which is what it did before this PR and still does. Nothing
// about the challenge branch may leak into this path — in particular the
// sentinel, which would turn a broken deployment into a 403 demanding a factor
// nobody has.
func TestLogin_NoSecondFactorKeepsTheClaimsHookFailure(t *testing.T) {
	svc, breakHook := brokenClaimsService(t)
	ctx := context.Background()
	if _, _, err := svc.Register(ctx, RegisterInput{Email: "no2fa@example.com", Password: "password1", TenantID: "t1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	breakHook()

	in := LoginInput{Email: "no2fa@example.com", Password: "password1", TenantID: "t1"}
	_, tokens, err := svc.Login(ctx, in)
	if !errors.Is(err, errClaimsHookDown) {
		t.Fatalf("Login = %v, want the claims hook failure", err)
	}
	if errors.Is(err, ErrTwoFactorRequired) {
		t.Fatal("a login with no second factor must never report ErrTwoFactorRequired")
	}
	if tokens.AccessToken != "" || tokens.RefreshToken != "" {
		t.Fatal("no session may be issued when the tokens could not be built")
	}
	if got := HTTPErrorFor(err); got != HTTPErrInternal {
		t.Fatalf("HTTPErrorFor = %+v, want %+v", got, HTTPErrInternal)
	}
	// LoginWithChallenge agrees on this path, so the two entry points differ only
	// on the branch that mints a challenge.
	result, err := svc.LoginWithChallenge(ctx, in)
	if !errors.Is(err, errClaimsHookDown) {
		t.Fatalf("LoginWithChallenge = %v, want the claims hook failure", err)
	}
	if result.Challenge != nil {
		t.Fatal("a login with no second factor must not produce a challenge")
	}
}
