package auth

import (
	"context"
	"testing"
	"time"
)

func TestPasswordResetFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "reset@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	resetToken, err := svc.ForgotPassword(ctx, ForgotPasswordInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil || resetToken == "" {
		t.Fatalf("forgot password: %v", err)
	}
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetToken, NewPassword: "password2"}); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err == nil {
		t.Fatal("old password should no longer work")
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password2", TenantID: user.TenantID}); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}

func TestMagicLinkFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "magic@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	token, err := svc.SendMagicLink(ctx, MagicLinkSendInput{Email: user.Email, TenantID: user.TenantID})
	if err != nil || token == "" {
		t.Fatalf("send magic link: %v", err)
	}
	_, tokens, err := svc.VerifyMagicLink(ctx, MagicLinkVerifyInput{Token: token})
	if err != nil {
		t.Fatalf("verify magic link: %v", err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("tokens should be issued after magic link verification")
	}
}

func TestSMSLoginFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()

	user, _, err := svc.Register(ctx, RegisterInput{Email: "sms@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	mu := svc.users.(*MemoryUserStore)
	mu.mu.Lock()
	u := mu.byID[user.ID]
	u.PhoneNumber = "+390000000000"
	mu.byID[user.ID] = u
	mu.mu.Unlock()

	code, err := svc.SendSMSCode(ctx, SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || code == "" {
		t.Fatalf("send sms code: %v", err)
	}
	_, tokens, err := svc.VerifySMSCode(ctx, SMSCodeVerifyInput{UserID: user.ID, TenantID: user.TenantID, Code: code})
	if err != nil {
		t.Fatalf("verify sms code: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("access token expected")
	}
}

func TestEmailVerificationAndEmailChangeFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	pw, _ := hashPassword("password1")
	user, err := svc.users.CreateUser(ctx, User{
		ID:              "usr_manual",
		Email:           "verify@example.com",
		PasswordHash:    pw,
		TenantID:        "t1",
		IsEmailVerified: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	verifyToken, err := svc.SendVerificationEmailToken(ctx, EmailVerificationInput{UserID: user.ID, TenantID: user.TenantID})
	if err != nil || verifyToken == "" {
		t.Fatalf("send verification token: %v", err)
	}
	if err := svc.VerifyEmail(ctx, VerifyEmailInput{Token: verifyToken}); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login should work after email verification: %v", err)
	}

	changeToken, err := svc.RequestEmailChange(ctx, ChangeEmailRequestInput{UserID: user.ID, TenantID: user.TenantID, NewEmail: "verify2@example.com"})
	if err != nil {
		t.Fatalf("request email change: %v", err)
	}
	if err := svc.ConfirmEmailChange(ctx, ConfirmEmailChangeInput{Token: changeToken}); err != nil {
		t.Fatalf("confirm email change: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: "verify2@example.com", Password: "password1", TenantID: user.TenantID}); err != nil {
		t.Fatalf("login with new email should work: %v", err)
	}
}

func TestTOTPFlow(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	now := time.Now()
	svc.now = func() time.Time { return now }

	user, _, err := svc.Register(ctx, RegisterInput{Email: "totp@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
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
		t.Fatalf("verify setup: %v", err)
	}
	if _, _, err := svc.Login(ctx, LoginInput{Email: user.Email, Password: "password1", TenantID: user.TenantID}); err != ErrTwoFactorRequired {
		t.Fatalf("expected 2FA required after setup, got %v", err)
	}
	_, tokens, err := svc.VerifyTOTP(ctx, user.ID, user.TenantID, code)
	if err != nil {
		t.Fatalf("verify totp: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("access token expected")
	}
}

func TestResolveUserHelper(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, _, err := svc.Register(ctx, RegisterInput{Email: "resolve@example.com", Password: "password1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	byID, err := svc.resolveUser(ctx, user.ID, "", user.TenantID)
	if err != nil || byID.ID != user.ID {
		t.Fatalf("resolve by id failed: %v", err)
	}

	byEmail, err := svc.resolveUser(ctx, "", user.Email, user.TenantID)
	if err != nil || byEmail.ID != user.ID {
		t.Fatalf("resolve by email failed: %v", err)
	}

	if _, err := svc.resolveUser(ctx, "", "", user.TenantID); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
