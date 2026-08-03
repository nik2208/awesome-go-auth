package gin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

// The passwordless entry points and the TOTP second factor: wire-contract §3.
// The branching, the literals and the sentinel mappings live in the root
// package, so these closures are the Gin plumbing and nothing else.
//
// SendMagicLink and SendSMSCode return the credential they minted to their
// caller and there is no mail or SMS transport in this package to hand it to,
// so the handlers drop it. A deployment delivers it by calling the service
// directly; putting it in the response body would turn a second factor into no
// factor at all.

func (ad *Adapter) magicLinkSend(c *gin.Context) {
	var req struct {
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	email, tenantID := req.Email, req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		// The address comes from the step-up token; an email in the body is
		// ignored, so a caller holding a tempToken cannot redirect the link.
		user, err := ad.auth.FindUser(c.Request.Context(), subject.UserID, "", subject.TenantID)
		if err != nil {
			auth.WriteHTTPError(c.Writer, auth.HTTPErrUserNotFound)
			return
		}
		email, tenantID = user.Email, user.TenantID
	} else if strings.TrimSpace(email) == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrEmailRequired)
		return
	}
	if _, err := ad.auth.SendMagicLink(c.Request.Context(), auth.MagicLinkSendInput{Email: email, TenantID: tenantID}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) magicLinkVerify(c *gin.Context) {
	var req struct {
		Token     string `json:"token"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	var subject auth.TempTokenSubject
	stepUp := auth.TwoFactorMode(req.Mode)
	if stepUp {
		resolved, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		subject = resolved
	}
	user, tokens, err := ad.auth.VerifyMagicLink(c.Request.Context(), auth.MagicLinkVerifyInput{Token: req.Token})
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.MagicLinkVerifyHTTPError(err))
		return
	}
	if stepUp && user.ID != subject.UserID {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrTokenMismatch)
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) smsSend(c *gin.Context) {
	var req struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	switch {
	case auth.TwoFactorMode(req.Mode):
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	case strings.TrimSpace(req.Email) != "":
		// An unknown address answers 200; an unknown userId 404s below. Only the
		// address is treated as enumerable, which is the reference's asymmetry.
		user, err := ad.auth.FindUser(c.Request.Context(), "", req.Email, tenantID)
		if err != nil {
			auth.WriteSuccess(c.Writer, http.StatusOK, nil)
			return
		}
		userID = user.ID
	case userID == "":
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserIDOrEmailRequired)
		return
	}

	user, err := ad.auth.FindUser(c.Request.Context(), userID, "", tenantID)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserNotFound)
		return
	}
	if strings.TrimSpace(user.PhoneNumber) == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrPhoneNotSet)
		return
	}
	if _, err := ad.auth.SendSMSCode(c.Request.Context(), auth.SMSCodeSendInput{UserID: user.ID, TenantID: user.TenantID}); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) smsVerify(c *gin.Context) {
	var req struct {
		UserID    string `json:"userId"`
		Code      string `json:"code"`
		Mode      string `json:"mode"`
		TempToken string `json:"tempToken"`
		TenantID  string `json:"tenantId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	userID, tenantID := strings.TrimSpace(req.UserID), req.TenantID
	if auth.TwoFactorMode(req.Mode) {
		subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrTempTokenRequired, auth.HTTPErrInvalidTempToken)
		if !ok {
			auth.WriteHTTPError(c.Writer, herr)
			return
		}
		userID, tenantID = subject.UserID, subject.TenantID
	} else if userID == "" {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserIDRequired)
		return
	}
	_, tokens, err := ad.auth.VerifySMSCode(c.Request.Context(), auth.SMSCodeVerifyInput{UserID: userID, TenantID: tenantID, Code: req.Code})
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.SMSVerifyHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) twoFactorSetup(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	setup, err := ad.auth.StartTOTPEnrolment(c.Request.Context(), user.ID, user.TenantID)
	if err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	// The enrolment material is the whole body: no success envelope.
	auth.WriteJSON(c.Writer, http.StatusOK, setup)
}

func (ad *Adapter) twoFactorVerifySetup(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	// The code field is "token" on this route and "totpCode" on /2fa/verify.
	var req struct {
		Token  string `json:"token"`
		Secret string `json:"secret"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	if err := ad.auth.VerifyTOTPSetup(c.Request.Context(), user.ID, user.TenantID, req.Secret, req.Token); err != nil {
		auth.WriteHTTPError(c.Writer, auth.TOTPSetupHTTPError(err))
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}

func (ad *Adapter) twoFactorVerify(c *gin.Context) {
	var req struct {
		TempToken string `json:"tempToken"`
		TOTPCode  string `json:"totpCode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrInvalidBody)
		return
	}
	// Both arguments are the same envelope: this route has no missing-tempToken
	// branch, and it answers INVALID_ACCESS_TOKEN where its siblings answer
	// INVALID_TEMP_TOKEN.
	subject, herr, ok := ad.auth.StepUpSubject(req.TempToken, auth.HTTPErrInvalidStepUpToken, auth.HTTPErrInvalidStepUpToken)
	if !ok {
		auth.WriteHTTPError(c.Writer, herr)
		return
	}
	_, tokens, err := ad.auth.VerifyTOTP(c.Request.Context(), subject.UserID, subject.TenantID, req.TOTPCode)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.TOTPVerifyHTTPError(err))
		return
	}
	ad.cfg.WriteTokens(c.Writer, c.Request, http.StatusOK, tokens, nil)
}

func (ad *Adapter) twoFactorDisable(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrNoAccessToken)
		return
	}
	// Re-read the user rather than trust the access token: a require2FA flag set
	// after the token was issued still has to be honoured.
	fresh, err := ad.auth.FindUser(c.Request.Context(), user.ID, "", user.TenantID)
	if err != nil {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrUserNotFound)
		return
	}
	if fresh.Require2FA {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrTwoFactorRequiredForUser)
		return
	}
	if ad.auth.TwoFactorPolicy() {
		auth.WriteHTTPError(c.Writer, auth.HTTPErrTwoFactorRequiredByPolicy)
		return
	}
	if err := ad.auth.DisableTOTP(c.Request.Context(), user.ID, user.TenantID); err != nil {
		auth.WriteServiceError(c.Writer, err)
		return
	}
	auth.WriteSuccess(c.Writer, http.StatusOK, nil)
}
