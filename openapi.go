package auth

import (
	"net/http"
	"strconv"
)

// The generated OpenAPI description of the mounted routes.
//
// It describes the contract the adapters actually serve — the same shapes
// wire.go, passwordless.go, wire_password_email.go, account.go and oauth_wire.go
// implement — rather than the pre-0.2.0 spec this file used to carry, which
// documented four routes nobody mounted and none of the ones added since.
//
// Two things keep it from drifting again: every path here is registered by
// Adapter.Mount, and the wiretest suite replays each documented operation
// against every adapter to prove it is not a 404. A spec that advertises an
// endpoint nobody serves is worse than a short one, and this one is now checked
// in both directions — see documentedRoutes in the suite.
//
// Routes the reference has and this port does not (the admin router) are absent.

// OpenAPIInfo holds metadata for the generated OpenAPI spec.
type OpenAPIInfo struct {
	Title       string
	Description string
	Version     string
	ServerURL   string
	// APIPrefix is where the routes are mounted. Empty means DefaultAPIPrefix,
	// and it must match the HTTPConfig the adapter was mounted with, otherwise
	// the spec documents paths the server does not serve.
	APIPrefix string
}

// GenerateOpenAPISpec returns an OpenAPI 3.0 spec for the mounted auth endpoints.
func GenerateOpenAPISpec(info OpenAPIInfo) map[string]any {
	if info.Title == "" {
		info.Title = "awesome-go-auth"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}
	if info.Description == "" {
		info.Description = "Authentication & Authorization API"
	}

	servers := []map[string]any{}
	if info.ServerURL != "" {
		servers = append(servers, map[string]any{"url": info.ServerURL})
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"servers": servers,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				// Two ways to present the same access token, and the reason both
				// are listed: a bearer client sends the Authorization header, a
				// browser client sends the cookie the server set. The cookie name
				// shown is the default; it resolves to __Secure- or the bare name
				// under other cookie configurations (see CookieOptions.CookieName).
				"BearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
				"CookieAuth": map[string]any{
					"type": "apiKey",
					"in":   "cookie",
					"name": hostCookiePrefix + AccessTokenCookieName,
				},
				"ApiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-Api-Key",
				},
			},
			"parameters": openAPIParameters(),
			"schemas":    openAPISchemas(),
		},
		"paths": openAPIPaths(openAPIPrefix(info.APIPrefix)),
	}
}

// openAPIPrefix normalises the mount prefix the same way HTTPConfig.Prefix does,
// so a spec and a mount built from the same string agree.
func openAPIPrefix(prefix string) string {
	return HTTPConfig{APIPrefix: prefix}.Prefix()
}

func openAPIParameters() map[string]any {
	return map[string]any{
		"AuthStrategy": map[string]any{
			"name": AuthStrategyHeader,
			"in":   "header",
			"description": "Send `" + AuthStrategyBearer + "` (exact, case-sensitive) to receive the token pair " +
				"in the response body and no cookies. Any other value, or the header's absence, selects cookie delivery.",
			"required": false,
			"schema":   map[string]any{"type": "string", "enum": []string{AuthStrategyBearer}},
		},
		"CSRFToken": map[string]any{
			"name": CSRFHeaderName,
			"in":   "header",
			"description": "Double-submit token. Required only for a cookie-authenticated request to a route behind " +
				"the access-token middleware; mirror the `" + CSRFTokenCookieName + "` cookie value here.",
			"required": false,
			"schema":   map[string]any{"type": "string"},
		},
	}
}

func openAPISchemas() map[string]any {
	str := map[string]any{"type": "string"}
	return map[string]any{
		"RegisterInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":    map[string]any{"type": "string", "format": "email"},
				"password": map[string]any{"type": "string", "minLength": 8},
				"tenantId": str,
			},
		},
		"LoginInput": map[string]any{
			"type":     "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":    map[string]any{"type": "string", "format": "email"},
				"password": str,
				"tenantId": str,
			},
		},
		// Success is what a route answers when it has nothing to hand back. Every
		// non-token route below returns exactly this object and no more.
		"Success": map[string]any{
			"type":       "object",
			"required":   []string{"success"},
			"properties": map[string]any{"success": map[string]any{"type": "boolean", "enum": []bool{true}}},
		},
		// AuthResult is the token-issuing answer. accessToken and refreshToken are
		// present only for a bearer caller; a cookie caller gets Set-Cookie
		// headers and a body with nothing but success.
		"AuthResult": map[string]any{
			"type":     "object",
			"required": []string{"success"},
			"properties": map[string]any{
				"success":      map[string]any{"type": "boolean", "enum": []bool{true}},
				"accessToken":  map[string]any{"type": "string", "description": "Bearer callers only."},
				"refreshToken": map[string]any{"type": "string", "description": "Bearer callers only."},
			},
		},
		// The two second-factor answers POST /login can give instead of a session.
		// Neither is the Error envelope: the first is a 200 with no error member at
		// all, the second a 403 with a code and no message. See login_2fa.go.
		"TwoFactorChallenge": map[string]any{
			"type":     "object",
			"required": []string{"requiresTwoFactor", "tempToken", "available2faMethods"},
			"properties": map[string]any{
				"requiresTwoFactor": map[string]any{"type": "boolean", "enum": []bool{true}},
				"tempToken":         map[string]any{"type": "string", "description": "Step-up token; present it to the route for the method the client picks."},
				"available2faMethods": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string", "enum": []string{TwoFactorMethodTOTP, TwoFactorMethodSMS, TwoFactorMethodMagicLink}},
					"description": "The factors this account can present. Never empty; an account with none gets TwoFactorSetupRequired instead.",
				},
			},
		},
		"TwoFactorSetupRequired": map[string]any{
			"type":     "object",
			"required": []string{"requires2FASetup", "tempToken", "code"},
			"properties": map[string]any{
				"requires2FASetup": map[string]any{"type": "boolean", "enum": []bool{true}},
				"tempToken":        str,
				"code":             map[string]any{"type": "string", "enum": []string{CodeTwoFactorSetupRequired}},
			},
		},
		"RegisterResult": map[string]any{
			"type":     "object",
			"required": []string{"success", "userId"},
			"properties": map[string]any{
				"success":      map[string]any{"type": "boolean", "enum": []bool{true}},
				"userId":       str,
				"accessToken":  map[string]any{"type": "string", "description": "Bearer callers only."},
				"refreshToken": map[string]any{"type": "string", "description": "Bearer callers only."},
			},
		},
		// Session is one entry of GET /sessions. It is the response-safe
		// projection: the refresh-token hash that identifies the row server-side
		// is never serialised, which is why revocation takes an opaque handle.
		"Session": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"handle":     str,
				"userAgent":  str,
				"ip":         str,
				"createdAt":  map[string]any{"type": "string", "format": "date-time"},
				"expiresAt":  map[string]any{"type": "string", "format": "date-time"},
				"revokedAt":  map[string]any{"type": "string", "format": "date-time"},
				"lastUsedAt": map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"SessionList": map[string]any{
			"type":       "object",
			"required":   []string{"sessions"},
			"properties": map[string]any{"sessions": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Session"}}},
		},
		"CleanupResult": map[string]any{
			"type":     "object",
			"required": []string{"success", "deleted"},
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean", "enum": []bool{true}},
				"deleted": map[string]any{"type": "integer"},
			},
		},
		"LinkedAccount": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider":          str,
				"providerAccountId": str,
				"email":             str,
				"createdAt":         map[string]any{"type": "string", "format": "date-time"},
			},
		},
		// TOTPSetup is the one route with no success envelope: the enrolment
		// material is the whole body.
		"TOTPSetup": map[string]any{
			"type":     "object",
			"required": []string{"secret", "otpauthUrl"},
			"properties": map[string]any{
				"secret":     str,
				"otpauthUrl": map[string]any{"type": "string", "description": "Provisioning URI; render it as a QR code client-side."},
			},
		},
		"User": map[string]any{
			"type":     "object",
			"required": []string{"id", "email", "isEmailVerified", "isTotpEnabled", "createdAt"},
			"properties": map[string]any{
				"id":              str,
				"email":           map[string]any{"type": "string", "format": "email"},
				"tenantId":        str,
				"firstName":       str,
				"lastName":        str,
				"phoneNumber":     str,
				"isEmailVerified": map[string]any{"type": "boolean"},
				"isTotpEnabled":   map[string]any{"type": "boolean"},
				"roles":           map[string]any{"type": "array", "items": str},
				"permissions":     map[string]any{"type": "array", "items": str},
				"metadata":        map[string]any{"type": "object"},
				"customClaims":    map[string]any{"type": "object"},
				"createdAt":       map[string]any{"type": "string", "format": "date-time"},
			},
		},
		// Error carries the reference's message, and its code where the reference
		// emits one — several failures are deliberately code-less, so clients are
		// documented not to pattern-match on an absent code.
		"Error": map[string]any{
			"type":     "object",
			"required": []string{"error"},
			"properties": map[string]any{
				"error": str,
				"code":  map[string]any{"type": "string", "description": "Absent where the reference emits no code."},
			},
		},
	}
}

func openAPIPaths(prefix string) map[string]any {
	schema := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	param := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/parameters/" + name}
	}
	jsonContent := func(s map[string]any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": s}}
	}
	body := func(s map[string]any) map[string]any {
		return map[string]any{"required": true, "content": jsonContent(s)}
	}
	inline := func(required []string, props map[string]any) map[string]any {
		out := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			out["required"] = required
		}
		return out
	}
	// fail renders one error response from the catalog entry the route actually
	// writes, so the documented status and code cannot disagree with wire.go.
	fail := func(entries ...HTTPError) map[string]any {
		out := map[string]any{}
		for _, e := range entries {
			description := e.Message
			if e.Code != "" {
				description += " (`" + e.Code + "`)"
			}
			key := strconv.Itoa(e.Status)
			if existing, ok := out[key].(map[string]any); ok {
				out[key] = map[string]any{
					"description": existing["description"].(string) + "; " + description,
					"content":     jsonContent(schema("Error")),
				}
				continue
			}
			out[key] = map[string]any{"description": description, "content": jsonContent(schema("Error"))}
		}
		return out
	}
	respond := func(status int, description string, s map[string]any, errs ...HTTPError) map[string]any {
		out := fail(errs...)
		out[strconv.Itoa(status)] = map[string]any{"description": description, "content": jsonContent(s)}
		return out
	}

	str := map[string]any{"type": "string"}
	mode := map[string]any{
		"type":        "string",
		"enum":        []string{"login", StepUpMode},
		"description": "Only the literal `" + StepUpMode + "` selects the step-up branch; absent, empty and anything else mean login.",
	}
	// POST /login is the one route with two answers per status, which the catalog
	// cannot express: a 200 is either a session or a second-factor challenge, and a
	// 403 is either EMAIL_NOT_VERIFIED or the 2FA_SETUP_REQUIRED envelope. Neither
	// challenge body is the error envelope — see login_2fa.go — so both statuses are
	// written out here rather than through fail().
	loginResponses := respond(http.StatusOK, "Session issued, or a second-factor challenge (`requiresTwoFactor`)",
		map[string]any{"oneOf": []any{schema("AuthResult"), schema("TwoFactorChallenge")}},
		HTTPErrInvalidBody, HTTPErrInvalidCredentials)
	loginResponses[strconv.Itoa(http.StatusForbidden)] = map[string]any{
		"description": HTTPErrEmailNotVerified.Message + " (`" + CodeEmailNotVerified + "`); or a second factor is required and this account has none enrolled (`" + CodeTwoFactorSetupRequired + "`)",
		"content":     jsonContent(map[string]any{"oneOf": []any{schema("Error"), schema("TwoFactorSetupRequired")}}),
	}

	tokenDelivery := []map[string]any{param("AuthStrategy")}
	protected := []map[string]any{param("AuthStrategy"), param("CSRFToken")}
	anyCredential := []map[string]any{{"BearerAuth": []string{}}, {"CookieAuth": []string{}}}

	return map[string]any{
		prefix + "/register": map[string]any{
			"post": map[string]any{
				"summary":     "Register a new user and open a session",
				"operationId": "register",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": body(schema("RegisterInput")),
				"responses": respond(http.StatusCreated, "Registered", schema("RegisterResult"),
					HTTPErrInvalidBody, HTTPErrWeakPassword, HTTPErrUserExists),
			},
		},
		prefix + "/login": map[string]any{
			"post": map[string]any{
				"summary":     "Log in with email and password",
				"operationId": "login",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": body(schema("LoginInput")),
				"responses":   loginResponses,
			},
		},

		prefix + "/sessions": map[string]any{
			"get": map[string]any{
				"summary":     "List the caller's sessions",
				"operationId": "listSessions",
				"tags":        []string{"Sessions"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "The caller's sessions", schema("SessionList"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken),
			},
		},
		prefix + "/sessions/{handle}": map[string]any{
			"delete": map[string]any{
				"summary":     "Revoke one of the caller's sessions",
				"description": "The handle is opaque; a session that does not exist and one that belongs to somebody else are deliberately indistinguishable.",
				"operationId": "revokeSession",
				"tags":        []string{"Sessions"},
				"security":    anyCredential,
				"parameters": append([]map[string]any{{
					"name": "handle", "in": "path", "required": true, "schema": str,
				}}, protected...),
				"responses": respond(http.StatusOK, "Session revoked", schema("Success"),
					HTTPErrSessionNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/sessions/cleanup": map[string]any{
			"post": map[string]any{
				"summary": "Delete expired sessions",
				"description": "Unauthenticated, as in the reference: anyone who can reach the router can trigger a cleanup. " +
					"Reproduced deliberately so an existing cron job keeps working.",
				"operationId": "cleanupSessions",
				"tags":        []string{"Sessions"},
				"responses":   respond(http.StatusOK, "Expired sessions deleted", schema("CleanupResult")),
			},
		},
		prefix + "/profile": map[string]any{
			"patch": map[string]any{
				"summary":     "Update the caller's profile",
				"description": "A partial update: an absent field is left alone, so it is not the same as sending it empty. The updated user is not echoed back — re-read /me.",
				"operationId": "updateProfile",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline(nil, map[string]any{"firstName": str, "lastName": str})),
				"responses": respond(http.StatusOK, "Profile updated", schema("Success"),
					HTTPErrInvalidBody, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/add-phone": map[string]any{
			"post": map[string]any{
				"summary":     "Set or clear the caller's phone number",
				"description": "An empty phoneNumber clears it. The number is what /sms/send texts.",
				"operationId": "addPhone",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"phoneNumber"}, map[string]any{"phoneNumber": str})),
				"responses": respond(http.StatusOK, "Phone number updated", schema("Success"),
					HTTPErrInvalidBody, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/account": map[string]any{
			"delete": map[string]any{
				"summary":     "Delete the caller's account",
				"description": "The auth cookies are cleared on the way out even for a bearer caller, so nobody is left holding live cookies for a deleted account.",
				"operationId": "deleteAccount",
				"tags":        []string{"Account"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Account deleted", schema("Success"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},

		prefix + "/oauth/{provider}": map[string]any{
			"get": map[string]any{
				"summary":     "Begin an OAuth login",
				"description": "Redirects to the provider. The `state` parameter is minted here and verified on the callback.",
				"operationId": "oauthAuthorize",
				"tags":        []string{"OAuth"},
				"parameters": []map[string]any{{
					"name": "provider", "in": "path", "required": true, "schema": str,
				}},
				"responses": map[string]any{
					"302": map[string]any{"description": "Redirect to the provider"},
					"400": map[string]any{"description": "Unknown or unconfigured provider", "content": jsonContent(schema("Error"))},
				},
			},
		},
		prefix + "/oauth/{provider}/callback": map[string]any{
			"get": map[string]any{
				"summary":     "Complete an OAuth login",
				"description": "Verifies the state, issues a session and redirects back to the origin the state names.",
				"operationId": "oauthCallback",
				"tags":        []string{"OAuth"},
				"parameters": []map[string]any{
					{"name": "provider", "in": "path", "required": true, "schema": str},
					{"name": "code", "in": "query", "required": false, "schema": str},
					{"name": "state", "in": "query", "required": false, "schema": str},
				},
				"responses": respond(http.StatusFound, "Redirect back to the application", schema("Success"),
					HTTPErrOAuthState),
			},
		},
		prefix + "/linked-accounts": map[string]any{
			"get": map[string]any{
				"summary":     "List the caller's linked OAuth accounts",
				"operationId": "listLinkedAccounts",
				"tags":        []string{"OAuth"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Linked accounts",
					inline(nil, map[string]any{"linkedAccounts": map[string]any{"type": "array", "items": schema("LinkedAccount")}}),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken),
			},
		},
		prefix + "/linked-accounts/{provider}/{providerAccountId}": map[string]any{
			"delete": map[string]any{
				"summary":     "Unlink an OAuth account",
				"operationId": "unlinkAccount",
				"tags":        []string{"OAuth"},
				"security":    anyCredential,
				"parameters": append([]map[string]any{
					{"name": "provider", "in": "path", "required": true, "schema": str},
					{"name": "providerAccountId", "in": "path", "required": true, "schema": str},
				}, protected...),
				"responses": respond(http.StatusOK, "Account unlinked", schema("Success"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/link-request": map[string]any{
			"post": map[string]any{
				"summary": "Request a link between two accounts",
				"description": "The one unauthenticated route that is still CSRF-checked, via a double-submit inside the handler: " +
					"without it a cross-site form post could overwrite an in-flight link token.",
				"operationId": "linkRequest",
				"tags":        []string{"OAuth"},
				"parameters":  []map[string]any{param("CSRFToken")},
				"requestBody": body(inline([]string{"email"}, map[string]any{"email": map[string]any{"type": "string", "format": "email"}})),
				"responses": respond(http.StatusOK, "Link email sent", schema("Success"),
					HTTPErrInvalidBody, HTTPErrLinkEmailRequired, HTTPErrTargetUserNotFound, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/link-verify": map[string]any{
			"post": map[string]any{
				"summary":     "Complete an account link",
				"operationId": "linkVerify",
				"tags":        []string{"OAuth"},
				"requestBody": body(inline([]string{"token"}, map[string]any{"token": str})),
				"responses": respond(http.StatusOK, "Accounts linked", schema("Success"),
					HTTPErrInvalidBody, HTTPErrTokenRequired, HTTPErrInvalidLinkToken,
					HTTPErrLinkTokenExpired, HTTPErrLinkUnauthorized),
			},
		},

		prefix + "/forgot-password": map[string]any{
			"post": map[string]any{
				"summary":     "Request a password-reset email",
				"description": "Answers 200 for an address the store does not have, so the route cannot be used to discover who is registered.",
				"operationId": "forgotPassword",
				"tags":        []string{"Password"},
				"requestBody": body(inline([]string{"email"}, map[string]any{
					"email":     map[string]any{"type": "string", "format": "email"},
					"tenantId":  str,
					"emailLang": map[string]any{"type": "string", "description": "Accepted for wire compatibility."},
				})),
				"responses": respond(http.StatusOK, "Reset email sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrResetTokenStoreMissing),
			},
		},
		prefix + "/reset-password": map[string]any{
			"post": map[string]any{
				"summary":     "Reset a password with a token",
				"description": "The new password field is named `password`, not `newPassword`: that is what the served auth.js and the Flutter client send.",
				"operationId": "resetPassword",
				"tags":        []string{"Password"},
				"requestBody": body(inline([]string{"token", "password"}, map[string]any{"token": str, "password": str})),
				"responses": respond(http.StatusOK, "Password reset", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidResetToken, HTTPErrWeakPassword, HTTPErrResetTokenStoreMissing),
			},
		},
		prefix + "/change-password": map[string]any{
			"post": map[string]any{
				"summary":     "Change the caller's password",
				"operationId": "changePassword",
				"tags":        []string{"Password"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"currentPassword", "newPassword"}, map[string]any{
					"currentPassword": str,
					"newPassword":     str,
				})),
				"responses": respond(http.StatusOK, "Password changed", schema("Success"),
					HTTPErrInvalidBody, HTTPErrCurrentPasswordIncorrect, HTTPErrNewPasswordRequired,
					HTTPErrWeakPassword, HTTPErrUserNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/send-verification-email": map[string]any{
			"post": map[string]any{
				"summary":     "Send the caller a verification email",
				"operationId": "sendVerificationEmail",
				"tags":        []string{"Email"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": map[string]any{
					"required": false,
					"content":  jsonContent(inline(nil, map[string]any{"emailLang": str})),
				},
				"responses": respond(http.StatusOK, "Verification email sent", schema("Success"),
					HTTPErrEmailAlreadyVerified, HTTPErrEmailVerificationStoreMissing,
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/verify-email": map[string]any{
			"get": map[string]any{
				"summary":     "Confirm an email address",
				"description": "A GET because the link is opened from a mailbox.",
				"operationId": "verifyEmail",
				"tags":        []string{"Email"},
				"parameters": []map[string]any{{
					"name": "token", "in": "query", "required": true, "schema": str,
				}},
				"responses": respond(http.StatusOK, "Email verified", schema("Success"),
					HTTPErrVerifyTokenRequired, HTTPErrInvalidVerifyToken, HTTPErrEmailVerificationStoreMissing),
			},
		},
		prefix + "/change-email/request": map[string]any{
			"post": map[string]any{
				"summary":     "Request an email-address change",
				"operationId": "changeEmailRequest",
				"tags":        []string{"Email"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"newEmail"}, map[string]any{
					"newEmail":  map[string]any{"type": "string", "format": "email"},
					"emailLang": str,
				})),
				"responses": respond(http.StatusOK, "Confirmation email sent", schema("Success"),
					HTTPErrInvalidBody, HTTPErrEmailInUse, HTTPErrPasswordRequired,
					HTTPErrChangeEmailStoreMissing, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/change-email/confirm": map[string]any{
			"post": map[string]any{
				"summary":     "Confirm an email-address change",
				"description": "No auth gate, and therefore no CSRF check: the confirmation token is the credential.",
				"operationId": "changeEmailConfirm",
				"tags":        []string{"Email"},
				"requestBody": body(inline([]string{"token"}, map[string]any{"token": str})),
				"responses": respond(http.StatusOK, "Email address changed", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidEmailChangeToken, HTTPErrChangeEmailStoreMissing),
			},
		},
		prefix + "/refresh": map[string]any{
			"post": map[string]any{
				"summary":     "Exchange a refresh token for a new session",
				"operationId": "refresh",
				"tags":        []string{"Auth"},
				"parameters":  tokenDelivery,
				"requestBody": map[string]any{
					"required":    false,
					"description": "Optional. A cookie caller sends no body; a bearer caller sends the token here.",
					"content":     jsonContent(inline(nil, map[string]any{"refreshToken": str})),
				},
				"responses": respond(http.StatusOK, "Session refreshed", schema("AuthResult"),
					HTTPErrNoRefreshToken, HTTPErrExpiredRefreshToken, HTTPErrInvalidRefreshToken, HTTPErrSessionRevoked),
			},
		},
		prefix + "/logout": map[string]any{
			"post": map[string]any{
				"summary":     "Revoke the caller's session and clear the auth cookies",
				"description": "Best effort: it answers 200 and clears cookies even without a usable credential, so a caller is never stranded logged in.",
				"operationId": "logout",
				"tags":        []string{"Auth"},
				"responses":   respond(http.StatusOK, "Logged out", schema("Success")),
			},
		},
		prefix + "/me": map[string]any{
			"get": map[string]any{
				"summary":     "Get the authenticated user",
				"description": "The user object is the whole body — it is not wrapped in an envelope.",
				"operationId": "me",
				"tags":        []string{"Auth"},
				"security":    anyCredential,
				"responses": respond(http.StatusOK, "The authenticated user", schema("User"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrSessionRevoked),
			},
		},

		prefix + "/magic-link/send": map[string]any{
			"post": map[string]any{
				"summary": "Mail a magic link",
				"description": "Answers 200 for an address the store does not have, so the route cannot be used to " +
					"discover who is registered. Requires Config.SendMagicLink; without it the answer is 500 " +
					CodeEmailNotConfigured + ", for an unknown address too.",
				"operationId": "sendMagicLink",
				"tags":        []string{"Passwordless"},
				"requestBody": body(inline(nil, map[string]any{
					"email":     map[string]any{"type": "string", "format": "email", "description": "Login mode only; the 2fa branch takes the address from the tempToken and ignores this field."},
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
				})),
				"responses": respond(http.StatusOK, "Link sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrPasswordlessEmailRequired, HTTPErrTempTokenRequired,
					HTTPErrInvalidTempToken, HTTPErrUserNotFound, HTTPErrEmailNotConfigured),
			},
		},
		prefix + "/magic-link/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Consume a magic link and open a session",
				"description": "Single use: the link is burned whether or not the rest of the request succeeds.",
				"operationId": "verifyMagicLink",
				"tags":        []string{"Passwordless"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"token"}, map[string]any{
					"token":     str,
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrTempTokenRequired, HTTPErrInvalidTempToken,
					HTTPErrInvalidMagicLink, HTTPErrTokenMismatch),
			},
		},
		prefix + "/sms/send": map[string]any{
			"post": map[string]any{
				"summary": "Text a one-time code",
				"description": "An unknown address answers 200; an unknown userId answers 404. Requires " +
					"Config.SendSMSCode; without it every request answers 500 " + CodeSMSNotConfigured + " before anything else is checked.",
				"operationId": "sendSMSCode",
				"tags":        []string{"Passwordless"},
				"requestBody": body(inline(nil, map[string]any{
					"userId":    map[string]any{"type": "string", "description": "Login mode: one of userId or email. An email outranks a userId."},
					"email":     map[string]any{"type": "string", "format": "email"},
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
				})),
				"responses": respond(http.StatusOK, "Code sent, or the address is unknown", schema("Success"),
					HTTPErrInvalidBody, HTTPErrUserIDOrEmailRequired, HTTPErrPhoneNotSet,
					HTTPErrTempTokenRequired, HTTPErrInvalidTempToken, HTTPErrUserNotFound, HTTPErrSMSNotConfigured),
			},
		},
		prefix + "/sms/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Verify a one-time code and open a session",
				"operationId": "verifySMSCode",
				"tags":        []string{"Passwordless"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"code"}, map[string]any{
					"userId":    map[string]any{"type": "string", "description": "Required outside `" + StepUpMode + "` mode."},
					"code":      str,
					"mode":      mode,
					"tempToken": map[string]any{"type": "string", "description": "Required in `" + StepUpMode + "` mode."},
					"tenantId":  str,
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrUserIDRequired, HTTPErrTempTokenRequired,
					HTTPErrInvalidTempToken, HTTPErrInvalidSMSCode, HTTPErrUserNotFound),
			},
		},

		prefix + "/2fa/setup": map[string]any{
			"post": map[string]any{
				"summary":     "Begin authenticator enrolment",
				"description": "Stateless: nothing is persisted until the secret comes back to /2fa/verify-setup with a code that verifies against it.",
				"operationId": "setupTwoFactor",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Enrolment material", schema("TOTPSetup"),
					HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/2fa/verify-setup": map[string]any{
			"post": map[string]any{
				"summary":     "Complete authenticator enrolment",
				"description": "The code field is named `token` on this route — not `code`, and not `totpCode`.",
				"operationId": "verifyTwoFactorSetup",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"requestBody": body(inline([]string{"token", "secret"}, map[string]any{
					"token":  map[string]any{"type": "string", "description": "The code from the authenticator app."},
					"secret": map[string]any{"type": "string", "description": "The secret returned by /2fa/setup."},
				})),
				"responses": respond(http.StatusOK, "Second factor enabled", schema("Success"),
					HTTPErrInvalidBody, HTTPErrInvalidTOTPSetupCode, HTTPErrNoAccessToken,
					HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
		prefix + "/2fa/verify": map[string]any{
			"post": map[string]any{
				"summary": "Complete a step-up challenge and open a session",
				"description": "The code field is named `totpCode` here. A bad tempToken answers `" + CodeInvalidAccessToken +
					"` on this route where its siblings answer `" + CodeInvalidTempToken + "`; the clients are written against the difference.",
				"operationId": "verifyTwoFactor",
				"tags":        []string{"TwoFactor"},
				"parameters":  tokenDelivery,
				"requestBody": body(inline([]string{"tempToken", "totpCode"}, map[string]any{
					"tempToken": str,
					"totpCode":  str,
				})),
				"responses": respond(http.StatusOK, "Session issued", schema("AuthResult"),
					HTTPErrInvalidBody, HTTPErrInvalidStepUpToken, HTTPErrInvalidTOTPCode, HTTPErrTOTPNotSetUp),
			},
		},
		prefix + "/2fa/disable": map[string]any{
			"post": map[string]any{
				"summary":     "Turn the second factor off",
				"description": "Refused when the user or the deployment requires 2FA. The user is re-read from the store, so a flag set after the access token was issued is still honoured.",
				"operationId": "disableTwoFactor",
				"tags":        []string{"TwoFactor"},
				"security":    anyCredential,
				"parameters":  protected,
				"responses": respond(http.StatusOK, "Second factor disabled", schema("Success"),
					HTTPErrTwoFactorRequiredForUser, HTTPErrTwoFactorRequiredByPolicy,
					HTTPErrUserNotFound, HTTPErrNoAccessToken, HTTPErrInvalidAccessToken, HTTPErrCSRFInvalid),
			},
		},
	}
}
