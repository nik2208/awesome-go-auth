package auth

// This file is the register of the places this port knowingly does not
// reproduce awesome-node-auth.
//
// The standing rule is the opposite: reproduce the reference including its
// quirks, because the family's shipped clients (ng-awesome-node-auth,
// awesome-node-auth-flutter, the served auth.js) are pinned to it and this
// port's whole value is that they work against it unchanged. Every place the
// rule is set aside is therefore a fact a consumer needs, and until now those
// facts lived only in prose — README sections and CHANGELOG entries — which the
// next person could fold away in good faith with nothing failing.
//
// So this list is the single source of truth. The README's "Deliberate
// deviations from the reference" section is *generated* from it by
// compatibility_markdown.go, and compatibility_test.go regenerates that section
// and compares it byte for byte against the committed README. Editing an entry
// here without regenerating fails; editing the README by hand fails; adding a
// deviation without a README entry is not possible, because the README entry is
// this entry. The register test additionally pins the id set and the wire facts
// each entry has to keep stating, so that an entry cannot be hollowed out even
// by someone who does regenerate.
//
// Because the section is generated, the prose fields below are markdown: the
// backticks and emphasis a reader sees in the README are written here, once.
// They are ordinary sentences otherwise, and a caller that serialises the
// register gets prose it can render or strip as it likes.
//
// What belongs here: a deliberate, client-visible difference in behaviour. What
// does not: a bug (fix it), a feature the port has not reached yet (that is a
// gap, and belongs in an issue), or an internal implementation choice that no
// caller can observe on the wire.

// ReferenceRevision names the revision every Deviation.Citations entry resolves
// against. The citations are file:line, so they mean nothing without it.
const ReferenceRevision = "awesome-node-auth@cc01e997 (npm 1.9.0)"

// Deviation is one place this port deliberately answers differently from the
// reference.
//
// The two behaviours are recorded separately, and the reference's carries a
// citation, so that a reader can check the claim rather than take it — and so
// that a maintainer who changes one of them has to come here and say so.
type Deviation struct {
	// ID is the stable handle for this deviation. It never changes once
	// published: the README keys its mirror on it and the tests pin the set, so
	// renaming one is a deliberate, visible act rather than a silent edit.
	ID string `json:"id"`
	// Title is the one-line heading a human reads first. It becomes the README
	// section heading for this entry.
	Title string `json:"title"`
	// Surface is the route or API surface affected, written as it is mounted —
	// paths are relative to the configured prefix, spelled <prefix> here.
	Surface string `json:"surface"`
	// Behaviour is what this port does.
	Behaviour string `json:"behaviour"`
	// Reference is what awesome-node-auth does instead.
	Reference string `json:"reference"`
	// Citations locate Reference in the reference source, as file:line or
	// file:line-line, resolved against ReferenceRevision.
	Citations []string `json:"citations"`
	// Why is the reason the standing rule was set aside. An entry without one is
	// not a decision, it is a bug that has not been recognised yet.
	Why string `json:"why"`
	// Notes carries any further labelled paragraphs this entry needs beyond the
	// four above — how to observe the difference, what a host can do about it.
	// Most entries need none.
	Notes []DeviationNote `json:"notes,omitempty"`
}

// DeviationNote is one extra labelled paragraph on a Deviation.
type DeviationNote struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

// APICompatibilityNotes is the contract this port targets, plus every known
// deviation from it.
type APICompatibilityNotes struct {
	// ContractTarget names the clients the wire shape is pinned to.
	ContractTarget string `json:"contractTarget"`
	// ReferenceRevision is ReferenceRevision, carried in the value so a caller
	// that serialises these notes ships the revision its citations need.
	ReferenceRevision string `json:"referenceRevision"`
	// CookieConventions and BearerConventions summarise the two delivery modes.
	CookieConventions string `json:"cookieConventions"`
	BearerConventions string `json:"bearerConventions"`
	// KnownDeviations is the register, in no significant order.
	KnownDeviations []Deviation `json:"knownDeviations"`
}

// CompatibilityNotes returns the wire contract this port targets and the known
// deviations from it.
//
// The result is freshly built on every call and shares nothing with the
// package, so a caller may sort, filter or edit it without affecting anyone
// else's view.
func CompatibilityNotes() APICompatibilityNotes {
	return APICompatibilityNotes{
		ContractTarget: "awesome-node-auth, as consumed by ng-awesome-node-auth, " +
			"awesome-node-auth-flutter and the served auth.js",
		ReferenceRevision: ReferenceRevision,
		CookieConventions: "Cookie mode is the default: login, register and refresh answer " +
			`{"success": true} and set accessToken, refreshToken and csrf-token, each ` +
			"resolved __Host- / __Secure- / bare from the cookie policy and read back in " +
			"that order. CSRF is double-submit on X-CSRF-Token, enforced for " +
			"cookie-authenticated unsafe methods only.",
		BearerConventions: "X-Auth-Strategy: bearer (exact, case-sensitive) switches to " +
			"top-level accessToken/refreshToken in the body and sets no cookies at all. " +
			"Protected routes then read Authorization: Bearer <accessToken> and are exempt " +
			"from CSRF.",
		KnownDeviations: []Deviation{
			{
				ID:      "forgot-password-succeeds-on-delivery-failure",
				Title:   "`forgot-password`: unconditional 200 on delivery failure",
				Surface: "`POST <prefix>/forgot-password`",
				Behaviour: `Always ` + "`200 {\"success\": true}`" + ` — when the mail was sent, when the ` +
					"configured sender returns an error, and when no sender is configured at " +
					"all. The reset token stays stored in every case. A *store* failure still " +
					"answers `500`, which is the reference's behaviour and is kept.",
				Reference: "The send sits inside the route's `try`, so a throwing mailer reaches " +
					"`handleError` and answers `500`.",
				Citations: []string{"auth.router.ts:787-798"},
				Why: "That `500` fires only for an address that **exists**, so a broken mail " +
					"gateway turns the one route whose purpose is to reveal nothing about who is " +
					"registered into an account-enumeration oracle. The contract records the " +
					"status as `[UNTESTED]`, and no client can depend on one that appears only " +
					"when the operator's mailer is down.",
				Notes: []DeviationNote{{
					Label: "Observing the failure",
					Text: "Only the HTTP surface swallows it. `Auth.ForgotPassword` absorbs " +
						"`ErrDeliveryFailed` (and nothing else) and logs `auth: password reset " +
						"delivery failed; the route still answered success: …`, without naming the " +
						"address. `Service.ForgotPassword` still returns the error, so a direct " +
						"library caller learns about it.",
				}},
			},
			{
				ID:      "temp-token-is-typed-not-an-access-token",
				Title:   "The 2FA step-up token is typed, not an access token",
				Surface: "`POST <prefix>/login` (the `tempToken` in a 2FA challenge) and the step-up routes that accept it",
				Behaviour: "The step-up token carries its own type. It is accepted by the " +
					"second-factor routes and by nothing else, and an ordinary access token is " +
					"not accepted in its place.",
				Reference: "Mints the `tempToken` as an ordinary 5-minute access token with no " +
					"claim distinguishing it, so it authenticates any protected route for five " +
					"minutes before the second factor has been presented, and a full access " +
					"token also passes as a `tempToken`.",
				Citations: []string{"auth.router.ts:572-575", "token.service.ts:20-24"},
				Why: "Reproducing it would mean shipping a five-minute bypass of the second " +
					"factor the challenge exists to demand. The type claim is not on the wire — " +
					"the token is opaque to every client — and the reference's own sharing is " +
					"`[UNTESTED]` there, so no shipped client depends on it. The cost is that the " +
					"`tempToken` in a `2FA_SETUP_REQUIRED` answer cannot reach the enrolment " +
					"routes, which sit behind the access-token gate.",
			},
			{
				ID:      "link-request-exempts-bearer-from-csrf",
				Title:   "`link-request` exempts a bearer credential from CSRF",
				Surface: "`POST <prefix>/link-request`",
				Behaviour: "A request carrying a real `Authorization: Bearer` credential is exempt " +
					"from the double-submit check, as it is on every other route. Without one " +
					"the check is enforced whether or not the request is cookie-authenticated.",
				Reference: "Gates its hand-written double-submit check on `config.csrf.enabled` " +
					"alone, with no `usingBearer` term — unlike its own auth middleware " +
					"(`auth.middleware.ts:35`) — so it answers `403 CSRF_INVALID` to a " +
					"bearer-authenticated caller that carries no cookie pair.",
				Citations: []string{"auth.router.ts:1489-1495"},
				Why: "`Authorization` is not CORS-safelisted, so no cross-site page can set it and " +
					"the exemption costs no CSRF protection: every request it admits is one an " +
					"attacker could not have forged. The family contract records the reference's " +
					"behaviour as a MISMATCH that breaks native bearer clients with no cookie " +
					"jar, and marks it `[UNTESTED]`. A client that sends the pair is accepted by " +
					"both.",
			},
			{
				ID:      "password-policy-on-reset-and-change",
				Title:   "A password policy on `reset-password` and `change-password`",
				Surface: "`POST <prefix>/reset-password` and `POST <prefix>/change-password`",
				Behaviour: "Rejects a new password shorter than `Config.MinPasswordLen` with " +
					"`400 {\"error\": \"Password is too weak\", \"code\": \"WEAK_PASSWORD\"}`, checked " +
					"before the current-password comparison on `/change-password`.",
				Reference: "Applies no strength check on either route — the password goes " +
					"straight to `passwordService.hash`. Its own OpenAPI document declares " +
					"`minLength: 8` on both bodies and nothing enforces it.",
				Citations: []string{"auth.router.ts:801-825", "auth.router.ts:904-932"},
				Why: "The reference will hash and store a two-character password on a route " +
					"reached with a mailed token, which silently undoes whatever policy the host " +
					"applied at registration. `WEAK_PASSWORD` has no reference counterpart, so a " +
					"client that does not know the code still sees a `400` it must show the user " +
					"either way. The check order differs too: the reference would report a wrong " +
					"current password first.",
			},
			{
				ID:        "totp-setup-omits-qrcode",
				Title:     "`2fa/setup` omits the QR code",
				Surface:   "`POST <prefix>/2fa/setup`",
				Behaviour: "Answers `{\"secret\", \"otpauthUrl\"}` and nothing else.",
				Reference: "Also returns `qrCode`, the same provisioning URI rendered as a PNG " +
					"data URL.",
				Citations: []string{"auth.router.ts:832-835"},
				Why: "The root package is stdlib plus `golang.org/x/crypto` and a QR encoder is " +
					"neither. A client renders `otpauthUrl` itself, which is what the Rust port of " +
					"this family does too. A client that displays the reference's PNG directly " +
					"has to encode the URI instead.",
			},
			{
				ID:        "one-time-tokens-are-base64url",
				Title:     "One-time tokens are base64url, not hex",
				Surface:   "The reset-password, email-verification and email-change tokens carried in mailed links",
				Behaviour: "Renders 32 random bytes as 43 base64url characters.",
				Reference: "Renders the same 32 random bytes as 64 hexadecimal characters.",
				Citations: []string{"token.service.ts:270-272"},
				Why: "`randomToken` is shared with the API-key and IdP code paths, which have no " +
					"reason to be hex. Both forms are URL-safe and opaque, and no shipped client " +
					"parses or measures a token — but a host that pinned a column width or a " +
					"validation regex to 64 hex characters has to widen it.",
			},
			{
				ID:      "advertised-2fa-methods-require-store-support",
				Title:   "An advertised 2FA method must be one the store supports",
				Surface: "`POST <prefix>/login`, the `available2faMethods` list in a 2FA challenge",
				Behaviour: "Advertises a second factor only when the configured user store " +
					"implements the capability that factor needs, as well as the configuration " +
					"and user state the reference checks.",
				Reference: "Checks configuration and user state alone, so it can advertise a " +
					"method whose route then answers `501` because the store does not implement it.",
				Citations: []string{"auth.router.ts:557-559"},
				Why: "A client picks its next request from this list, so advertising a factor " +
					"that cannot complete strands the login with no way forward. The extra term " +
					"can only ever remove an option that would have failed; a deployment whose " +
					"store implements the capability sees the reference's list.",
			},
			{
				ID:      "csrf-cookie-not-reissued-with-tokens",
				Title:   "The CSRF cookie is not reissued alongside tokens",
				Surface: "`Set-Cookie` on every route that issues tokens, including `POST <prefix>/login` and `POST <prefix>/refresh`",
				Behaviour: "The CSRF cookie is written by the router-level auto-init only, when " +
					"the request carries no readable one. Issuing tokens does not reissue it, so " +
					"one response never carries two `Set-Cookie` headers for that name.",
				Reference: "`setTokenCookies` sets a fresh `csrf-token` cookie on every cookie-mode " +
					"issuance — it is reached from `sendTokens` (`auth.router.ts:403`) and from the " +
					"OAuth redirect path — in addition to the router-level auto-init, so a first " +
					"login emits two `Set-Cookie` headers for the same name with different values " +
					"in one response.",
				Citations: []string{"token.service.ts:204-209", "auth.router.ts:529-538"},
				Why: "Which of two same-name `Set-Cookie` headers survives is left to the cookie " +
					"jar, so the reference's pair makes the token a client will send back " +
					"ambiguous on exactly the response that establishes it. Emitting one keeps " +
					"the double-submit pair consistent. The cookie stays JS-readable and valid " +
					"either way, so a client that reads it per request — as all three family " +
					"clients do — cannot tell the difference.",
			},
			{
				ID:      "cookie-max-age-follows-configured-ttl",
				Title:   "Cookie `Max-Age` follows the configured TTL, not a hardcoded 7 days",
				Surface: "`Set-Cookie` on every cookie-mode route that issues tokens, including `POST <prefix>/login`, `POST <prefix>/register` and `POST <prefix>/refresh`",
				Behaviour: "Derives each token cookie's `Max-Age` from the lifetime of the token it " +
					"carries — the access cookie from `Config.AccessTokenTTL`, the refresh cookie " +
					"from `Config.RefreshTokenTTL` — unless the deployment sets " +
					"`CookieOptions.AccessTokenMaxAge` or `RefreshTokenMaxAge` explicitly. On " +
					"`DefaultConfig` that is `Max-Age=900` on the access cookie and " +
					"`Max-Age=2592000` (30 days) on the refresh cookie.",
				Reference: "Hardcodes both lifetimes in `setTokenCookies`, ignoring configuration: " +
					"`maxAge: 15 * 60 * 1000` on the access cookie and " +
					"`maxAge: 7 * 24 * 60 * 60 * 1000` on the refresh cookie, so it always emits " +
					"`Max-Age=604800` there whatever `refreshTokenExpiresIn` says.",
				Citations: []string{"token.service.ts:28", "token.service.ts:195", "token.service.ts:199-202"},
				Why: "Deriving the cookie lifetime from the configured TTL is the point: a cookie " +
					"must not outlive, or expire before, the token it carries. The reference's " +
					"hardcoded value silently contradicts its own `refreshTokenExpiresIn` — that " +
					"option signs the refresh token (defaulting to `7d`), so raising it to 30 days " +
					"leaves the token valid for 30 days while the browser drops the cookie " +
					"carrying it after 7, ending the session early with a credential nobody can " +
					"present. The divergence is a header value, not a validity change: each port " +
					"honours its own tokens' server-side expiry either way. The access cookie " +
					"matches the reference on `DefaultConfig` (both 15 minutes, `Max-Age=900`) and " +
					"diverges on any custom `AccessTokenTTL`; the refresh cookie diverges at the " +
					"default too, because `Config.RefreshTokenTTL` is 30 days here where the " +
					"reference's refresh token defaults to `7d`.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "A host that needs the reference's literal headers sets " +
						"`CookieOptions.RefreshTokenMaxAge` to 7 days (and `AccessTokenMaxAge` to 15 " +
						"minutes); an explicit value is never overwritten by the derivation.",
				}},
			},
		},
	}
}
