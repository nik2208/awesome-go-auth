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

// DevLineRevision names the second tree this package cites: nik2208/node-auth,
// the private line the published reference is cut from.
//
// Nothing in the deviation register resolves against it. Deviation.Citations is
// ReferenceRevision only, and compatibility_test.go enforces that. This
// constant exists because a few wire facts outside the register do come from
// the dev line, and a reader has to be able to tell which tree a file:line in a
// doc comment means: a citation written as "node-auth auth.router.ts:N" is this
// revision, a bare "auth.router.ts:N" is ReferenceRevision.
//
// One such fact exists today, and it is deliberate rather than accidental: the
// INVALID_INPUT refusal on POST /register (CodeInvalidInput in wire.go,
// ErrInvalidInput in errors.go, the check in Service.Register). The dev line
// mounts that route by default and gives its default handler a presence check
// on the two fields; the published reference mounts /register only when the
// host supplies options.onRegister (auth.router.ts:713), has no default handler
// at all, and therefore has no message and no code of its own there. Copying
// the dev line's answer is a bet that the published tree will grow the same
// one. When the dev line ships, ReferenceRevision moves forward and those
// citations fold back into it.
const DevLineRevision = "nik2208/node-auth@e8af923 (unreleased, package.json 1.9.0)"

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
				ID:      "totp-issuer-defaults-to-config-issuer",
				Title:   "The default TOTP issuer is `Config.Issuer`, not `awesome-node-auth`",
				Surface: "`POST <prefix>/2fa/setup`, the issuer in `otpauthUrl`",
				Behaviour: "Labels the provisioning URI with `Config.TwoFactorAppName` when it is " +
					"set and with `Config.Issuer` when it is not — `awesome-go-auth` on " +
					"`DefaultConfig` — as both the label prefix and the `issuer` parameter, in " +
					"otplib's `issuer:account` form.",
				Reference: "Labels it with `config.twoFactor.appName` and falls back to the " +
					"literal `'awesome-node-auth'` — its own package name — when no app name is " +
					"configured.",
				Citations: []string{"auth.router.ts:830", "totp.strategy.ts:11-17"},
				Why: "The reference's fallback names the library, not the deployment, which is " +
					"the wrong thing to show a user who opens their authenticator app. This port " +
					"has carried `Config.Issuer` there since the route existed, so enrolments " +
					"made before `TwoFactorAppName` was added sit under that name in users' apps, " +
					"and switching the default now would file every new enrolment under a " +
					"different name from the old ones on the same deployment. The difference is " +
					"visible only on a deployment that sets neither field: one that sets " +
					"`TwoFactorAppName` — the reference's `appName` — gets exactly the " +
					"reference's label.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "`WithTwoFactorAppName(\"awesome-node-auth\")`. Any name given is carried " +
						"verbatim; only the fallback differs.",
				}},
			},
			{
				ID:      "totp-accepts-one-step-of-skew",
				Title:   "TOTP codes from the adjacent 30-second steps are accepted",
				Surface: "`POST <prefix>/2fa/verify-setup` and `POST <prefix>/2fa/verify`, the two routes that check a TOTP code (`/2fa/disable` takes none, in either implementation)",
				Behaviour: "Accepts a code from the previous or the next 30-second step as well as " +
					"the current one: `validateTOTPCode` tries `TOTPSkew = 1` step either side " +
					"of now (`totp.go`), so three codes are valid at any instant and each code " +
					"is accepted over a 90-second window — its own step and the 30 seconds " +
					"before and after it — where the reference's window is 30.",
				Reference: "Accepts the current step only. `TotpStrategy.verify` in " +
					"`totp.strategy.ts` calls `totp.verify(token, { secret })` and sets no other " +
					"option, and otplib's `verify` — `@otplib/totp` 13.4.0, the version the " +
					"reference's package-lock.json pins for `otplib ^13.3.0` (13.4.1 today, same " +
					"default) — defaults its window to zero seconds either " +
					"side of now: `epochTolerance:f=0` in the `verify` method of " +
					"`@otplib/totp`'s `dist/index.js`, documented in its " +
					"types as `default: 0 = current period only`. A code is refused from the " +
					"first second of the step after its own.",
				Citations: []string{"totp.strategy.ts:22-25", "auth.router.ts:846", "auth.router.ts:868"},
				Why: "An authenticator runs on the phone's clock, and a user reads a code some " +
					"seconds before the server sees it, so with no tolerance a code read in the " +
					"last seconds of a step — or on a phone a few seconds adrift — is refused " +
					"and the user has to try again, at every step boundary. RFC 6238 §5.2 " +
					"recommends allowing one step for exactly that delay, and one step is the " +
					"tolerance mainstream verifiers ship with. The cost is that three of the " +
					"million possible codes are valid at any instant instead of one.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not possible: `TOTPSkew` is a constant, not a knob, and no knob is " +
						"planned. A deployment gets the one-step window whether or not it wants it.",
				}},
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
				ID:      "config-require2fa-is-a-system-policy-term",
				Title:   "`Config.Require2FA` is a deployment-level 2FA policy the reference has no equivalent of",
				Surface: "`POST <prefix>/2fa/disable` and `POST <prefix>/login`",
				Behaviour: "`Config.Require2FA` is a third term in two decisions the reference " +
					"makes with two. On `/2fa/disable` it is ORed with the stored `require2FA` " +
					"into the system-policy refusal, so a deployment that sets it and configures " +
					"no settings store at all answers " +
					"`403 {\"error\":\"Cannot disable 2FA: required by system policy\",\"code\":\"2FA_REQUIRED\"}` " +
					"where the reference answers `200 {\"success\":true}` and turns the factor " +
					"off. At login it is ORed into the challenge term, so a user with no enrolled " +
					"TOTP and no per-user flag is challenged where the reference logs them " +
					"straight in.",
				Reference: "Has no config-level `require2FA`: the name exists only on the settings " +
					"store and on the user record, never on `AuthConfig`. `/2fa/disable` refuses " +
					"on the per-user flag and on the stored setting and on nothing else, and " +
					"login challenges on an enrolled TOTP or the per-user flag alone",
				Citations: []string{
					"auth.router.ts:880-902", "auth.router.ts:552",
					"settings-store.interface.ts:64", "user.model.ts:39",
				},
				Why: "A deployment-wide switch is what an embedder without the admin router has " +
					"instead of the Control panel: the reference reaches the same policy by " +
					"writing `require2FA: true` through a settings store, which requires running " +
					"a store and an admin surface to write it. The term is additive and " +
					"inert by default — `Config.Require2FA` is `false` unless a deployment sets " +
					"it, and a deployment that leaves it alone gets the reference's answers on " +
					"both routes, including with a settings store attached. Both wire shapes are " +
					"the reference's own: the `403` body is the one it sends for the stored " +
					"setting, and the challenge is the one it sends for the per-user flag, so a " +
					"client meets nothing it has no branch for.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `Config.Require2FA` unset (the default) and express the policy " +
						"through a `SettingsStore` holding `require2FA: true`, which is the " +
						"reference's own term and produces the same `/2fa/disable` refusal with no " +
						"login-side difference.",
				}},
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
				ID:      "oauth-provisioning-is-a-policy-not-a-function",
				Title:   "OAuth provisioning is a configured policy, with three refusals the reference has no counterpart for",
				Surface: "`GET <prefix>/oauth/{provider}/callback`",
				Behaviour: "Resolves the callback under `OAuthWiring.Provisioning` " +
					"(`OAuthProvisioning{AutoCreate, AllowedEmailDomains, RequireVerifiedEmail, " +
					"OnEmailMatch, FieldMap}`). Three of its outcomes are refusals with no reference " +
					"counterpart, all `403` JSON on the callback: `OAUTH_EMAIL_NOT_VERIFIED` when " +
					"`RequireVerifiedEmail` is set and the provider asserted nothing, " +
					"`OAUTH_EMAIL_DOMAIN_NOT_ALLOWED` when the address is outside " +
					"`AllowedEmailDomains`, and `OAUTH_USER_NOT_PROVISIONED` when the identity is " +
					"unknown and `AutoCreate` is false, or when the address belongs to an account and " +
					"`OnEmailMatch` is `reject`. The fourth, `OnEmailMatch: \"conflict\"`, is the " +
					"reference's own `OAUTH_ACCOUNT_CONFLICT`: the stash and the 302 to " +
					"`/account-conflict`, sent exactly as the reference sends them. An account the " +
					"callback creates records the provider as `loginProvider`, takes " +
					"`isEmailVerified` from the provider's claim — true when the provider said " +
					"nothing, which is the common case — and fills further columns from `FieldMap`.",
				Reference: "Has no provisioning at all: `findOrCreateUser(profile, state)` is an " +
					"abstract method the integrator implements, and the library knows only two " +
					"outcomes from it — a user, which becomes a session, or an `AuthError` coded " +
					"`OAUTH_ACCOUNT_CONFLICT`, which becomes the stash and the redirect. Anything " +
					"else that function throws reaches `handleError`, which answers `500` unless it " +
					"is an `AuthError` carrying its own status.",
				Citations: []string{
					"generic-oauth.strategy.ts:169-172", "google.strategy.ts:67",
					"github.strategy.ts:78", "auth.router.ts:1346-1355",
				},
				Why: "This port's consumer configures the library from a file; it cannot subclass a " +
					"strategy, so a policy expressed as configuration is the only form the " +
					"reference's function can take here. The refusals are what that policy needs to " +
					"say and the reference never had to: its integrator would have thrown whatever " +
					"they liked. Defaults reproduce what this port did before the policy existed — " +
					"`AutoCreate` true, `OnEmailMatch` `link`, no domain list, no verification " +
					"demand — so a deployment that configures nothing cannot see any of the three " +
					"codes. `OnEmailMatch` exists because linking by address across providers is the " +
					"account-takeover shape the reference's own store interface warns about " +
					"(`findByProviderAccount`, `user-store.interface.ts:105-119`), and the port's " +
					"default is the unsafe one only because changing it silently would lock accounts " +
					"out of deployments that rely on it.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `OAuthWiring.Provisioning` nil. The callback then behaves as it " +
						"always has, no refusal is reachable, and the only policy-driven answer that " +
						"can appear is the reference's own account conflict — which needs " +
						"`OnEmailMatch: \"conflict\"` and so cannot appear either.",
				}},
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
			{
				ID:      "jwks-cors-wildcard-string-form",
				Title:   "The JWKS CORS wildcard is the one-element `[]string{\"*\"}`, not an entry",
				Surface: "`GET <prefix>/.well-known/jwks.json`",
				Behaviour: "A `JWKSCORSOrigins` of exactly `[]string{\"*\"}` answers " +
					"`Access-Control-Allow-Origin: *` to every request, the same as leaving the " +
					"field nil. Every other slice is an allowlist: a listed `Origin` is echoed " +
					"back, an unlisted one gets no `Access-Control-Allow-Origin` header at all, " +
					"and an entry `*` inside a longer slice is an ordinary entry that matches " +
					"only an `Origin` header of literally `*`.",
				Reference: "`jwksCorsOrigins` is typed `string | string[]` and the wildcard test is " +
					"`corsOrigins === '*'` against the whole value, so only the *string* is the " +
					"wildcard. Every array is an allowlist, including `['*']`, whose one entry " +
					"matches only the `Origin` header `*` — one no browser sends — so that value " +
					"disables the header rather than opening the route.",
				Citations: []string{"auth.router.ts:492-500", "auth-config.model.ts:102"},
				Why: "Go has no `string | string[]`, and `[]string` is the shape every other list " +
					"in this package has, so one of the two readings of `{\"*\"}` had to win. The " +
					"reference's own documented default for the field is the wildcard " +
					"(`@default '*'`), so the slice that spells it is read as the string form " +
					"rather than as an allowlist that can never match — the reading a host " +
					"writing `{\"*\"}` plainly intends. The difference is confined to that single " +
					"value: nil, the empty slice and every other allowlist behave exactly as the " +
					"reference does.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "A deployment that means the reference's `['*']` — an allowlist no " +
						"browser `Origin` can match — writes the empty slice `[]string{}` here, " +
						"which sends the header to nobody. Note also that neither implementation " +
						"sends `Vary: Origin` while both send `Cache-Control: public, max-age=3600`, " +
						"so an allowlisted response must not reach a shared cache.",
				}},
			},
			{
				ID:      "resource-server-gates-all-credential-routes",
				Title:   "Resource-server mode unmounts the whole credential set, not six routes of it",
				Surface: "`HTTPConfig.ResourceServer`: the nineteen routes of `ResourceServerGatedRoutes`",
				Behaviour: "Registers none of the nineteen routes that mint, deliver or consume a " +
					"credential, so each answers `404` — `/register`, `/login`, " +
					"`/refresh`, `/logout`, `/forgot-password`, `/reset-password`, " +
					"`/change-password`, `/send-verification-email`, `/verify-email`, " +
					"`/change-email/request`, `/change-email/confirm`, `/magic-link/send`, " +
					"`/magic-link/verify`, `/sms/send`, `/sms/verify`, `/2fa/setup`, " +
					"`/2fa/verify-setup`, `/2fa/verify` and `/2fa/disable`. " +
					"`GenerateOpenAPISpec` drops the same nineteen under " +
					"`OpenAPIInfo.ResourceServer`, so the published spec and the mount agree. " +
					"What stays is `/me`, the session routes, `/profile`, `/add-phone`, " +
					"`/account` and the OAuth and linking group — and those still need a local " +
					"user store: `/me` reads it through `Service.Authenticate`, `/profile`, " +
					"`/add-phone` and `/account` write it, and the OAuth callback provisions a " +
					"user and mints a local session. The flag is about credentials, not about " +
					"store independence. The deployment with no user store is the one that " +
					"mounts `ResourceServerMiddleware` on its own routes, whose bearer and " +
					"cookie paths both build the principal from verified claims and read no " +
					"store at all.",
				Reference: "Guards six registrations on `isResourceServer` — `/login`, `/logout`, " +
					"`/refresh`, `/register`, `/forgot-password` and `/reset-password` — and " +
					"leaves the other thirteen mounted. Those thirteen reach handlers that read " +
					"and write the user store the mode says this instance does not have, so a " +
					"caller gets a `500` from a failing store lookup, or a `200` on a route that " +
					"mailed nothing, rather than a routing answer.",
				Citations: []string{
					"auth.router.ts:507-510",
					"auth.router.ts:541",
					"auth.router.ts:590",
					"auth.router.ts:622",
					"auth.router.ts:713",
					"auth.router.ts:777",
					"auth.router.ts:802",
				},
				Why: "The reference's own comment for the flag is that this instance has no local " +
					"user DB and only token verification makes sense, and the six guards are an " +
					"incomplete application of exactly that rule: a magic link cannot be minted, " +
					"an SMS code cannot be stored and a TOTP secret cannot be enrolled without " +
					"the store the mode has removed. Leaving them mounted turns a configuration " +
					"mistake into a runtime failure on a credential route, which is the worst " +
					"place to discover it. Gating all nineteen makes the mode mean one thing, " +
					"and makes it checkable: the same list drives the mount, the OpenAPI spec " +
					"and the conformance suite. It is drawn at the credential and not at the " +
					"store deliberately: gating every store-reading route would unmount `/me` " +
					"and the account routes from the deployment that has both a store and a " +
					"remote issuer, which is the commoner configuration, to protect one that " +
					"has no reason to mount the auth router at all.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Leave `HTTPConfig.ResourceServer` unset and mount " +
						"`ResourceServerMiddleware` on the host's own routes: the bearer " +
						"verification is independent of the gating, and every auth route then stays " +
						"mounted as it is today. A host that wants the reference's partial set " +
						"mounts two routers — one with the flag, one without — under different " +
						"prefixes.",
				}},
			},
			{
				ID:      "jwks-unknown-kid-refetch-is-rate-limited",
				Title:   "An unknown `kid` refetches the JWKS at most once per `MinRefreshInterval`",
				Surface: "`VerifyRS256` / `JWKSClient`: the rotation retry behind every bearer token",
				Behaviour: "On a `kid` the cached JWKS does not carry, the cache is invalidated and " +
					"the key looked up once more — but only when the cached document is older " +
					"than `ResourceServerConfig.MinRefreshInterval` (default " +
					"`DefaultJWKSMinRefreshInterval`, 30 seconds). Inside that window the token " +
					"is refused with `Unknown signing key` and no HTTP call is made, so N " +
					"requests bearing unknown `kid`s cost at most one outbound fetch per " +
					"interval. A negative `MinRefreshInterval` turns the limit off and restores " +
					"the reference behaviour exactly. The `RS256` allow-list is also checked " +
					"before the key lookup rather than after it, so an `alg: none` or `alg: " +
					"HS256` token never reaches the issuer at all; both orderings answer `401` " +
					"`INVALID_TOKEN`, only the logged message differs.",
				Reference: "Calls `jwksClient.invalidateCache()` and retries on every unknown `kid`, " +
					"with no interval and no cap. `invalidateCache` clears the cached document " +
					"*and* the in-flight `fetchPromise`, so concurrent requests do not even " +
					"coalesce onto one fetch, and the `algorithms: ['RS256']` pin is inside " +
					"`jwt.verify`, which runs after the key lookup.",
				Citations: []string{
					"token.service.ts:116-125",
					"token.service.ts:136",
					"jwks.service.ts:101-105",
					"jwks.service.ts:56-58",
				},
				Why: "Unrestricted, the retry is an unauthenticated request amplifier: anyone who " +
					"can reach the resource server makes it call the issuer once per request by " +
					"sending a random `kid`, and because the in-flight handle is dropped too, a " +
					"burst multiplies rather than coalesces. Worse, the refusal is collateral: " +
					"every legitimate request arriving between the invalidation and the next " +
					"document landing takes the cold path and blocks on the issuer, which is the " +
					"one thing the stale-while-revalidate cache exists to prevent. The interval " +
					"costs a real rotation nothing — a cached document is typically an hour old " +
					"by the time a token names a key it does not carry, so the first such token " +
					"still refetches and still verifies — and only refuses the case of two " +
					"rotations inside 30 seconds. `node-jwks-rsa` ships the same guard as its " +
					"`rateLimit` option for the same reason.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Set `ResourceServerConfig.MinRefreshInterval` to any negative duration: " +
						"every unknown `kid` then invalidates and refetches, as the reference " +
						"does. Nothing else in the verifier changes.",
				}},
			},
			{
				ID: "register-issues-a-session",
				Title: "`register` opens a session, where the reference only creates the " +
					"account — provisional, tracked as `nik2208/awesome-go-auth#21`",
				Surface: "`POST <prefix>/register`",
				Behaviour: "Mints a token pair for the new account and delivers it with the " +
					"`201`, through the same delivery switch every other issuing route uses: " +
					"in cookie mode the response is " +
					"`201 {\"success\": true, \"userId\": \"…\"}` plus `Set-Cookie` for " +
					"`accessToken` and `refreshToken`, and in bearer mode (`X-Auth-Strategy: " +
					"bearer`) the same body with top-level `accessToken` and `refreshToken` " +
					"fields and no cookies at all. A refresh session row is created with it, so " +
					"the account is logged in as soon as it exists and `GET <prefix>/me` " +
					"answers on the credential the registration returned.",
				Reference: "Mounts the route at all only when the host supplies " +
					"`options.onRegister`; without it there is no `POST <prefix>/register` in " +
					"the reference and the path answers `404` where this port answers `201` " +
					"(or `400 INVALID_INPUT` for a body missing a credential). That " +
					"unconditional mount is a second, smaller difference on this surface, and " +
					"it is named here rather than kept as a separate entry because a host that " +
					"has no register route has no session question to ask. Where the reference " +
					"*is* mounted it answers `201 {\"success\": true, \"userId\": user.id}` and " +
					"nothing else: the register route never reaches `sendTokens` — the one " +
					"function that writes `setTokenCookies` or the body tokens — and never " +
					"reaches `issueTokens`, so no cookie is set, no token is returned and no " +
					"session row is created. The caller is unauthenticated after a successful " +
					"registration and has to `POST /login` with the credentials it just chose.",
				Citations: []string{
					"auth.router.ts:713-730",
					"auth.router.ts:726",
					"auth.router.ts:399-406",
				},
				Why: "**Provisional, and recorded rather than endorsed.** The entry exists so " +
					"that a difference which is client-visible today is visible in the contract " +
					"too; it is not a settled product decision. What it costs is a bypass of the " +
					"email verification gate: `Service.Register` sets `IsEmailVerified` from the " +
					"configured mode and then mints the token pair unconditionally, so under " +
					"`strict` a brand-new account walks away holding a usable access token that " +
					"`POST <prefix>/login` would have refused for the same user with `403 " +
					"EMAIL_NOT_VERIFIED`. The registration hands out exactly the credential the " +
					"gate exists to withhold. The family already carries that as a defect and " +
					"not as a decision: it is tracked as " +
					"[nik2208/awesome-go-auth#21](https://github.com/nik2208/awesome-go-auth/issues/21), and " +
					"`awesome-lambda-auth`'s contract suite pins the current behaviour under " +
					"protest in `test/contract/cases_register_test.go`, which calls it " +
					"security-relevant and is written to fail the moment #21 lands. This entry " +
					"follows that suite: when #21 lands, the behaviour changes and the entry is " +
					"retired, not reworded. " +
					"What has kept the issuance in place so far is only the first-run cost of " +
					"the alternative — a registration that leaves the caller logged out makes " +
					"the first thing a new account does re-present the password it typed one " +
					"screen earlier, and issuing here removes that round trip. That argument " +
					"covers the round trip and nothing else; it is not a reason to skip a " +
					"verification gate the deployment asked for, and where the two conflict the " +
					"gate is the stronger claim. " +
					"The difference has stayed invisible this long because it costs the shipped " +
					"clients nothing: " +
					"`ng-awesome-node-auth` posts the registration `withCredentials` and reads " +
					"only `userId` off the body, so the cookies simply land in the jar and its " +
					"next session check succeeds instead of redirecting to the login form; the " +
					"Flutter client reads `userId` (or `id`) and ignores every other field, so " +
					"on native it discards the tokens and logs in exactly as it does today, and " +
					"on web it inherits the same cookie jar. Neither reads a field this port " +
					"omits, and neither has a branch that a present session breaks — but a " +
					"client that does not notice is not a client that consented, and it is the " +
					"gate, not the client, that #21 is about.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not possible today: there is no knob. The issuance is unconditional " +
						"in the handler and no configuration field switches it off, which is part " +
						"of why `nik2208/awesome-go-auth#21` is open rather than closed as " +
						"configurable: a deployment running `EmailVerificationModeStrict` cannot " +
						"opt out of the email verification bypass described above. The only way " +
						"to get the reference's answer now is to not mount " +
						"`POST <prefix>/register` — `HTTPConfig.ResourceServer` unmounts it along " +
						"with the rest of the credential set — and create accounts through " +
						"`UserStore` itself, verifying the address before the first login. Read " +
						"\"no knob\" as the state of this release and not as a decision that it " +
						"stays that way: the fix for #21 is expected to remove the issuance " +
						"rather than add a switch.",
				}},
			},
			{
				ID:      "ui-config-verify-email-follows-the-effective-mode",
				Title:   "`ui/config`: `features.verifyEmail` follows the effective verification mode",
				Surface: "`GET <prefix>/ui/config`, the `features.verifyEmail` flag",
				Behaviour: "Answers `true` when `Config.SendEmailVerification` is wired *and* the " +
					"effective `Config.EmailVerificationMode` is `lazy` or `strict`. An unset mode " +
					"is `none` here as it is everywhere else in this port, and `DefaultConfig` " +
					"writes `none` into the field outright, so a deployment that wired the sender " +
					"and left the mode alone is told `false` and its login page offers no " +
					"verify-email affordance.",
				Reference: "Asks `(sendVerificationEmail || mailer) && (emailVerificationMode !== 'none' " +
					"|| requireEmailVerification)`. An *unset* mode passes the second term, since " +
					"`undefined !== 'none'` is true in JavaScript, so the same deployment is told " +
					"`true` — even though the reference's own fallback makes an unset mode behave " +
					"as `'none'` in every decision that acts on it. Its deprecated " +
					"`requireEmailVerification` boolean is a third route to `true`, reaching it " +
					"even with the mode set to `'none'`; this port has no field of that name.",
				Citations: []string{"ui.router.ts:121", "auth-config.model.ts:286-298"},
				Why: "The family's clients read `features` to decide which affordances to render, " +
					"so a flag that differs is a difference a consumer sees: a node-auth " +
					"deployment that wired a verification sender and never set the mode loses the " +
					"verify-email affordance when it moves here. Reproducing the term costs more " +
					"than it buys. It needs a distinction between an unset `EmailVerificationMode` " +
					"and one set to `none` that nothing else in this port makes — the service " +
					"normalises the empty string to `none` for registration, for login and for the " +
					"2FA path — and `DefaultConfig` erases that distinction anyway, so the flag " +
					"would answer differently for two configurations that behave identically on " +
					"every route, according to which of the two the host happened to build. It " +
					"would also advertise a step the deployment does not perform: with the " +
					"effective mode `none`, `Register` marks the address verified on the spot and " +
					"verification never comes up. Answering for what this deployment does is the " +
					"reading closest to what the flag means.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Set `Config.EmailVerificationMode` to `lazy` or `strict` — which is what " +
						"a deployment that wires a verification sender generally means — and the " +
						"flag answers `true`, as the reference does for the same deployment. There " +
						"is no way to reach `true` with the mode at `none`, because the legacy " +
						"boolean that reaches it there does not exist here.",
				}},
			},
			{
				ID:      "register-route-is-always-mounted",
				Title:   "`POST <prefix>/register` is unconditional, and `ui/config` reports it as such",
				Surface: "`POST <prefix>/register`, and the `features.register` flag of `GET <prefix>/ui/config`",
				Behaviour: "Registration is part of the library rather than a hook the host supplies: " +
					"every adapter mounts `POST <prefix>/register` on `Service.Register` on every " +
					"deployment, and `GET <prefix>/ui/config` answers `features.register: true` to " +
					"match. Resource-server mode is the one thing that unmounts the route, with " +
					"the rest of the credential set — see " +
					"`resource-server-gates-all-credential-routes` — and the flag does not follow " +
					"it there, which is what the reference does too for a resource server that " +
					"supplied the hook.",
				Reference: "Mounts `/register` only when `routerOptions.onRegister` is supplied, the " +
					"host having written the account-creation function itself, and reports " +
					"`!!routerOptions?.onRegister` in `features.register`. A deployment that " +
					"supplies no hook answers `404` on the route and tells the UI to hide the " +
					"sign-up affordance.",
				Citations: []string{"auth.router.ts:712-715", "ui.router.ts:115"},
				Why: "This port ships registration instead of asking for it: `Service.Register` " +
					"applies the password policy, hashes the password, applies the email " +
					"verification mode and writes through `UserStore`. There is no hook that can " +
					"be absent, so there is nothing for the route's presence to be conditional on, " +
					"and the flag — derived from the wiring rather than configured — answers for " +
					"the routes this port actually serves. The difference runs one way only: a " +
					"client is offered sign-up against a deployment whose node-auth counterpart, " +
					"having no `onRegister`, would have hidden it.",
				Notes: []DeviationNote{{
					Label: "Matching the reference exactly",
					Text: "Not available from configuration. A host that wants no public sign-up " +
						"mounts the adapter on its own mux and refuses `POST <prefix>/register` " +
						"there, or runs in resource-server mode; `features.register` still answers " +
						"`true` in the first case, so such a host hides the affordance in its own " +
						"UI rather than reading the flag.",
				}},
			},
			{
				ID:      "docs-routes-are-opt-in",
				Title:   "The documentation routes are off until asked for, and the document describes them",
				Surface: "`HTTPConfig.Docs.Enabled`: `GET <prefix>/openapi.json` and `GET <prefix>/docs`",
				Behaviour: "Registers neither route unless `HTTPConfig.Docs.Enabled` is set, so a " +
					"deployment that configures nothing answers `404` for both. Set, the two " +
					"answer what the reference answers, to a request carrying no credential of " +
					"any kind: the generated document as `application/json`, and the reference's " +
					"Swagger UI page reproduced byte for byte, `swagger-ui-dist@5` from the unpkg " +
					"CDN included. Neither route has an auth gate, as neither has one there; both " +
					"sit behind the CSRF middleware, as every reference route registered after " +
					"the router-level auto-init does, which on a `GET` only writes the " +
					"`csrf-token` cookie to a reader who arrives without one. The served document " +
					"additionally describes those same two paths, which is what `OpenAPIInfo.Docs` " +
					"adds; the reference's generator describes neither, under any option.",
				Reference: "Registers both when `swagger === true || (swagger !== false && " +
					"NODE_ENV !== 'production')`. The option defaults to `'auto'`, which is the " +
					"second arm, so a deployment that configures nothing serves them everywhere " +
					"except where the process environment sets `NODE_ENV` to exactly " +
					"`production`. Its generator emits the auth routes and stops, so neither " +
					"`/openapi.json` nor `/docs` appears in the document it serves.",
				Citations: []string{
					"auth.router.ts:123-131",
					"auth.router.ts:529-538",
					"auth.router.ts:1652-1654",
					"auth.router.ts:1656-1677",
					"openapi.ts:1646-1669",
				},
				Why: "What a library serves must follow from its own configuration, not from a " +
					"process-wide variable it never sees set. `NODE_ENV` is a Node convention " +
					"with no Go counterpart — there is no one variable a Go deployment agrees " +
					"on, and picking one would make these routes appear and disappear on a value " +
					"the caller never passed to this library. Reading the ambient environment is " +
					"the host's call, and `Docs.Enabled` is where its answer goes, which is also " +
					"the reference's own `swagger: true | false` for a host that wants to decide " +
					"rather than infer. Defaulting to off rather than to on is the safe " +
					"direction of that choice: an unserved document is a missing convenience, a " +
					"served one is a description of the surface an attacker would otherwise have " +
					"to guess — and `<prefix>/docs` is more than a description. The page is the " +
					"reference's, so it loads `swagger-ui-dist@5` from the unpkg CDN with no " +
					"subresource integrity, and whatever that CDN serves then runs on the auth " +
					"origin, where the `csrf-token` cookie is readable from JavaScript by design. " +
					"A deployment should keep the UI route off in production, or serve it behind " +
					"a `Content-Security-Policy` that pins the CDN.",
				Notes: []DeviationNote{
					{
						Label: "Restoring the reference's default",
						Text: "One line where the `HTTPConfig` is built — " +
							"`cfg.Docs.Enabled = os.Getenv(\"APP_ENV\") != \"production\"` — with " +
							"whatever variable the deployment actually uses. Nothing else changes: " +
							"the routes, the bodies and the mount are the same either way.",
					},
					{
						Label: "Why the document lists itself",
						Text: "The wire conformance suite compares the generated document to the " +
							"mounted routes in both directions, on every adapter: a documented " +
							"operation that answers `404` fails, and so does a mounted route the " +
							"document omits. A document that hid the endpoint serving it would " +
							"have to be exempted from the second half, and the exemption is what " +
							"lets a spec drift. `OpenAPIInfo.Docs` is set with " +
							"`HTTPConfig.Docs.Enabled` and describes exactly the two paths that " +
							"flag mounts.",
					},
				},
			},
			{
				ID:      "event-handler-panic-does-not-fail-the-publisher",
				Title:   "A panicking event handler is contained instead of failing the request that published",
				Surface: "`auth.EventBus.Publish` and `PublishContext`, and therefore every route that will publish an `identity.*` event",
				Behaviour: "Each handler runs with `recover` around it. A handler that panics is " +
					"logged and stepped over, the remaining handlers for that event still run, " +
					"and `Publish` returns normally — so the route that published answers as " +
					"though nothing had gone wrong.",
				Reference: "`AuthEventBus` extends Node's `EventEmitter` and publishes with two " +
					"`emit` calls, which invoke their listeners inline. A listener that throws " +
					"propagates out of `emit`, out of `publish`, and into whatever published: " +
					"for the router that is the route handler's own `catch`, which passes the " +
					"error to `handleError` and answers `500` for work that already succeeded. " +
					"The listeners after the one that threw are never called, and the wildcard " +
					"channel is never reached if the throw came from the named one.",
				Citations: []string{"auth-event-bus.ts:48", "auth-event-bus.ts:55-64"},
				Why: "The reference's behaviour here is a consequence of extending `EventEmitter` " +
					"rather than a decision it took, and the Go form of it is worse than the " +
					"Node form. A panic that is not recovered unwinds the goroutine " +
					"`net/http` serves the request on; the server recovers it at the top, drops " +
					"the connection and logs, so a bug in a telemetry subscriber becomes a " +
					"failed request with no response body rather than a `500` with one. Nothing " +
					"about the auth operation is undone either way — the account is created, " +
					"the session is minted, the password is changed — so the choice is only " +
					"between reporting a subscriber's bug as a failure of the operation and " +
					"reporting it where it belongs. Containment also keeps one broken " +
					"subscriber from silencing the others, which the reference's ordering makes " +
					"a real hazard: an SSE handler registered after a webhook handler stops " +
					"receiving events entirely the moment the webhook handler throws.",
				Notes: []DeviationNote{
					{
						Label: "Observing it",
						Text: "Subscribe two handlers to one name, panic in the first, and both " +
							"the second handler and the caller of `Publish` proceed; the panic " +
							"appears on the standard logger as " +
							"`auth: recovered panic in event handler for \"<name>\"`. Under the " +
							"reference the second listener is not called and the publishing " +
							"request fails.",
					},
					{
						Label: "For a host that wants the failure",
						Text: "A handler that must not fail silently should report its own errors " +
							"— to its logger, its error tracker, its metrics — rather than " +
							"panicking. There is no knob that restores the reference's " +
							"propagation, because a bus whose delivery semantics depend on " +
							"configuration is a bus no downstream consumer can reason about.",
					},
				},
			},
			{
				ID:      "ui-ssr-config-json-is-html-escaped",
				Title:   "The SSR-injected `__AUTH_CONFIG__` is HTML-escaped JSON, and cannot be broken out of",
				Surface: "`GET <prefix>/ui/<page>`, the `<script>window.__AUTH_CONFIG__ = …</script>` block",
				Behaviour: "Serialises the config object with `encoding/json` at its default " +
					"settings, which escape `<`, `>` and `&` as `\\u003c`, `\\u003e` and " +
					"`\\u0026`. Any `</script>` inside `siteName`, `logoUrl` or `customCss` " +
					"therefore reaches the browser as `\\u003c/script\\u003e`: it stays inside " +
					"the string, the script block ends where the server put its `</script>`, and " +
					"the value `JSON.parse` yields is character for character the one that was " +
					"configured. The bytes on the wire differ from the reference's whenever any " +
					"string in the document contains one of those three characters — a " +
					"`customCss` with a child selector is enough.",
				Reference: "Writes `JSON.stringify(config)` straight into the `<script>` block. " +
					"`JSON.stringify` escapes nothing for HTML, and a `<script>` element is " +
					"terminated by the byte sequence `</script>` wherever it appears, quoted or " +
					"not — so a `siteName` of `x</script><img src=x onerror=…>` closes the " +
					"block and the rest is parsed as markup and runs. The same page HTML-escapes " +
					"that identical `siteName` five characters at a time before putting it in " +
					"`<title>` and `<h1 class=\"site-name\">`, so the omission is in one sink " +
					"rather than a decision about the value.",
				Citations: []string{"ui.router.ts:272", "ui.router.ts:217-226"},
				Why: "Reproducing the reference including its quirks is the standing rule here, " +
					"and this is the register that exists for the cases where it is set aside. " +
					"It is set aside because the cost and the benefit are as lopsided as they " +
					"get. What reproducing it buys is byte-identical output for configurations " +
					"containing `<`, `>` or `&`; what it costs is an HTML injection into every " +
					"page this port serves, reachable by whoever can set the branding. No client " +
					"can observe the difference: `\\u003c` and `<` are the same character to " +
					"`JSON.parse`, so `window.__AUTH_CONFIG__` is the identical object either " +
					"way, and the escaping is visible only to something reading the raw bytes of " +
					"the HTML — which is not what the family's clients do with this block. " +
					"Turning the escaping off would have taken an explicit " +
					"`Encoder.SetEscapeHTML(false)`, so keeping it is also the reading where the " +
					"unsafe behaviour is the one that has to be asked for. The direction of the " +
					"difference matters too: this is the only entry in this register where the " +
					"port is *stricter* than the reference, and a deployment cannot be broken by " +
					"a hole being closed.",
				Notes: []DeviationNote{
					{
						Label: "Matching the reference exactly",
						Text: "Not available from configuration, and deliberately so. A host that " +
							"needs the exact bytes serves its own page: `UIOptions.Assets` takes " +
							"any `fs.FS`, and `(*Auth).UIConfig` returns the same document to " +
							"marshal however it likes.",
					},
					{
						Label: "The two sinks this does not close",
						Text: "`customCss` is written into a second `<style>` element unescaped " +
							"and `logoUrl` into an `<img src=\"…\">` attribute unescaped, both " +
							"exactly as the reference writes them, because there escaping would " +
							"change what renders rather than only how it is encoded. " +
							"`UIOptions.CustomCSS` is read from the static configuration alone " +
							"and is therefore the host's own code; `logoUrl` can also come from " +
							"a `SettingsStore`, whose only writer in this release is the host's " +
							"own code, since the admin panel that would let an operator write " +
							"one arrives in M8. A deployment that lets a lower-privileged actor " +
							"write either value is trusting that actor with the auth origin.",
					},
				},
			},
		},
	}
}
