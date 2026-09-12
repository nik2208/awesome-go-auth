package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The admin router's skeleton: the access guard, its own login and logout, and
// the HTML shell that loads the vendored admin SPA.
//
// This is the port of admin.router.ts's front half — buildPolicyGuard
// (:250-395), the login and logout routes (:543-636), the two static asset
// routes (:690-701), the shell (:707-738) and GET /api/ping (:741). Everything
// under /api/* other than ping belongs to later PRs and mounts behind the same
// guard, which is why the guard is the whole substance of this file: every one
// of those routes is as reachable as AdminGuard.Protect lets it be.
//
// # Where it mounts, and why not under the API prefix
//
// The reference's createAdminRouter returns an Express router the host mounts
// itself. Nothing ties that mount to the auth router's: the admin router builds
// its own paths from req.baseUrl, its OpenAPI spec defaults swaggerBasePath to
// '/admin' (admin.router.ts:190, openapi.ts:674), and its apiPrefix option
// exists precisely because the admin router has to be *told* where the auth
// router lives (:152-157). So the two are siblings, not parent and child, and
// AdminOptions.Path is a path on whatever router the adapter was handed —
// "/admin" by default — rather than a suffix of HTTPConfig.APIPrefix.
//
// That is not cosmetic. Mounting the console under the API prefix would put it
// inside the auth router's CSRF and rate-limiter chain, which the reference's
// separate router is outside of, and would make an operator's reverse-proxy
// rule for /auth silently expose the console too.
//
// # What is not wrapped around it
//
// The four adapters mount these six routes bare: no CSRFMiddleware, no
// RateLimitMiddleware, no EventContextMiddleware. All three are the auth
// router's, applied by (*Adapter).guard to the routes registered after the
// reference's router-level auto-init (auth.router.ts:529-538); the admin router
// is a different router and carries none of them. Reproducing that is also what
// keeps the vendored admin.js working — it posts to <admin>/login as JSON with
// credentials: 'include' and no CSRF header (admin.js doLogin), so a
// double-submit check here would refuse every login the shipped SPA makes.
//
// The consequence is stated rather than hidden: POST <admin>/login and POST
// <admin>/logout accept a cross-site form post. SameSite=Lax on the admin
// cookie — the reference's own attribute, and this port's Cookies default — is
// what stands between that and a login-CSRF session fixation; the impact of the
// logout half is a logged-out administrator.

// The admin router's own paths, relative to its mount. These six are the whole
// of U12; the rest of /api/* arrives with the PRs that own those routes.
const (
	// DefaultAdminPath is AdminOptions.Path's default and the reference's
	// swaggerBasePath default (admin.router.ts:190, openapi.ts:674).
	DefaultAdminPath = "/admin"

	AdminLoginPath  = "/login"            // admin.router.ts:543
	AdminLogoutPath = "/logout"           // admin.router.ts:618
	AdminCSSPath    = "/assets/admin.css" // admin.router.ts:690
	AdminJSPath     = "/assets/admin.js"  // admin.router.ts:696
	AdminShellPath  = "/"                 // admin.router.ts:738
	AdminPingPath   = "/api/ping"         // admin.router.ts:741
)

// adminTokenType is the typ claim on the token POST <admin>/login mints, and
// the reason a claim in a token cannot be used to bypass the user store.
//
// The reference signs {sub, email, isRoot} with nothing else and verifies with
// a bare jwt.verify (admin.router.ts:582-586, :300), so *any* token its secret
// signs is an admin credential there: a refresh token, and — the one that
// matters — the typed step-up token a user holds after a password but before a
// second factor. This port types the admin token and checks the type, so the
// guard accepts exactly two: this one, and an ordinary access token, which is
// the integration the reference documents when it says jwtSecret "must match
// AuthConfig.accessTokenSecret" (admin.router.ts:70-78). See the
// admin-guard-accepts-only-typed-session-tokens deviation.
const adminTokenType = "admin"

// adminAccessTokenType is the typ an ordinary access token carries — the
// literal issueToken writes. Spelled here rather than imported from a shared
// constant because there is no shared constant; see issueToken.
const adminAccessTokenType = "access"

// adminSessionTTL is the reference's expiresIn: '24h' on the signed token and
// the matching maxAge on the cookie (admin.router.ts:585, :610). It is
// deliberately not CookieOptions.AccessTokenMaxAge: the two have to agree with
// each other, and the reference pins both to the same literal day.
const adminSessionTTL = 24 * time.Hour

// AdminPolicyKind is the string half of the reference's AdminAccessPolicy union
// (admin.router.ts:38-42).
type AdminPolicyKind string

const (
	// AdminPolicyOpen grants every request, with no token read and no store
	// consulted (admin.router.ts:269). It is the reference's "use only behind a
	// VPN or IP allow-list" (:29) and it is also the only way to ask this port
	// for an unguarded console — see AdminOptions.AccessPolicy.
	AdminPolicyOpen AdminPolicyKind = "open"
	// AdminPolicyFirstUser grants the user whose id matches ListUsers(1, 0)[0]
	// (admin.router.ts:372-374). AdminUserStore's doc comment carries why that
	// ordering is a contract here and a promise the reference's own stores do
	// not keep.
	AdminPolicyFirstUser AdminPolicyKind = "first-user"
	// AdminPolicyIsAdminFlag grants a user whose IsAdmin is set, and reads
	// nothing else — not Role, not RBAC (admin.router.ts:370). See User.IsAdmin.
	AdminPolicyIsAdminFlag AdminPolicyKind = "is-admin-flag"
)

// AdminPolicyFunc is the reference's custom predicate arm: handed the resolved
// user and the configured RBAC store, returning whether to grant
// (admin.router.ts:41, :376).
//
// A non-nil error is a denial and not a 500, because the reference wraps the
// whole policy evaluation in a try/catch whose catch sets granted = false
// (:378-380). A predicate that cannot reach its store therefore refuses the
// request rather than failing it, on both sides.
type AdminPolicyFunc func(ctx context.Context, user User, rbac RolesPermissionsStore) (bool, error)

// AdminAccessPolicy is the reference's AdminAccessPolicy (admin.router.ts:38-42):
// one of three named policies, or a host-supplied predicate.
//
// It is a struct behind a pointer rather than a bare string because the
// reference distinguishes three states and not two — a policy, a legacy secret,
// and *neither* (:516-537) — and `accessPolicy !== undefined` is the test that
// picks the first. A nil *AdminAccessPolicy is "not set".
//
// Kind and Predicate are exclusive: a non-nil Predicate is the function arm and
// Kind is ignored. A zero value — no Kind, no Predicate — is the reference's
// "policy is a string nobody matched": the evaluation falls through every
// branch with granted still false, and the request is refused 403.
type AdminAccessPolicy struct {
	Kind      AdminPolicyKind
	Predicate AdminPolicyFunc
}

// AdminOpen, AdminFirstUser, AdminIsAdminFlag and AdminPredicate build the four
// policies. They exist so that a configuration reads as one call — the shape
// the reference's string union has — rather than as a struct literal whose
// fields a reader has to check against each other.
func AdminOpen() *AdminAccessPolicy { return &AdminAccessPolicy{Kind: AdminPolicyOpen} }

func AdminFirstUser() *AdminAccessPolicy { return &AdminAccessPolicy{Kind: AdminPolicyFirstUser} }

func AdminIsAdminFlag() *AdminAccessPolicy {
	return &AdminAccessPolicy{Kind: AdminPolicyIsAdminFlag}
}

func AdminPredicate(fn AdminPolicyFunc) *AdminAccessPolicy {
	return &AdminAccessPolicy{Predicate: fn}
}

// AdminRootUser is the reference's AdminOptions.rootUser (admin.router.ts:110-115):
// a bootstrap credential that lives in configuration rather than in the user
// store, for "environments without local users".
//
// PasswordHash is a bcrypt hash and never a password. A login against it mints
// a token carrying isRoot, which is the one claim that skips the store lookup
// and the policy alike — so this pair is the most privileged credential the
// console has, and it is as strong as the hash and the JWT secret together.
type AdminRootUser struct {
	Email        string
	PasswordHash string
}

// AdminOptions is HTTPConfig.Admin: whether the adapters mount the admin
// surface, where, and who gets in.
//
// It is the reference's AdminOptions (admin.router.ts:44-186) less the store
// slots. The reference passes each optional store to createAdminRouter and
// turns the SPA's tabs on from what it was handed; this port already holds
// those stores on the Auth, so the feature flags are derived from what is
// actually configured (adminFeatures) and there is nothing to pass twice.
type AdminOptions struct {
	// Enabled mounts the admin surface, the way Docs.Enabled mounts the
	// documentation routes. Unset — the default — nothing under Path is
	// registered at all and every admin route answers 404.
	//
	// Enabled on its own is not sufficient: with neither AccessPolicy nor
	// Secret configured the adapters still mount nothing. That is the
	// admin-console-requires-an-explicit-policy deviation, and the shortest way
	// to the reference's own default is AccessPolicy: AdminOpen().
	Enabled bool
	// Path is where the admin router mounts, on the same router the adapter was
	// given and beside HTTPConfig.APIPrefix rather than under it. Empty means
	// DefaultAdminPath, which is the reference's own default (:190).
	Path string
	// AccessPolicy is the reference's accessPolicy: the session-based guard,
	// and the first arm of the selection at :516-537. Non-nil wins over Secret.
	//
	// Every policy other than AdminPolicyOpen needs JWTSecret to verify
	// anything, exactly as there (:76-79) — with no secret the guard reads no
	// token, every request is unauthenticated, and the surface is a login form
	// and a string of 401s.
	//
	// Nil, with Secret also empty, is where this port parts company with the
	// reference. There the router is built anyway, a warning is written to
	// stderr and every route is served unguarded (:530-536); here nothing is
	// mounted. A deployment that wants the open console asks for it by name
	// with AdminOpen(), which is the reference's own vocabulary for exactly
	// that deployment and which puts the decision in the host's configuration
	// where a reviewer can see it.
	AccessPolicy *AdminAccessPolicy
	// Secret is the reference's deprecated adminSecret (:44-56): a bearer token
	// compared against the Authorization header, and the second arm of the
	// selection. It is also a login credential — POST <admin>/login accepts it
	// as a password for the empty email or the literal "admin" and answers with
	// a token carrying isRoot (:557-562).
	//
	// Under Secret alone the shell is served unguarded and the SPA does the
	// login client-side, holding the secret in sessionStorage (:707-737,
	// admin.js). Prefer AccessPolicy.
	//
	// Deprecated: use AccessPolicy. Kept because the reference keeps it.
	Secret string
	// JWTSecret verifies the tokens the guard reads and signs the one
	// <admin>/login mints — the reference's jwtSecret (:68-79). Empty means
	// Config.Secret, which is what the reference's "must match
	// AuthConfig.accessTokenSecret" asks a host to arrange by hand, and which
	// is the arrangement that makes an ordinary access token a valid admin
	// credential for the policy to judge.
	//
	// Setting it to something else is a real choice and not a hardening: it
	// severs that integration, so the only credential the guard can then accept
	// is one <admin>/login minted, and AccessPolicy still decides who that is.
	JWTSecret string
	// LoginPath redirects an unauthenticated browser instead of showing the
	// built-in login form (:107-113, :311-315). Set, the guard answers 302 to
	// <LoginPath>?redirect=<the admin URL>; unset, a GET that accepts HTML is
	// let through to the shell, which renders the form.
	//
	// The value is emitted as given. A host that points it at another origin is
	// choosing to, and the redirect parameter it carries is this router's own
	// path, never anything read off the request.
	LoginPath string
	// CookiePrefix overrides the prefix on the cookie the guard reads and
	// <admin>/login writes — the reference's cookiePrefix (:96-103).
	//
	// It is a *string because the reference tests `cookiePrefix !== undefined`
	// (:221, :291): an explicitly empty prefix means the bare name
	// "accessToken" and is a different instruction from leaving it unset, which
	// tries "__Host-accessToken", "__Secure-accessToken" and "accessToken" in
	// that order on the way in and derives the name from CookieOptions on the
	// way out.
	CookiePrefix *string
	// RootUser is the bootstrap credential; see AdminRootUser.
	RootUser *AdminRootUser
	// AuthAPIPrefix is the auth router's mount as the SPA should call it — the
	// reference's apiPrefix (:152-157), injected as authApiPrefix. Empty means
	// HTTPConfig.Prefix(), which this port knows and the reference's separate
	// router does not.
	AuthAPIPrefix string
	// UploadBaseURL is the public base the SPA builds uploaded-asset URLs from
	// (:136-150). It is carried into the injected config and nothing in U12
	// reads it; the upload routes are a later PR's, and adminFeatures reports
	// upload as false until one exists.
	UploadBaseURL string
}

// AdminPath is AdminOptions.Path resolved: the configured value normalised the
// way Prefix normalises the API prefix, or DefaultAdminPath when none is set.
func (c HTTPConfig) AdminPath() string {
	path := strings.TrimSpace(c.Admin.Path)
	if path == "" {
		return DefaultAdminPath
	}
	return "/" + strings.Trim(path, "/")
}

// AdminMounted reports whether the adapters register the admin surface: the
// block is enabled *and* an access decision has been configured for it.
//
// The second half is the admin-console-requires-an-explicit-policy deviation.
// It is a method rather than a field so that the four adapters cannot come to
// disagree about the condition, and so that a host can assert on it at startup
// — `if cfg.Admin.Enabled && !cfg.AdminMounted() { log.Fatal(...) }` — which is
// the one thing that turns an unexpected 404 into a message.
func (c HTTPConfig) AdminMounted() bool {
	return c.Admin.Enabled && (c.Admin.AccessPolicy != nil || strings.TrimSpace(c.Admin.Secret) != "")
}

// ── the guard ────────────────────────────────────────────────────────────────

// adminUserContextKey and adminNeedsAuthContextKey carry the guard's two
// outputs to the handler behind it. Unexported key types, so nothing outside
// this package can plant either.
type adminUserContextKey struct{}

type adminNeedsAuthContextKey struct{}

// AdminUserFromContext returns the principal the guard resolved, and whether
// there was one. It is the reference's `(req as any).user` (admin.router.ts:341,
// :390) and it is what every route behind AdminGuard.Protect reads.
//
// The second result is false under AdminPolicyOpen and under the legacy secret,
// where the reference calls next() with no user on the request either: those
// two policies authorise a request without ever identifying anybody.
func AdminUserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(adminUserContextKey{}).(User)
	return user, ok
}

// adminNeedsAuth reports the reference's adminNeedsAuth marker
// (admin.router.ts:322). It is unexported on purpose: the shell is the only
// thing entitled to see it, ProtectShell is the only thing that sets it, and a
// route that could read it could be made to serve an unauthenticated caller.
func adminNeedsAuth(ctx context.Context) bool {
	needs, _ := ctx.Value(adminNeedsAuthContextKey{}).(bool)
	return needs
}

// adminOutcome is what authorise decided.
type adminOutcome int

const (
	// adminGranted: the request may proceed. The user, when there is one, is
	// already in the returned context.
	adminGranted adminOutcome = iota
	// adminNeedsLoginForm is the reference's marker branch (:318-325): an
	// unauthenticated GET that accepts HTML, with no loginPath configured. Only
	// the shell honours it.
	adminNeedsLoginForm
	// adminRefused: a response has already been written.
	adminRefused
)

// AdminGuard is buildPolicyGuard (admin.router.ts:250-395) plus the selection
// above it (:516-537), resolved once at mount time.
//
// One value serves every admin route, and the two wrappers below are the only
// way through it. U13 onwards mount their routes with Protect and read the
// principal with AdminUserFromContext; nothing else about this type is theirs
// to re-derive.
type AdminGuard struct {
	auth *Auth
	cfg  HTTPConfig
	// policy is nil under the legacy secret.
	policy *AdminAccessPolicy
	// secret is the legacy bearer secret, empty under a policy.
	secret string
	// jwtSecret is AdminOptions.JWTSecret resolved against Config.Secret.
	jwtSecret string
	// sessionBased is the reference's variable of the same name (:516, :526):
	// a policy is configured and it is not 'open'. It decides whether the login
	// and logout routes exist at all, and whether the shell is guarded.
	sessionBased bool
}

// AdminGuard resolves the access decision for cfg. It is safe to call once per
// mount and share; the value holds no per-request state.
func (a *Auth) AdminGuard(cfg HTTPConfig) *AdminGuard {
	opts := cfg.Admin
	guard := &AdminGuard{auth: a, cfg: cfg, jwtSecret: strings.TrimSpace(opts.JWTSecret)}
	if guard.jwtSecret == "" {
		guard.jwtSecret = a.service.cfg.Secret
	}
	// Priority: accessPolicy, then adminSecret (admin.router.ts:516-537). The
	// third arm there — neither set, warn on stderr, serve unguarded — has no
	// counterpart here because AdminMounted refuses to mount that configuration
	// at all; see AdminOptions.AccessPolicy.
	switch {
	case opts.AccessPolicy != nil:
		guard.policy = opts.AccessPolicy
		guard.sessionBased = !(opts.AccessPolicy.Predicate == nil && opts.AccessPolicy.Kind == AdminPolicyOpen)
	default:
		guard.secret = strings.TrimSpace(opts.Secret)
	}
	return guard
}

// SessionBased reports whether the console authenticates through a session
// rather than through the legacy bearer secret. It is what makes the shell
// conditional (:707) and what the SPA reads to choose its login form.
func (g *AdminGuard) SessionBased() bool { return g.sessionBased }

// LoginRoutesMounted reports whether POST <admin>/login and POST
// <admin>/logout exist: the reference registers both only under `sessionBased
// && secret` (:541).
func (g *AdminGuard) LoginRoutesMounted() bool {
	return g.sessionBased && g.jwtSecret != ""
}

// Protect is the guard every admin route other than the shell wraps itself in.
//
// It differs from the reference in exactly one branch, and it is the branch the
// reference gets wrong. There, an unauthenticated GET carrying `Accept:
// text/html` is let through to *every* guarded route when no loginPath is
// configured (:318-325) — so `curl -H 'Accept: text/html' /admin/api/users`
// reads the user table with no credential at all, because the handler behind
// the guard never looks at the marker. Here the marker never reaches a handler
// through Protect: it is 401, like every other unauthenticated request. See the
// admin-unauthenticated-get-serves-only-the-login-form deviation.
func (g *AdminGuard) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := g.authorise(w, r)
		switch outcome {
		case adminGranted:
			next.ServeHTTP(w, r.WithContext(ctx))
		case adminNeedsLoginForm:
			writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
		}
	})
}

// ProtectShell is Protect for the one route that is allowed to answer an
// unauthenticated request: the HTML shell, whose whole job in that state is to
// render the built-in login form (:318-325, :709-724).
//
// The marker reaches the handler as adminNeedsAuth, and the handler serves a
// page with showLogin set and every feature flag off. Nothing else is behind
// this wrapper, and nothing else may be.
func (g *AdminGuard) ProtectShell(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, outcome := g.authorise(w, r)
		switch outcome {
		case adminGranted:
			next.ServeHTTP(w, r.WithContext(ctx))
		case adminNeedsLoginForm:
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, adminNeedsAuthContextKey{}, true)))
		}
	})
}

// authorise is buildPolicyGuard's body. It returns the context the handler
// should see and what to do with the request; adminRefused means the response
// has already been written.
func (g *AdminGuard) authorise(w http.ResponseWriter, r *http.Request) (context.Context, adminOutcome) {
	ctx := r.Context()

	// The legacy guard (adminAuth, admin.router.ts:252-266): a bearer token
	// compared against the configured secret, 401 when absent and 403 when
	// wrong. The comparison is constant-time here and `!==` there, which no
	// caller can observe on the wire.
	if g.policy == nil {
		token := BearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
			return ctx, adminRefused
		}
		if !secureEqual(token, g.secret) {
			writeAdminError(w, http.StatusForbidden, "Forbidden")
			return ctx, adminRefused
		}
		return ctx, adminGranted
	}

	// 'open' — no auth required at all (:269). No token is read, no store is
	// touched, and no principal is established.
	if g.policy.Predicate == nil && g.policy.Kind == AdminPolicyOpen {
		return ctx, adminGranted
	}

	// ── 1. Extract and verify the token (:274-296) ───────────────────────────
	//
	// The reference hand-parses the Cookie header when cookie-parser is absent
	// (:285-290). There is nothing to port: net/http parses Cookie on every
	// request, so (*http.Request).Cookie is the same fallback always taken.
	claims, ok := g.readToken(r)

	// ── 2. Unauthenticated → redirect, marker, or 401 (:307-332) ─────────────
	if !ok {
		if !strings.Contains(r.Header.Get("Accept"), "text/html") {
			writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
			return ctx, adminRefused
		}
		if loginPath := strings.TrimSpace(g.cfg.Admin.LoginPath); loginPath != "" {
			// `${loginPath}?redirect=${encodeURIComponent(req.baseUrl + req.path)}`
			// (:312-314). The redirect target is this router's own mount and the
			// router-relative path, both known to the mount rather than read off
			// the request line, so nothing a caller sends reaches the Location
			// header.
			target := loginPath + "?redirect=" +
				url.QueryEscape(g.cfg.AdminPath()+adminRouterPath(r, g.cfg))
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return ctx, adminRefused
		}
		if r.Method == http.MethodGet {
			return ctx, adminNeedsLoginForm
		}
		writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
		return ctx, adminRefused
	}

	// ── 3. Resolve the principal (:335-359) ──────────────────────────────────
	if claims.Sub == "" {
		writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
		return ctx, adminRefused
	}

	// The root/bootstrap override (:341-352): a token whose payload says
	// isRoot short-circuits the store lookup and the policy alike, and the user
	// behind it is synthesised from the token.
	//
	// readToken is what keeps that safe. isRoot is honoured only on a token
	// typed adminTokenType, which only POST <admin>/login mints — so the claim
	// cannot arrive on an access token, and in particular cannot arrive from
	// Config.BuildTokenClaims, which is a host hook that may return any claim
	// name the reserved set does not cover.
	if claims.IsRoot {
		email := claims.Email
		if email == "" {
			email = "root@admin"
		}
		user := User{ID: claims.Sub, Email: email, IsAdmin: true}
		return contextWithAdminUser(ctx, user), adminGranted
	}

	// findById (:355). The tenant comes from the token: an access token carries
	// the tid it was minted with, and the admin token carries the tenant the
	// login route found its user in. The reference has no tenancy on this route
	// at all and looks the user up by id alone.
	user, err := g.auth.service.users.GetUserByID(ctx, claims.Sub, claims.Tid)
	if err != nil {
		writeAdminError(w, http.StatusUnauthorized, "Unauthorized")
		return ctx, adminRefused
	}

	// ── 4. Evaluate the policy (:362-388) ────────────────────────────────────
	granted, capabilityMissing := g.evaluate(ctx, user)
	if capabilityMissing {
		// 500, and not the 501 the three listing routes answer for the same
		// missing capability (:754, :1093, :1133). The status is the
		// reference's (:377) and the message is its string.
		writeAdminError(w, http.StatusInternalServerError,
			"accessPolicy: first-user requires IUserStore.listUsers to be implemented")
		return ctx, adminRefused
	}
	if !granted {
		writeAdminError(w, http.StatusForbidden, "Forbidden")
		return ctx, adminRefused
	}
	return contextWithAdminUser(ctx, user), adminGranted
}

// evaluate is the policy switch (:366-382). The second result is the one
// failure that is not a denial: 'first-user' against a store that cannot list.
//
// Every error other than that one collapses to granted = false, which is the
// reference's try/catch around the whole switch (:378-380).
func (g *AdminGuard) evaluate(ctx context.Context, user User) (granted, capabilityMissing bool) {
	if g.policy.Predicate != nil {
		ok, err := g.policy.Predicate(ctx, user, g.auth.service.rbac)
		return err == nil && ok, false
	}
	switch g.policy.Kind {
	case AdminPolicyIsAdminFlag:
		// `user.isAdmin === true` and nothing else — no role, no RBAC lookup
		// (:370). See User.IsAdmin.
		return user.IsAdmin, false
	case AdminPolicyFirstUser:
		// `listUsers(1, 0)` and compare the first id (:372-374). The tenant is
		// "" — every user, in every tenant — because the reference's call takes
		// no tenant and "the first registered user" is a statement about the
		// whole table. See AdminUserStore on why the order is a contract.
		first, err := g.auth.service.ListUsers(ctx, "", 1, 0)
		if errors.Is(err, ErrFeatureNotSupported) {
			return false, true
		}
		if err != nil {
			return false, false
		}
		return len(first) > 0 && first[0].ID == user.ID, false
	default:
		// A policy nobody matched. The reference's `granted` is still false
		// here and the request is refused 403.
		return false, false
	}
}

func contextWithAdminUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, adminUserContextKey{}, user)
}

// ── the admin token ──────────────────────────────────────────────────────────

// adminClaims is the payload of the token <admin>/login mints, and the subset
// of an access token's payload the guard reads.
//
// The reference signs {sub, email, isRoot} and verifies with a bare jwt.verify
// (:582-586, :300). This port adds typ, iss and tid — the first because an
// untyped token is every token, the second because parseToken already refuses a
// token from another issuer and a guard that did not would be the weakest door
// in the building, and the third because this port's user lookup is
// tenant-scoped.
type adminClaims struct {
	Sub    string `json:"sub"`
	Email  string `json:"email"`
	IsRoot bool   `json:"isRoot"`
	Tid    string `json:"tid,omitempty"`
	Typ    string `json:"typ"`
	Iss    string `json:"iss"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// readToken applies the reference's extraction order — Authorization: Bearer
// first, then a cookie (:276-296) — and verifies what it finds.
//
// The cookie name is `<cookiePrefix>accessToken` when a prefix is configured,
// and otherwise the first present of "__Host-accessToken",
// "__Secure-accessToken", "accessToken", in that order (:291-295). CookieValue
// is that order already: it is the same precedence the auth routes read their
// own cookies with.
func (g *AdminGuard) readToken(r *http.Request) (adminClaims, bool) {
	if g.jwtSecret == "" {
		// `if (jwtSecret)` (:274): with no secret nothing is read at all and
		// every request is unauthenticated.
		return adminClaims{}, false
	}
	raw := BearerToken(r.Header.Get("Authorization"))
	if raw == "" {
		if prefix := g.cfg.Admin.CookiePrefix; prefix != nil {
			if c, err := r.Cookie(*prefix + AccessTokenCookieName); err == nil {
				raw = strings.TrimSpace(c.Value)
			}
		} else {
			raw = CookieValue(r, AccessTokenCookieName)
		}
	}
	if raw == "" {
		return adminClaims{}, false
	}
	return g.verifyToken(raw)
}

// verifyToken is the port's jwt.verify: HS256 over the admin secret, then the
// claims the reference does not check.
//
// The type check is the substance. Accepted: adminTokenType, which only
// adminLogin mints, and adminAccessTokenType, which is the integration the
// reference documents for jwtSecret. Refused: a refresh token, and the typed
// step-up token a user holds after a password and before a second factor —
// which under a bare jwt.verify is a valid admin credential and is how the
// reference's console can be entered without the second factor the deployment
// requires.
//
// isRoot is honoured only on the first of the two. See adminTokenType.
func (g *AdminGuard) verifyToken(raw string) (adminClaims, bool) {
	var claims adminClaims
	header, payload, sig, err := splitToken(raw)
	if err != nil {
		return claims, false
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return claims, false
	}
	if alg, ok := headerAlg(rawHeader); !ok || alg != tokenAlg {
		return claims, false
	}
	if !secureEqual(sign(header+"."+payload, g.jwtSecret), sig) {
		return claims, false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims, false
	}
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return claims, false
	}
	switch claims.Typ {
	case adminTokenType:
	case adminAccessTokenType:
		// An access token is somebody's session, not an admin bootstrap: the
		// policy decides what it is worth, and isRoot on it means nothing.
		claims.IsRoot = false
	default:
		return adminClaims{}, false
	}
	if claims.Iss != g.auth.service.cfg.Issuer {
		return adminClaims{}, false
	}
	now := g.auth.service.now()
	if now.After(time.Unix(claims.Exp, 0).Add(g.auth.service.cfg.ClockSkew)) {
		return adminClaims{}, false
	}
	return claims, true
}

// mintAdminToken signs the token POST <admin>/login sets as a cookie: the
// reference's jwt.sign({sub, email, isRoot}, secret, {expiresIn: '24h'})
// (:582-586), plus the three claims verifyToken checks.
func (g *AdminGuard) mintAdminToken(claims adminClaims) (string, error) {
	now := g.auth.service.now()
	claims.Typ = adminTokenType
	claims.Iss = g.auth.service.cfg.Issuer
	claims.Iat = now.Unix()
	claims.Exp = now.Add(adminSessionTTL).Unix()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	var members map[string]any
	if err := json.Unmarshal(payload, &members); err != nil {
		return "", err
	}
	return buildHS256JWT(members, g.jwtSecret)
}

// ── the admin session cookie ─────────────────────────────────────────────────

// adminCookieName is resolveAdminCookieName (:218-231) with one substitution:
// the reference derives isSecure per request from `req.secure ||
// x-forwarded-proto === 'https'`, and this port reads CookieOptions.Secure.
//
// X-Forwarded-Proto is a request header. Believing it means a caller decides
// whether the cookie carrying a 24-hour admin session is marked Secure and
// which name it is written under, and the failure is bidirectional: a spoofed
// `https` over plaintext writes a Secure, possibly __Host- cookie the browser
// then drops, while a genuine TLS deployment whose proxy does not set the
// header writes a bare, non-Secure `accessToken` holding that same session —
// which is then sent over plain HTTP and can be replaced by anyone on the path.
//
// HTTPConfig.ClientIP settled this class of question a release ago, and in the
// same direction: the trust configuration behind a forwarded header is the
// host's knowledge, so the port takes the unambiguous half and gives the host
// the seam. Here the seam already exists — CookieOptions.Secure is the
// operator's statement about the deployment, it defaults to true, and
// CookieOptions.CookieName is the identical prefix rule applied to the auth
// cookies. Reading it means the admin cookie and the session cookies cannot
// disagree about the deployment, which is also what makes the guard's read
// order find what the login route wrote.
//
// An explicit AdminOptions.CookiePrefix still overrides everything, as there
// (:219-223).
func (c HTTPConfig) adminCookieName() string {
	if prefix := c.Admin.CookiePrefix; prefix != nil {
		return *prefix + AccessTokenCookieName
	}
	return c.Cookies.CookieName(AccessTokenCookieName)
}

// adminCookie builds the Set-Cookie the login and logout routes write. It is
// the reference's cookie options (:603-611) with applyHostCookieRequirements
// (:243-252) applied.
//
// That last function is load-bearing in exactly one configuration and is
// therefore ported rather than assumed away: CookieOptions.CookieName only ever
// produces "__Host-" when Secure is set, the path is root and no domain is
// configured, but an explicit CookiePrefix of "__Host-" can produce it from any
// configuration at all — and a __Host- cookie that is not Secure, not
// root-scoped or carries a Domain is one the browser silently refuses.
func (c HTTPConfig) adminCookie(value string, maxAge time.Duration) *http.Cookie {
	name := c.adminCookieName()
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     c.Cookies.basePath(),
		Domain:   c.Cookies.Domain,
		HttpOnly: true,
		Secure:   c.Cookies.Secure,
		SameSite: c.Cookies.SameSite,
	}
	if cookie.SameSite == 0 {
		// The reference's literal `sameSite: 'lax'` (:606), which is also
		// DefaultCookieOptions.
		cookie.SameSite = http.SameSiteLaxMode
	}
	if strings.HasPrefix(name, hostCookiePrefix) {
		cookie.Secure = true
		cookie.Path = "/"
		cookie.Domain = ""
	}
	switch {
	case maxAge > 0:
		cookie.MaxAge = int(maxAge / time.Second)
	case maxAge < 0:
		cookie.MaxAge = -1
	}
	return cookie
}

// ── the routes ───────────────────────────────────────────────────────────────

// AdminHandler serves the whole admin router: the six routes of U12, dispatched
// on the path below the mount.
//
// It is one handler rather than six mounts for the reason (*Auth).UIHandler is:
// the reference mounts one router, the later PRs fill it with paths carrying
// parameters, and a catch-all beside fixed siblings is not a shape every Go
// router will register — gin's tree refuses it outright. The four adapters
// therefore mount this at <AdminPath> and <AdminPath>/, and U13 onwards add
// their routes to the switch below rather than to four mount functions.
//
// Anything the switch does not recognise is a 404, which is what an Express
// router with no matching layer ends at.
func (a *Auth) AdminHandler(cfg HTTPConfig) http.Handler {
	guard := a.AdminGuard(cfg)

	shell := guard.shellHandler()
	ping := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET /api/ping — the SPA's health and auth check (:741-743). The body
		// is `{ok, features}`, the same feature object the shell injects.
		WriteJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"features": a.adminFeatures(cfg).ping(),
		})
	}))

	// U13's read surface, behind one Protect. The route is classified twice —
	// once unguarded in the switch below, so that a path the reference never
	// registered answers 404 rather than 401, and once here — because the
	// classification is a pure function of the path and re-running it is cheaper
	// than a context value that a handler could then be made to trust.
	reads := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, param := matchAdminRead(adminRelativePath(r.URL.EscapedPath(), cfg.AdminPath()))
		a.serveAdminRead(w, r, route, param)
	}))

	// U14's write surface, behind the same Protect and classified the same way.
	// The method is part of the match rather than a check beside it, because
	// Express routes on both: DELETE /api/users/:id and GET /api/users/:id are
	// two layers over one path.
	writes := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params := matchAdminWrite(r.Method, adminRelativePath(r.URL.EscapedPath(), cfg.AdminPath()))
		a.serveAdminWrite(w, r, route, params)
	}))

	// U14b's credential surface — the API-key and webhook routes — behind the
	// same Protect and classified the same way. They are a third family rather
	// than more cases in the two above because they are one class of risk:
	// everything they hold, mint or mask is a secret. See admin_credentials.go.
	credentials := guard.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, param := matchAdminCredential(r.Method, adminRelativePath(r.URL.EscapedPath(), cfg.AdminPath()))
		a.serveAdminCredential(w, r, route, param)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := adminRouterPath(r, cfg)
		// The read and write routes match on the escaped path, so a parameter is
		// split before it is decoded — see matchAdminRead.
		escaped := adminRelativePath(r.URL.EscapedPath(), cfg.AdminPath())
		read, _ := matchAdminRead(escaped)
		write, _ := matchAdminWrite(r.Method, escaped)
		credential, _ := matchAdminCredential(r.Method, escaped)
		switch {
		case rel == AdminLoginPath && r.Method == http.MethodPost:
			if !guard.LoginRoutesMounted() {
				http.NotFound(w, r)
				return
			}
			guard.adminLogin(w, r)
		case rel == AdminLogoutPath && r.Method == http.MethodPost:
			if !guard.LoginRoutesMounted() {
				http.NotFound(w, r)
				return
			}
			guard.adminLogout(w, r)
		case rel == AdminCSSPath && isAdminRead(r):
			serveAdminAsset(w, "admin.css", "text/css; charset=utf-8")
		case rel == AdminJSPath && isAdminRead(r):
			serveAdminAsset(w, "admin.js", "application/javascript; charset=utf-8")
		case rel == AdminShellPath && isAdminRead(r):
			shell.ServeHTTP(w, r)
		case rel == AdminPingPath && isAdminRead(r):
			ping.ServeHTTP(w, r)
		// The fourteen read routes of admin_read.go. They are one case rather
		// than fourteen because six of them carry a path parameter, which a
		// `rel ==` case cannot express; the route table is matchAdminRead.
		case isAdminRead(r) && a.adminReadRegistered(read):
			reads.ServeHTTP(w, r)
		// The sixteen write routes of admin_write.go. matchAdminWrite has
		// already refused every method the reference registers no layer for, so
		// this case needs no isAdminRead counterpart.
		case a.adminWriteRegistered(write):
			writes.ServeHTTP(w, r)
		// The eight credential routes of admin_credentials.go. All eight are
		// registered unconditionally there, so matching one is the whole test —
		// each answers its own 404 for the store it was not given.
		case credential != adminCredentialNone:
			credentials.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// isAdminRead is Express's fallback from HEAD to a GET layer, which every
// router.get in the reference's admin router inherits.
func isAdminRead(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

// adminRouterPath is the path below the admin mount, the way uiRouterPath is
// the path below the UI mount. It is also what the unauthenticated redirect
// appends to the mount to rebuild `req.baseUrl + req.path`.
func adminRouterPath(r *http.Request, cfg HTTPConfig) string {
	return adminRelativePath(r.URL.Path, cfg.AdminPath())
}

// adminRelativePath is adminRouterPath's body over an explicit path, so that the
// parameterised routes can run it over r.URL.EscapedPath() instead — Express
// matches its patterns against the raw pathname and decodes each captured
// parameter afterwards, and a path already decoded would split a parameter
// carrying %2F into two segments. See matchAdminRead.
func adminRelativePath(p, mount string) string {
	switch {
	case p == mount:
		return "/"
	case strings.HasPrefix(p, mount+"/"):
		return p[len(mount):]
	default:
		return p
	}
}

// serveAdminAsset serves admin.css and admin.js: the two static routes, public
// and unguarded, exactly as the reference registers them (:688-701).
//
// They are public there because the login screen the shell renders needs them
// before any session exists. The bytes are the reference's own, vendored under
// ui/upstream/assets and pinned by sha256 (ui_upstream.go) — the reference
// searches six candidate directories on disk for the same two files and
// answers 404 when it finds neither (:673-687), which is the branch below that
// cannot be taken here because the files are compiled in.
//
// Cache-Control is the reference's `public, max-age=3600` (:693, :699).
func serveAdminAsset(w http.ResponseWriter, name, contentType string) {
	data, err := ReadUpstreamUIAsset(name)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// shellHandler is the conditional htmlRoute (:707-738): guarded under a
// session-based policy, unguarded under the legacy secret, where the SPA does
// the login client-side and there is no server-side session to check.
//
// Reproducing the condition rather than picking one arm is the point. Under the
// legacy secret the page has to be served to an anonymous browser or the secret
// can never be entered; under a policy it must not be, or the guard is a
// suggestion.
func (g *AdminGuard) shellHandler() http.Handler {
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		needsAuth := adminNeedsAuth(r.Context())
		// no-store and its three companions are the reference's (:712-715). A
		// shell that a shared cache could hand to the next visitor is a shell
		// that leaks whichever state it was rendered in.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(g.auth.adminShellHTML(g.cfg, g.sessionBased, needsAuth))
	})
	if g.sessionBased {
		return g.ProtectShell(page)
	}
	return page
}

// adminLogin is POST <admin>/login (:543-616): three credential sources, in
// order, and a 24-hour session cookie for whichever answers.
//
// What it does not have is worth stating, because all three are the
// reference's and all three are visible to a reviewer here:
//
//   - No rate limiting of its own. HTTPConfig.RateLimiter is the auth router's
//     slot and is not applied to this router; the family's private development
//     line carries a second slot on its admin router and spreads it onto one
//     route, which is not this one (node-auth admin.router.ts:211, :614,
//     :1030). A deployment that wants this route limited wraps the handler the
//     adapter mounts.
//   - No password policy. Config.MinPasswordLen governs registration and the
//     reset and change routes; nothing here consults it, because nothing here
//     sets a password.
//   - A timing signal. bcrypt runs only when an email matched — the configured
//     root user, or a row in the store — so a wrong email is refused measurably
//     faster than a wrong password, on both sides. It is the same shape
//     Service.loginPassword has, so closing it here alone would be a
//     difference between two login routes of the same library rather than a
//     fix.
func (g *AdminGuard) adminLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// A body that will not decode leaves both fields empty and falls into the
	// "Password required" branch below, which is where express.json's own
	// failure on this route also ends up for a client that sent no usable body.
	_ = json.NewDecoder(r.Body).Decode(&body)

	if body.Password == "" {
		writeAdminError(w, http.StatusBadRequest, "Password required")
		return
	}

	ctx := r.Context()
	var authed *adminClaims

	// 1. The configured root user (:552-556). Compared by exact email, and the
	// token it yields carries isRoot — the claim that skips the store and the
	// policy.
	if root := g.cfg.Admin.RootUser; root != nil && body.Email == root.Email {
		if verifyPassword(body.Password, root.PasswordHash) {
			authed = &adminClaims{Sub: "root", Email: root.Email, IsRoot: true}
		}
	}

	// 2. The legacy secret as a bootstrap override (:558-563), accepted only
	// for an empty email or the literal "admin", and yielding isRoot as well.
	// Note which secret this is: AdminOptions.Secret is a *bearer* credential
	// under the legacy guard and a *password* here, in a configuration that
	// also sets an access policy — so setting both leaves the policy in place
	// for everyone except whoever holds the secret.
	if authed == nil && g.cfg.Admin.Secret != "" && (body.Email == "" || body.Email == "admin") {
		if secureEqual(body.Password, g.cfg.Admin.Secret) {
			authed = &adminClaims{Sub: "admin", Email: "admin@bootstrap", IsRoot: true}
		}
	}

	// 3. The ordinary user store (:566-573). No tenant, as there: the reference
	// calls findByEmail(email) with nothing else, so this route resolves users
	// in the empty tenant only. A multi-tenant deployment authenticates through
	// the auth router's own /login, whose access token carries its tid and
	// which this guard accepts.
	//
	// The policy is not consulted here and is not meant to be: this route
	// establishes *who* the caller is, and the guard decides on every
	// subsequent request whether that person may use the console. A user the
	// policy will refuse can therefore log in successfully and be answered 403
	// by the very next request, which is the reference's arrangement too.
	if authed == nil && body.Email != "" {
		user, err := g.auth.service.users.GetUserByEmail(ctx, body.Email, "")
		if err == nil && user.PasswordHash != "" && verifyPassword(body.Password, user.PasswordHash) {
			authed = &adminClaims{Sub: user.ID, Email: user.Email, Tid: user.TenantID}
		}
	}

	if authed == nil {
		writeAdminError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := g.mintAdminToken(*authed)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Invalid credentials")
		return
	}

	// The cookie is written under the same name the auth routes write the
	// access token under, which is the reference's deliberate arrangement —
	// resolveAdminCookieName exists so that "the guard reads exactly the cookie
	// that was written by the admin login handler" even when a regular session
	// is also active (:277-281). The consequence is that logging into the
	// console replaces the browser's auth session cookie with a token the auth
	// middleware will not accept, until the next /refresh mints a new one. That
	// is the reference's behaviour as well: the token it writes there carries
	// no sid either.
	http.SetCookie(w, g.cfg.adminCookie(token, adminSessionTTL))
	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// adminLogout is POST <admin>/logout (:618-636): clear the cookie the login
// route wrote, under the same name and the same attributes, and answer
// {"success": true}.
//
// It authenticates nothing, as there. The route is reachable without a session
// — clearing a cookie that is not there is a no-op — and it is outside the CSRF
// chain, so a cross-site post logs an administrator out. Both are the
// reference's.
func (g *AdminGuard) adminLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, g.cfg.adminCookie("", -1))
	WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// writeAdminError writes the admin router's error envelope, which is
// `{error: string}` and not the auth router's HTTPError shape.
func writeAdminError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// ── the shell ────────────────────────────────────────────────────────────────

// adminFeatureSet is the flag object buildAdminHtml injects and GET /api/ping
// answers with (:399-419, :742). Each flag is a section of the SPA, and each is
// on only when this deployment can actually serve it.
type adminFeatureSet struct {
	Sessions       bool
	Roles          bool
	Tenants        bool
	Metadata       bool
	TwoFAPolicy    bool
	Control        bool
	LinkedAccounts bool
	APIKeys        bool
	Webhooks       bool
	Templates      bool
	Upload         bool
}

// adminFeatures derives the flags from what is configured, which is the
// reference's `!!options.sessionStore` and its nine siblings (:645-656) read
// against the stores this port already holds on the Auth.
//
// twoFAPolicy is the one flag that is not `!!store`: it is the conjunction of
// two optional capabilities, because its route needs both — a lister to walk the
// table and a writer to set the flag on each row. The reference asks the same
// question of the same store (:649-650), and this port asks it of the two
// interfaces that stand for those methods.
//
// apiKeys and webhooks are `!!options.apiKeyStore` and `!!options.webhookStore`
// (:653-654) — the store being configured and nothing about what it can do. That
// is deliberately not the same question the routes behind the tab ask: a store
// that cannot enumerate turns the tab on and answers 501 to the listing it
// draws, which is the reference's arrangement and the reason the 501 carries an
// empty page. WithAPIKeyStore and WithWebhookStore are what set them.
//
// One is still false and will stay false until the PR that owns the section
// lands, and it is false rather than absent so the SPA hides the tab instead of
// drawing one whose every request 404s: upload needs a writable asset directory,
// and UIOptions.Uploads is an fs.FS, which is a read seam, where the reference's
// uploadDir is a path it writes to.
func (a *Auth) adminFeatures(cfg HTTPConfig) adminFeatureSet {
	svc := a.service
	_, sessions := svc.sessions.(SessionLister)
	_, userLister := svc.users.(AdminUserStore)
	_, twoFAWriter := svc.users.(UserTwoFactorPolicyStore)
	return adminFeatureSet{
		Sessions:       sessions,
		Roles:          svc.rbac != nil,
		Tenants:        svc.tenants != nil,
		Metadata:       svc.metadata != nil,
		TwoFAPolicy:    userLister && twoFAWriter,
		Control:        svc.cfg.Settings != nil,
		LinkedAccounts: a.oauth != nil && a.oauth.LinkedAccounts != nil,
		APIKeys:        a.apiKeys != nil,
		Webhooks:       a.webhooks != nil,
		Templates:      svc.cfg.Templates != nil,
		Upload:         false,
	}
}

// ping is the features object GET /api/ping answers with (:742).
func (f adminFeatureSet) ping() map[string]bool {
	return map[string]bool{
		"sessions": f.Sessions, "roles": f.Roles, "tenants": f.Tenants,
		"metadata": f.Metadata, "twoFAPolicy": f.TwoFAPolicy, "control": f.Control,
		"linkedAccounts": f.LinkedAccounts, "apiKeys": f.APIKeys,
		"webhooks": f.Webhooks, "templates": f.Templates, "upload": f.Upload,
	}
}

// adminShellHTML is buildAdminHtml (:406-496): the thin page that injects
// window.__ADMIN_CONFIG__ and loads the vendored admin.css and admin.js.
//
// needsAuth is the guard's marker, and it decides two things here rather than
// one. The reference's `showLogin` (:448) makes it render the login form; this
// port also empties the feature flags on that render, so the page an
// unauthenticated caller receives carries the login form, the mount path, and
// nothing about the deployment. The flags are the same object GET /api/ping
// answers with — a route that requires a session — and the SPA reloads the page
// after a successful login (admin.js doLogin), so it has them by the time it
// draws a tab. See the admin-unauthenticated-get-serves-only-the-login-form
// deviation.
func (a *Auth) adminShellHTML(cfg HTTPConfig, sessionBased, needsAuth bool) []byte {
	base := cfg.AdminPath()
	features := a.adminFeatures(cfg)
	if needsAuth {
		features = adminFeatureSet{}
	}

	authAPIPrefix := strings.TrimSpace(cfg.Admin.AuthAPIPrefix)
	if authAPIPrefix == "" {
		authAPIPrefix = cfg.Prefix()
	}
	uploadBaseURL := cfg.Admin.UploadBaseURL
	if needsAuth {
		uploadBaseURL = ""
	}

	injected := map[string]any{
		"base":               base,
		"featSessions":       features.Sessions,
		"featRoles":          features.Roles,
		"featTenants":        features.Tenants,
		"featMetadata":       features.Metadata,
		"feat2faPolicy":      features.TwoFAPolicy,
		"featControl":        features.Control,
		"featLinkedAccounts": features.LinkedAccounts,
		"featApiKeys":        features.APIKeys,
		"featWebhooks":       features.Webhooks,
		"featTemplates":      features.Templates,
		"featUpload":         features.Upload,
		"uploadBaseUrl":      uploadBaseURL,
		"sessionBased":       sessionBased,
		"authApiPrefix":      authAPIPrefix,
	}
	if prefix := cfg.Admin.CookiePrefix; prefix != nil {
		injected["cookiePrefix"] = *prefix
	}

	// encoding/json at its default settings, which escape <, > and & — the same
	// treatment and the same reasoning as the UI's SSR injection; see the
	// ui-ssr-config-json-is-html-escaped deviation. Every string in this object
	// comes from configuration, and one of them ending the script element would
	// hand the auth origin to whoever set it.
	cfgJSON, err := json.Marshal(injected)
	if err != nil {
		cfgJSON = []byte("{}")
	}

	// showLogin = features.showLogin || !features.sessionBased (:448). Under
	// the legacy secret the SPA always needs its form; under a policy only the
	// marker branch does.
	showLogin := needsAuth || !sessionBased

	loginScreen := ""
	if showLogin {
		emailInput := ""
		passwordPlaceholder := "Admin secret"
		autofocus := " autofocus"
		if sessionBased {
			emailInput = `<input type="email" id="email-input" placeholder="Email" autofocus>`
			passwordPlaceholder = "Password"
			autofocus = ""
		}
		loginScreen = `
<!-- Login screen -->
<div id="login">
  <div class="login-card">
    <h1>&#128272; awesome-node-auth</h1>
    <p>Administration panel</p>
    <div id="login-error" class="alert alert-error" style="display:none"></div>
    <div style="display:flex;flex-direction:column;gap:.75rem">
      ` + emailInput + `
      <input type="password" id="secret-input" placeholder="` + passwordPlaceholder + `"` + autofocus + `>
      <button class="btn btn-primary" onclick="doLogin()">Sign in</button>
    </div>
  </div>
</div>
`
	}

	return []byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>awesome-node-auth Admin</title>
  <link rel="stylesheet" href="` + base + `/assets/admin.css">
</head>
<body>
` + loginScreen + `
<!-- Main app -->
<div id="app">
  <div id="flash"></div>
  <header>
    <h1>&#128272; awesome-node-auth Admin</h1>
    <span id="header-meta"></span>
  </header>
  <nav id="nav">
    <button class="btn logout-btn" style="margin-left:auto;margin-top:.4rem;margin-bottom:.4rem;font-size:.75rem;padding:.25rem .75rem;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:6px" onclick="doLogout()">Logout</button>
  </nav>
  <main id="main"></main>
</div>

<script>window.__ADMIN_CONFIG__ = ` + string(cfgJSON) + `;</script>
<script src="` + base + `/assets/admin.js"></script>
</body>
</html>`)
}
