package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"golang.org/x/crypto/bcrypt"
)

// The admin console: the six routes of admin.router.ts's skeleton, and — the
// reason this file is as long as it is — the guard in front of five of them.
//
// M8 is split by class of risk rather than by route count, and U12 is the PR
// that decides who gets in. Everything U13 through U16 mount sits behind
// auth.AdminGuard.Protect, so a hole here is a hole in the whole console. The
// cases below are therefore written as a guard suite that happens to have six
// routes attached, not as a route suite that happens to have a guard.
//
// It is a conditional set in the sense the file at the bottom of ui.go is: the
// surface exists only under HTTPConfig.Admin, and both directions are checked —
// mounted when configured, 404 on every path when not. It is deliberately not
// registered in suite.go's conditionalRoutes, and that is not an oversight.
// That registry holds each set to GenerateOpenAPISpec in both directions, and
// GenerateOpenAPISpec describes the auth router: its paths are relative to
// HTTPConfig.Prefix(), while the admin console mounts beside that prefix rather
// than under it, and the document that describes it in the reference is
// buildAdminOpenApiSpec — a second generator this port has not reached. A set
// registered there would have to claim the auth document describes /admin/*,
// which is exactly the sort of untrue thing that registry exists to catch.

// The credentials the cases configure. None is a default, so an assertion
// cannot pass against a handler that ignored the configuration.
const (
	testAdminSecret       = "wiretest-admin-secret"
	testAdminPassword     = "wiretest-password"
	testAdminRootEmail    = "root@wiretest.example"
	testAdminRootPassword = "wiretest-root-password"
	testAdminLoginPath    = "/app/sign-in"
)

// testAdminUserStore is a user store that implements auth.UserStore and nothing
// else — in particular not auth.AdminUserStore. It is what the 'first-user'
// policy meets in a deployment whose store cannot enumerate, which the
// reference answers with a 500 carrying a specific message (admin.router.ts:377)
// rather than with the 501 its three listing routes answer for the same missing
// capability.
type testAdminUserStore struct{ inner *auth.MemoryUserStore }

func (s testAdminUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s testAdminUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s testAdminUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

// adminEnv is an Env whose user store was seeded before the mount, with users
// in the empty tenant — the only tenant POST <admin>/login resolves, because
// the reference's findByEmail(email) carries no tenant at all.
type adminEnv struct {
	*Env
	// users is the seeded set by email. Nothing in U12 reads it — every case
	// here identifies a user by the email it logs in with — but the ids it
	// carries are what a later PR asserting on /api/users will need, and they
	// are only knowable here.
	users map[string]auth.User
}

// adminSeed describes one user to create before mounting.
type adminSeed struct {
	email   string
	isAdmin bool
}

// newAdminEnv mounts an adapter with an admin block and a pre-seeded store.
//
// The store is created here rather than taken from newEnv's defaults because
// the seeds have to exist before the first request: 'first-user' compares
// against ListUsers(1, 0), so which user was created first is the whole test.
func newAdminEnv(t *testing.T, mount Mounter, opts adminEnvOptions) *adminEnv {
	t.Helper()

	memory := auth.NewMemoryUserStore()
	hash, err := bcrypt.GenerateFromPassword([]byte(testAdminPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	users := make(map[string]auth.User, len(opts.seeds))
	for i, seed := range opts.seeds {
		// Ids ascending in creation order, because AdminUserStore's contract
		// orders by id and 'first-user' reads the first of that order.
		created, err := memory.CreateUser(context.Background(), auth.User{
			ID:              string(rune('a'+i)) + "-user",
			Email:           seed.email,
			PasswordHash:    string(hash),
			IsAdmin:         seed.isAdmin,
			IsEmailVerified: true,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", seed.email, err)
		}
		users[seed.email] = created
	}

	var store auth.UserStore = memory
	if opts.noListUsers {
		store = testAdminUserStore{inner: memory}
	}

	cfg := auth.DefaultHTTPConfig()
	cfg.Admin = opts.admin
	env := NewEnv(t, mount, cfg,
		auth.WithUserStore(store),
		auth.WithBcryptCost(bcrypt.MinCost),
	)
	return &adminEnv{Env: env, users: users}
}

type adminEnvOptions struct {
	admin       auth.AdminOptions
	seeds       []adminSeed
	noListUsers bool
}

// adminRequest builds a request against a path below the admin mount — which is
// not below the API prefix, so Env.Request cannot build it.
func (e *adminEnv) adminRequest(method, route string, body string) *http.Request {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	path := e.Config.AdminPath()
	if route != "/" {
		path += route
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// adminHTML marks a request as a browser navigation, which is the whole input
// to the three-way unauthenticated branch (admin.router.ts:308).
func adminHTML(req *http.Request) *http.Request {
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	return req
}

// adminPaths is every route U12 mounts, used by the not-configured direction.
var adminPaths = map[string]string{
	auth.AdminShellPath:  http.MethodGet,
	auth.AdminPingPath:   http.MethodGet,
	auth.AdminCSSPath:    http.MethodGet,
	auth.AdminJSPath:     http.MethodGet,
	auth.AdminLoginPath:  http.MethodPost,
	auth.AdminLogoutPath: http.MethodPost,
}

func testAdmin(t *testing.T, mount Mounter) {
	t.Run("NotMounted", func(t *testing.T) { testAdminNotMounted(t, mount) })
	t.Run("Open", func(t *testing.T) { testAdminOpen(t, mount) })
	t.Run("Unauthenticated", func(t *testing.T) { testAdminUnauthenticated(t, mount) })
	t.Run("Login", func(t *testing.T) { testAdminLogin(t, mount) })
	t.Run("Policies", func(t *testing.T) { testAdminPolicies(t, mount) })
	t.Run("RootClaim", func(t *testing.T) { testAdminRootClaim(t, mount) })
	t.Run("LegacySecret", func(t *testing.T) { testAdminLegacySecret(t, mount) })
	t.Run("TokenTypes", func(t *testing.T) { testAdminTokenTypes(t, mount) })
	t.Run("Assets", func(t *testing.T) { testAdminAssets(t, mount) })
}

// testAdminNotMounted is the negative direction of the conditional set, and it
// covers the configuration this port refuses: Enabled with no access decision.
//
// The reference builds the router anyway there, writes a warning to stderr and
// serves every route unguarded (admin.router.ts:530-536). Here nothing is
// registered, so the console cannot be reached at all — see the
// admin-console-requires-an-explicit-policy deviation.
func testAdminNotMounted(t *testing.T, mount Mounter) {
	cases := map[string]auth.AdminOptions{
		"unconfigured":                     {},
		"enabled with no policy or secret": {Enabled: true},
		"policy without the flag":          {AccessPolicy: auth.AdminIsAdminFlag()},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			env := newAdminEnv(t, mount, adminEnvOptions{admin: options})
			for route, method := range adminPaths {
				rec := env.Do(adminHTML(env.adminRequest(method, route, "{}")))
				switch rec.Code {
				case http.StatusNotFound, http.StatusMethodNotAllowed:
				default:
					t.Errorf("%s %s = %d, want 404 or 405 — the admin surface must not be mounted by %s",
						method, route, rec.Code, name)
				}
			}
		})
	}
}

// testAdminOpen pins AdminPolicyOpen: every route reachable with no credential
// at all, no login route, and the shell rendering the legacy secret form
// because sessionBased is false (admin.router.ts:265, :519, :451).
func testAdminOpen(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminOpen()},
	})

	rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminPingPath, ""))
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "ok", "features")

	rec = env.Do(env.adminRequest(http.MethodGet, auth.AdminShellPath, ""))
	AssertStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `id="login"`) {
		t.Error("the shell under 'open' must render the login screen: sessionBased is false there")
	}

	// The login and logout routes are registered only under `sessionBased &&
	// secret` (admin.router.ts:541), and 'open' is not session-based.
	for _, route := range []string{auth.AdminLoginPath, auth.AdminLogoutPath} {
		rec := env.Do(env.adminRequest(http.MethodPost, route, `{"password":"x"}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d under 'open', want 404: the route is not registered", route, rec.Code)
		}
	}
}

// testAdminUnauthenticated is the branch with the most behaviour in it
// (admin.router.ts:307-332), and the one place this port deliberately answers
// differently.
func testAdminUnauthenticated(t *testing.T, mount Mounter) {
	options := auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}

	t.Run("json is 401", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options})
		for _, route := range []string{auth.AdminShellPath, auth.AdminPingPath} {
			rec := env.Do(env.adminRequest(http.MethodGet, route, ""))
			AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
		}
	})

	t.Run("html GET reaches the shell and nothing else", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options})

		// The shell renders the login form. This is the one route the marker
		// may reach, and the only reason the branch exists.
		rec := env.Do(adminHTML(env.adminRequest(http.MethodGet, auth.AdminShellPath, "")))
		AssertStatus(t, rec, http.StatusOK)
		page := rec.Body.String()
		if !strings.Contains(page, `id="login"`) || !strings.Contains(page, `id="email-input"`) {
			t.Error("the unauthenticated shell must render the session-based login form")
		}
		if rec.Header().Get("Cache-Control") != "no-store, no-cache, must-revalidate, max-age=0" {
			t.Errorf("Cache-Control = %q, want the reference's no-store set", rec.Header().Get("Cache-Control"))
		}
		// Nothing about the deployment. Every feature flag is false, which is
		// what keeps the feature matrix — the body of GET /api/ping, a route
		// that requires a session — behind the session it requires.
		if strings.Contains(page, `"featSessions":true`) || strings.Contains(page, `:true,"feat`) {
			t.Errorf("the unauthenticated shell disclosed a feature flag: %s", page)
		}

		// Every other guarded route is 401, where the reference would let an
		// Accept: text/html GET through to the handler.
		rec = env.Do(adminHTML(env.adminRequest(http.MethodGet, auth.AdminPingPath, "")))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	})

	t.Run("html non-GET is 401", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options})
		rec := env.Do(adminHTML(env.adminRequest(http.MethodPost, auth.AdminPingPath, "{}")))
		switch rec.Code {
		case http.StatusUnauthorized, http.StatusNotFound, http.StatusMethodNotAllowed:
		default:
			t.Errorf("POST %s = %d, want 401 (or unrouted): the marker is GET-only",
				auth.AdminPingPath, rec.Code)
		}
	})

	t.Run("loginPath redirects", func(t *testing.T) {
		redirecting := options
		redirecting.LoginPath = testAdminLoginPath
		env := newAdminEnv(t, mount, adminEnvOptions{admin: redirecting})

		rec := env.Do(adminHTML(env.adminRequest(http.MethodGet, auth.AdminShellPath, "")))
		AssertStatus(t, rec, http.StatusFound)
		want := testAdminLoginPath + "?redirect=" + "%2Fadmin%2F"
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
		// With a loginPath the marker branch is unreachable, so even the shell
		// is a redirect rather than a page.
		if strings.Contains(rec.Body.String(), `id="login"`) {
			t.Error("a configured loginPath must redirect rather than render the built-in form")
		}
	})
}

// testAdminLogin covers POST <admin>/login and <admin>/logout: the three
// credential sources, the two refusals, and the cookie.
func testAdminLogin(t *testing.T, mount Mounter) {
	options := auth.AdminOptions{
		Enabled:      true,
		AccessPolicy: auth.AdminIsAdminFlag(),
		RootUser: &auth.AdminRootUser{
			Email:        testAdminRootEmail,
			PasswordHash: adminRootHash(t),
		},
		Secret: testAdminSecret,
	}
	seeds := []adminSeed{{email: "admin@wiretest.example", isAdmin: true}}

	t.Run("missing password is 400", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
		rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath, `{"email":"admin@wiretest.example"}`))
		AssertError(t, rec, http.StatusBadRequest, "Password required", "")
		AssertNoCookies(t, rec)
	})

	t.Run("bad credentials are 401", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
		rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath,
			`{"email":"admin@wiretest.example","password":"wrong"}`))
		AssertError(t, rec, http.StatusUnauthorized, "Invalid credentials", "")
		AssertNoCookies(t, rec)
	})

	t.Run("the user store grants a session", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
		rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath,
			`{"email":"admin@wiretest.example","password":"`+testAdminPassword+`"}`))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		// The cookie is the auth access-token cookie's name under the same
		// naming rule, because the guard has to read back exactly what this
		// wrote (admin.router.ts:277-281).
		cookie := Cookie(t, rec, hostAccess)
		if !cookie.HttpOnly || !cookie.Secure {
			t.Errorf("admin cookie = %s, want HttpOnly and Secure", cookie.String())
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("admin cookie SameSite = %v, want Lax (admin.router.ts:605)", cookie.SameSite)
		}
		if cookie.Path != "/" {
			t.Errorf("admin cookie Path = %q, want / (__Host- requires it)", cookie.Path)
		}
		if cookie.MaxAge != 24*60*60 {
			t.Errorf("admin cookie Max-Age = %d, want 86400 to match expiresIn '24h'", cookie.MaxAge)
		}

		// And it opens the console.
		ping := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
		ping.AddCookie(&http.Cookie{Name: hostAccess, Value: cookie.Value})
		AssertStatus(t, env.Do(ping), http.StatusOK)

		// Logout clears it under the same name.
		out := env.Do(env.adminRequest(http.MethodPost, auth.AdminLogoutPath, ""))
		AssertStatus(t, out, http.StatusOK)
		cleared := Cookie(t, out, hostAccess)
		if cleared.Value != "" || cleared.MaxAge >= 0 {
			t.Errorf("logout cookie = %s, want an immediate expiry", cleared.String())
		}
	})

	t.Run("the root user and the legacy secret both yield isRoot", func(t *testing.T) {
		for name, body := range map[string]string{
			"rootUser":    `{"email":"` + testAdminRootEmail + `","password":"` + testAdminRootPassword + `"}`,
			"secret":      `{"password":"` + testAdminSecret + `"}`,
			"secretAdmin": `{"email":"admin","password":"` + testAdminSecret + `"}`,
		} {
			t.Run(name, func(t *testing.T) {
				env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
				rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath, body))
				AssertStatus(t, rec, http.StatusOK)

				// isRoot short-circuits the store lookup and the policy: the
				// principal it synthesises is in no user store at all, and
				// 'is-admin-flag' is never consulted (admin.router.ts:341-352).
				ping := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
				ping.AddCookie(&http.Cookie{Name: hostAccess, Value: Cookie(t, rec, hostAccess).Value})
				AssertStatus(t, env.Do(ping), http.StatusOK)
			})
		}
	})

	t.Run("X-Forwarded-Proto does not decide the cookie", func(t *testing.T) {
		// The reference derives the Secure flag and therefore the cookie's name
		// from `req.secure || x-forwarded-proto === 'https'`
		// (admin.router.ts:594). This port reads CookieOptions.Secure, so a
		// header a caller controls changes nothing. Both directions are pinned.
		for _, proto := range []string{"https", "http"} {
			env := newAdminEnv(t, mount, adminEnvOptions{admin: options, seeds: seeds})
			req := env.adminRequest(http.MethodPost, auth.AdminLoginPath,
				`{"email":"admin@wiretest.example","password":"`+testAdminPassword+`"}`)
			req.Header.Set("X-Forwarded-Proto", proto)
			rec := env.Do(req)
			AssertStatus(t, rec, http.StatusOK)
			cookie := Cookie(t, rec, hostAccess)
			if !cookie.Secure {
				t.Errorf("X-Forwarded-Proto: %s produced %s, want Secure from the configuration",
					proto, cookie.String())
			}
		}
	})
}

// testAdminPolicies pins what each of the four policies grants.
func testAdminPolicies(t *testing.T, mount Mounter) {
	seeds := []adminSeed{
		{email: "first@wiretest.example"},
		{email: "second@wiretest.example", isAdmin: true},
	}

	t.Run("is-admin-flag", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
			seeds: seeds,
		})
		// The flag and nothing else: the second user holds it, the first does
		// not, and neither has a role (admin.router.ts:370).
		assertAdminAccess(t, env, "second@wiretest.example", http.StatusOK)
		assertAdminAccess(t, env, "first@wiretest.example", http.StatusForbidden)
	})

	t.Run("first-user", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminFirstUser()},
			seeds: seeds,
		})
		// ListUsers(1, 0)[0] by id ascending, which is creation order here.
		// Note that the second user's IsAdmin buys nothing under this policy.
		assertAdminAccess(t, env, "first@wiretest.example", http.StatusOK)
		assertAdminAccess(t, env, "second@wiretest.example", http.StatusForbidden)
	})

	t.Run("first-user without the capability is 500", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:       auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminFirstUser()},
			seeds:       seeds,
			noListUsers: true,
		})
		// 500 and this message, not the 501 the three listing routes answer for
		// the same missing capability (admin.router.ts:377 against :754).
		rec := adminPingAs(t, env, "first@wiretest.example")
		AssertError(t, rec, http.StatusInternalServerError,
			"accessPolicy: first-user requires IUserStore.listUsers to be implemented", "")
	})

	t.Run("predicate", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminPredicate(
				func(_ context.Context, user auth.User, _ auth.RolesPermissionsStore) (bool, error) {
					return user.Email == "first@wiretest.example", nil
				})},
			seeds: seeds,
		})
		assertAdminAccess(t, env, "first@wiretest.example", http.StatusOK)
		assertAdminAccess(t, env, "second@wiretest.example", http.StatusForbidden)
	})

	t.Run("a predicate error denies rather than fails", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminPredicate(
				func(context.Context, auth.User, auth.RolesPermissionsStore) (bool, error) {
					return true, context.DeadlineExceeded
				})},
			seeds: seeds,
		})
		// The reference wraps the whole evaluation in a try/catch whose catch
		// sets granted = false (admin.router.ts:378-380).
		assertAdminAccess(t, env, "first@wiretest.example", http.StatusForbidden)
	})
}

// testAdminRootClaim pins the sharpest privilege in the file: a claim in a
// token that skips the user store entirely.
func testAdminRootClaim(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: auth.AdminOptions{
			Enabled:      true,
			AccessPolicy: auth.AdminFirstUser(),
			RootUser:     &auth.AdminRootUser{Email: testAdminRootEmail, PasswordHash: adminRootHash(t)},
		},
		seeds: []adminSeed{{email: "first@wiretest.example"}},
	})

	rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath,
		`{"email":"`+testAdminRootEmail+`","password":"`+testAdminRootPassword+`"}`))
	AssertStatus(t, rec, http.StatusOK)

	ping := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	ping.AddCookie(&http.Cookie{Name: hostAccess, Value: Cookie(t, rec, hostAccess).Value})
	// 'first-user' would refuse this subject — "root" is in no store — and is
	// never asked. That is the reference's short-circuit (admin.router.ts:341).
	AssertStatus(t, env.Do(ping), http.StatusOK)
}

// testAdminLegacySecret pins the deprecated bearer guard and the unguarded
// shell that goes with it (admin.router.ts:252-266, :726-737).
func testAdminLegacySecret(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: auth.AdminOptions{Enabled: true, Secret: testAdminSecret},
	})

	rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminPingPath, ""))
	AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")

	wrong := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	wrong.Header.Set("Authorization", "Bearer not-the-secret")
	AssertError(t, env.Do(wrong), http.StatusForbidden, "Forbidden", "")

	right := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	right.Header.Set("Authorization", "Bearer "+testAdminSecret)
	AssertStatus(t, env.Do(right), http.StatusOK)

	// The shell is unguarded here: the SPA holds the secret and does the login
	// client-side, so a page it could never fetch would be a console nobody can
	// enter (admin.router.ts:707, :726-737).
	shell := env.Do(env.adminRequest(http.MethodGet, auth.AdminShellPath, ""))
	AssertStatus(t, shell, http.StatusOK)
	if !strings.Contains(shell.Body.String(), "Admin secret") {
		t.Error("the legacy shell must render the admin-secret form")
	}
	if strings.Contains(shell.Body.String(), `"sessionBased":true`) {
		t.Error("sessionBased must be false under the legacy secret")
	}
}

// testAdminTokenTypes pins the one thing the reference's bare jwt.verify does
// not check, and the reason this port checks it.
func testAdminTokenTypes(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
	})

	// An ordinary user of the auth router, seeded through the service so that
	// the token pair below is real rather than hand-built. Env.Seed creates no
	// admin, which is what makes the access-token case a 403 and not a 200.
	_, tokens := env.Seed("typed@wiretest.example")

	// The refresh token is signed by the same secret and is not a session for
	// this purpose. Under a bare jwt.verify it would be accepted and the policy
	// would run; here it is not a credential at all.
	refresh := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	refresh.Header.Set("Authorization", "Bearer "+tokens.RefreshToken)
	AssertError(t, env.Do(refresh), http.StatusUnauthorized, "Unauthorized", "")

	// The access token is the integration the reference documents for
	// jwtSecret, and it reaches the policy — which refuses this user, because
	// Env.Seed creates no admin.
	access := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	access.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	AssertError(t, env.Do(access), http.StatusForbidden, "Forbidden", "")

	// Garbage is 401, not 500.
	bad := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	bad.Header.Set("Authorization", "Bearer not.a.token")
	AssertError(t, env.Do(bad), http.StatusUnauthorized, "Unauthorized", "")
}

// testAdminAssets pins the two static routes: public, unguarded, and the
// vendored bytes (admin.router.ts:688-701).
func testAdminAssets(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
	})

	for route, contentType := range map[string]string{
		auth.AdminCSSPath: "text/css; charset=utf-8",
		auth.AdminJSPath:  "application/javascript; charset=utf-8",
	} {
		// No credential, and the guard that answers 401 next door does not
		// apply: the login screen needs both files before a session exists.
		rec := env.Do(env.adminRequest(http.MethodGet, route, ""))
		AssertStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Content-Type"); got != contentType {
			t.Errorf("%s Content-Type = %q, want %q", route, got, contentType)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
			t.Errorf("%s Cache-Control = %q, want the reference's public, max-age=3600", route, got)
		}
		name := strings.TrimPrefix(route, "/assets/")
		want, err := auth.ReadUpstreamUIAsset(name)
		if err != nil {
			t.Fatalf("read vendored %s: %v", name, err)
		}
		if rec.Body.String() != string(want) {
			t.Errorf("%s is not the vendored asset byte for byte", route)
		}
	}
}

// assertAdminAccess logs email in through the admin login route and asserts
// what the guard then makes of the session.
func assertAdminAccess(t *testing.T, env *adminEnv, email string, want int) {
	t.Helper()
	AssertStatus(t, adminPingAs(t, env, email), want)
}

// adminPingAs logs in and replays the session against GET /api/ping.
func adminPingAs(t *testing.T, env *adminEnv, email string) *httptest.ResponseRecorder {
	t.Helper()
	rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath,
		`{"email":"`+email+`","password":"`+testAdminPassword+`"}`))
	AssertStatus(t, rec, http.StatusOK)
	ping := env.adminRequest(http.MethodGet, auth.AdminPingPath, "")
	ping.AddCookie(&http.Cookie{Name: hostAccess, Value: Cookie(t, rec, hostAccess).Value})
	return env.Do(ping)
}

func adminRootHash(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testAdminRootPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash root password: %v", err)
	}
	return string(hash)
}
