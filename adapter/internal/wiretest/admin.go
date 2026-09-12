package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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

// adminSeed describes one user to create before mounting. Everything past
// isAdmin exists for the users table, whose projection picks five fields no
// other case in this file looks at (admin.router.ts:764-773).
type adminSeed struct {
	email       string
	isAdmin     bool
	role        string
	phoneNumber string
	require2FA  bool
	totp        bool
	createdAt   time.Time
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
			Role:            seed.role,
			PhoneNumber:     seed.phoneNumber,
			Require2FA:      seed.require2FA,
			IsTOTPEnabled:   seed.totp,
			CreatedAt:       seed.createdAt,
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
	options := []auth.Option{
		auth.WithUserStore(store),
		auth.WithBcryptCost(bcrypt.MinCost),
	}
	if opts.sessions != nil {
		options = append(options, auth.WithSessionStore(opts.sessions))
	}
	env := NewEnv(t, mount, cfg, append(options, opts.options...)...)
	return &adminEnv{Env: env, users: users}
}

type adminEnvOptions struct {
	admin       auth.AdminOptions
	seeds       []adminSeed
	noListUsers bool
	// sessions overrides the default MemorySessionStore, which is the only way
	// to reach a deployment whose sessions cannot be enumerated.
	sessions auth.SessionStore
	// options are the optional feature stores. Their absence is what each read
	// route answers 404 for, so most cases here deliberately pass none.
	options []auth.Option
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
	t.Run("Reads", func(t *testing.T) { testAdminReads(t, mount) })
}

// adminReadPaths is every route U13 mounts, with a concrete parameter where the
// reference's pattern carries one. The ids are the ones newAdminEnv assigns.
var adminReadPaths = []string{
	auth.AdminUsersPath,
	auth.AdminUsersPath + "/a-user",
	auth.AdminUsersPath + "/a-user/metadata",
	auth.AdminUsersPath + "/a-user/linked-accounts",
	auth.AdminUsersPath + "/a-user/roles",
	auth.AdminUsersPath + "/a-user/tenants",
	auth.AdminActionsPath,
	auth.AdminSettingsPath,
	auth.AdminSessionsPath,
	auth.AdminRolesPath,
	auth.AdminTenantsPath,
	auth.AdminTenantsPath + "/acme/users",
	auth.AdminMailTemplatesPath,
	auth.AdminUITemplatesPath,
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
			env := newAdminEnv(t, mount, adminEnvOptions{
				admin: options,
				// Every store the read routes need, so that a route answering
				// anything but 404 here is a mount and not a missing store.
				options: adminAllStores(),
			})
			paths := make(map[string]string, len(adminPaths)+len(adminReadPaths))
			for route, method := range adminPaths {
				paths[route] = method
			}
			for _, route := range adminReadPaths {
				paths[route] = http.MethodGet
			}
			for route, method := range paths {
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

// ── U13: the read surface ────────────────────────────────────────────────────

// testAdminReads is the fourteen GETs of admin.router.ts's read half, and its
// invariant is shape against shape: every body asserted below is the reference
// handler's key set, and nothing here writes.
//
// Most cases mount under AdminPolicyOpen, which authorises without identifying —
// AdminUserFromContext's second result is false throughout. That is deliberate.
// No route in the reference's read half consults req.user, so an env that always
// carried a principal could not tell a route that reads one from a route that
// does not, and the two policies that authorise anonymously are exactly the ones
// a deployment is most likely to run the console under.
func testAdminReads(t *testing.T, mount Mounter) {
	t.Run("Guarded", func(t *testing.T) { testAdminReadsGuarded(t, mount) })
	t.Run("Users", func(t *testing.T) { testAdminUsers(t, mount) })
	t.Run("UserDetail", func(t *testing.T) { testAdminUserDetail(t, mount) })
	t.Run("UserPanel", func(t *testing.T) { testAdminUserPanel(t, mount) })
	t.Run("Actions", func(t *testing.T) { testAdminActions(t, mount) })
	t.Run("Settings", func(t *testing.T) { testAdminSettings(t, mount) })
	t.Run("Sessions", func(t *testing.T) { testAdminSessions(t, mount) })
	t.Run("Roles", func(t *testing.T) { testAdminRoles(t, mount) })
	t.Run("Tenants", func(t *testing.T) { testAdminTenants(t, mount) })
	t.Run("Templates", func(t *testing.T) { testAdminTemplates(t, mount) })
}

// adminOpenOptions is the mount every body case below uses.
func adminOpenOptions() auth.AdminOptions {
	return auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminOpen()}
}

// adminAllStores wires every optional store a read route can consult, so that a
// case about a body is never accidentally a case about a missing store.
func adminAllStores() []auth.Option {
	return []auth.Option{
		auth.WithMetadataProvider(auth.NewMemoryMetadataStore()),
		auth.WithRBACProvider(auth.NewMemoryRolesPermissionsStore()),
		auth.WithTenantProvider(auth.NewMemoryTenantStore()),
		auth.WithSettingsStore(auth.NewMemorySettingsStore()),
		auth.WithTemplateStore(auth.NewMemoryTemplateStore()),
		auth.WithOAuth(auth.OAuthWiring{LinkedAccounts: auth.NewMemoryLinkedAccounts()}),
	}
}

// adminGet issues a GET against a read route and decodes the body.
func adminGet(t *testing.T, env *adminEnv, route string, want int) map[string]any {
	t.Helper()
	rec := env.Do(env.adminRequest(http.MethodGet, route, ""))
	AssertStatus(t, rec, want)
	return Body(t, rec)
}

// adminEntries pulls a list out of a body, failing on the null a nil slice would
// have produced.
func adminEntries(t *testing.T, body map[string]any, key string) []any {
	t.Helper()
	entries, ok := body[key].([]any)
	if !ok {
		t.Fatalf("%s = %v, want an array (a nil slice would be null here)", key, body[key])
	}
	return entries
}

// adminObject pulls one object out of a list.
func adminObject(t *testing.T, entries []any, index int) map[string]any {
	t.Helper()
	if index >= len(entries) {
		t.Fatalf("entry %d is missing from %v", index, entries)
	}
	object, ok := entries[index].(map[string]any)
	if !ok {
		t.Fatalf("entry %d = %v, want an object", index, entries[index])
	}
	return object
}

// adminTotal reads the best-effort total, which JSON decodes as a float.
func adminTotal(t *testing.T, body map[string]any) int {
	t.Helper()
	total, ok := body["total"].(float64)
	if !ok {
		t.Fatalf("total = %v, want a number", body["total"])
	}
	return int(total)
}

// testAdminReadsGuarded is the invariant the rest of M8 inherits: all fourteen
// sit behind AdminGuard.Protect and none of them behind ProtectShell.
func testAdminReadsGuarded(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
		options: adminAllStores(),
	})
	for _, route := range adminReadPaths {
		rec := env.Do(env.adminRequest(http.MethodGet, route, ""))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")

		// And with the header that reads the whole admin API on the reference.
		// There, a guarded GET carrying Accept: text/html with no loginPath
		// configured is marked and passed through to the handler, so
		// `curl -H 'Accept: text/html' …/admin/api/users` is the entire exploit;
		// here the marker reaches the shell and nothing else. See the
		// admin-unauthenticated-get-serves-only-the-login-form deviation.
		rec = env.Do(adminHTML(env.adminRequest(http.MethodGet, route, "")))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	}
}

// testAdminUsers is GET <admin>/api/users: the projection, the paging arithmetic
// and the in-memory filter (admin.router.ts:748-786).
func testAdminUsers(t *testing.T, mount Mounter) {
	created := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	seeds := []adminSeed{
		{
			email: "alpha@wiretest.example", isAdmin: true, role: "owner",
			phoneNumber: "+390000000", require2FA: true, totp: true, createdAt: created,
		},
		{email: "beta@wiretest.example"},
		{email: "gamma@wiretest.example"},
	}

	t.Run("the projection is the reference's eight keys", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), seeds: seeds})
		body := adminGet(t, env, auth.AdminUsersPath, http.StatusOK)
		AssertKeys(t, body, "users", "total")

		rows := adminEntries(t, body, "users")
		if len(rows) != 3 {
			t.Fatalf("users = %d entries, want 3", len(rows))
		}
		// isAdmin is true on this seed and must still not appear: the reference
		// serialises that field nowhere, this route included, and AssertKeys is
		// what catches a projection that grew one.
		first := adminObject(t, rows, 0)
		AssertKeys(t, first, "id", "email", "role", "isEmailVerified", "isTotpEnabled",
			"require2FA", "phoneNumber", "createdAt")
		if first["id"] != "a-user" || first["email"] != "alpha@wiretest.example" {
			t.Errorf("first row = %v, want the first seed — the listing is id ascending", first)
		}
		if first["role"] != "owner" || first["phoneNumber"] != "+390000000" {
			t.Errorf("row = %v, want the seeded role and phone number", first)
		}
		if first["require2FA"] != true || first["isTotpEnabled"] != true {
			t.Errorf("row = %v, want the seeded 2FA flags", first)
		}

		// A store that carries none of the optional columns omits them, as
		// JSON.stringify omits an undefined member rather than writing null.
		AssertKeys(t, adminObject(t, rows, 1), "id", "email", "isEmailVerified",
			"isTotpEnabled", "require2FA")
	})

	t.Run("total is best-effort and off by one on a full last page", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), seeds: seeds})

		// A short page: three users under the default limit of 20, so nothing
		// follows and total is exact.
		if got := adminTotal(t, adminGet(t, env, auth.AdminUsersPath, http.StatusOK)); got != 3 {
			t.Errorf("total = %d for a short page of 3, want 3", got)
		}

		// A page that happens to be exactly full: len(page) == limit adds one,
		// and there is no fourth user. That is the reference's arithmetic
		// (admin.router.ts:782) and reproducing it is the point — the table
		// draws a "next" button that leads nowhere, and would draw none here if
		// this port counted honestly.
		if got := adminTotal(t, adminGet(t, env, auth.AdminUsersPath+"?limit=3", http.StatusOK)); got != 4 {
			t.Errorf("total = %d for a full page of 3 with limit=3, want 4 — the off-by-one is the contract", got)
		}

		// offset rides on the total whether or not the page is full.
		body := adminGet(t, env, auth.AdminUsersPath+"?limit=1&offset=1", http.StatusOK)
		if got := adminTotal(t, body); got != 3 {
			t.Errorf("total = %d for limit=1&offset=1, want 1 + 1 + 1", got)
		}
		if row := adminObject(t, adminEntries(t, body, "users"), 0); row["id"] != "b-user" {
			t.Errorf("offset=1 returned %v, want the second user by id", row["id"])
		}
	})

	t.Run("limit is clamped to 100", func(t *testing.T) {
		many := make([]adminSeed, 0, 101)
		for i := 0; i < 101; i++ {
			many = append(many, adminSeed{email: "bulk" + strconv.Itoa(i) + "@wiretest.example"})
		}
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), seeds: many})

		body := adminGet(t, env, auth.AdminUsersPath+"?limit=500", http.StatusOK)
		if got := len(adminEntries(t, body, "users")); got != 100 {
			t.Errorf("limit=500 returned %d users, want 100 — Math.min(limit, 100)", got)
		}
		// A full page of 100 out of 101, so the +1 happens to be right for once.
		if got := adminTotal(t, body); got != 101 {
			t.Errorf("total = %d, want 100 + 0 + 1", got)
		}
	})

	t.Run("filter is an in-memory substring on email or id", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), seeds: seeds})

		body := adminGet(t, env, auth.AdminUsersPath+"?filter=ALPHA", http.StatusOK)
		rows := adminEntries(t, body, "users")
		if len(rows) != 1 || adminObject(t, rows, 0)["email"] != "alpha@wiretest.example" {
			t.Errorf("filter=ALPHA returned %v, want the one match — the filter is lowercased", rows)
		}
		// Under a filter total is the count before the slice, so it is exact.
		if got := adminTotal(t, body); got != 1 {
			t.Errorf("total = %d under a filter, want the filtered length", got)
		}

		// The id is the second field matched (admin.router.ts:777).
		rows = adminEntries(t, adminGet(t, env, auth.AdminUsersPath+"?filter=c-user", http.StatusOK), "users")
		if len(rows) != 1 || adminObject(t, rows, 0)["id"] != "c-user" {
			t.Errorf("filter=c-user returned %v, want the match on id", rows)
		}

		// The filtered set is then sliced [offset, offset+limit) while total
		// keeps reporting the whole of it.
		body = adminGet(t, env, auth.AdminUsersPath+"?filter=wiretest&limit=1&offset=1", http.StatusOK)
		rows = adminEntries(t, body, "users")
		if len(rows) != 1 || adminObject(t, rows, 0)["id"] != "b-user" {
			t.Errorf("filtered page = %v, want the second match", rows)
		}
		if got := adminTotal(t, body); got != 3 {
			t.Errorf("total = %d on a sliced filter, want the 3 matches", got)
		}
	})

	t.Run("a store that cannot list is 501 with an empty page", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), seeds: seeds, noListUsers: true,
		})
		body := adminGet(t, env, auth.AdminUsersPath, http.StatusNotImplemented)
		// The error carries users and total, which the 2FA-policy walk's own
		// 501 for the same missing capability does not (:754 against :832), and
		// which the guard's 'first-user' arm answers as a 500 (:377).
		AssertKeys(t, body, "error", "users", "total")
		if body["error"] != "IUserStore.listUsers is not implemented" {
			t.Errorf("error = %v, want the reference's message naming the method", body["error"])
		}
		if len(adminEntries(t, body, "users")) != 0 || adminTotal(t, body) != 0 {
			t.Errorf("501 body = %v, want an empty page so the table renders", body)
		}
	})
}

// testAdminUserDetail is GET <admin>/api/users/:id (admin.router.ts:789-800),
// whose projection is five keys where the table's is eight.
func testAdminUserDetail(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: adminOpenOptions(),
		seeds: []adminSeed{{
			email: "detail@wiretest.example", role: "owner",
			phoneNumber: "+390000000", require2FA: true, createdAt: time.Now(),
		}},
	})

	body := adminGet(t, env, auth.AdminUsersPath+"/a-user", http.StatusOK)
	// require2FA, phoneNumber and createdAt are in the listing and not here.
	// That the detail view carries less than the row linking to it is the
	// reference's shape, not an omission.
	AssertKeys(t, body, "id", "email", "role", "isEmailVerified", "isTotpEnabled")
	if body["id"] != "a-user" || body["email"] != "detail@wiretest.example" {
		t.Errorf("body = %v, want the seeded user", body)
	}

	rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminUsersPath+"/nobody", ""))
	AssertError(t, rec, http.StatusNotFound, "User not found", "")
}

// testAdminUserPanel is the four sub-resources of the user detail panel, each of
// which answers 404 naming the store it was not given.
func testAdminUserPanel(t *testing.T, mount Mounter) {
	seeds := []adminSeed{{email: "panel@wiretest.example"}}

	t.Run("each 404s by name without its store", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions(), seeds: seeds})
		for route, message := range map[string]string{
			"/metadata":        "User metadata store not configured",
			"/linked-accounts": "Linked accounts store not configured",
			"/roles":           "RBAC store not configured",
			"/tenants":         "Tenant store not configured",
		} {
			rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminUsersPath+"/a-user"+route, ""))
			AssertError(t, rec, http.StatusNotFound, message, "")
		}
	})

	t.Run("metadata is the object itself, unwrapped", func(t *testing.T) {
		store := auth.NewMemoryMetadataStore()
		if err := store.UpdateMetadata(context.Background(), "a-user",
			map[string]any{"plan": "pro"}); err != nil {
			t.Fatalf("seed metadata: %v", err)
		}
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), seeds: seeds,
			options: []auth.Option{auth.WithMetadataProvider(store)},
		})
		body := adminGet(t, env, auth.AdminUsersPath+"/a-user/metadata", http.StatusOK)
		AssertKeys(t, body, "plan")
		if body["plan"] != "pro" {
			t.Errorf("metadata = %v, want the stored object with no envelope", body)
		}
		// A user the store holds nothing for is {} and never null.
		AssertKeys(t, adminGet(t, env, auth.AdminUsersPath+"/nobody/metadata", http.StatusOK))
	})

	t.Run("linked accounts are the shared projection", func(t *testing.T) {
		store := auth.NewMemoryLinkedAccounts()
		if err := store.Save(context.Background(), auth.OAuthLinkedAccount{
			ID: "link-1", UserID: "a-user", Provider: "acme", ProviderID: "acme-1",
			Email: "panel@wiretest.example", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed link: %v", err)
		}
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), seeds: seeds,
			options: []auth.Option{auth.WithOAuth(auth.OAuthWiring{LinkedAccounts: store})},
		})
		body := adminGet(t, env, auth.AdminUsersPath+"/a-user/linked-accounts", http.StatusOK)
		AssertKeys(t, body, "linkedAccounts")
		entry := adminObject(t, adminEntries(t, body, "linkedAccounts"), 0)
		// The same keys GET <prefix>/linked-accounts answers with: the reference
		// hands back the store's LinkedAccount records on both routes.
		AssertKeys(t, entry, "provider", "providerAccountId", "email", "linkedAt")

		// An unknown user is an empty list, not a 404: the route looks none up.
		empty := adminGet(t, env, auth.AdminUsersPath+"/nobody/linked-accounts", http.StatusOK)
		if len(adminEntries(t, empty, "linkedAccounts")) != 0 {
			t.Errorf("linkedAccounts = %v for an unknown user, want []", empty)
		}
	})

	t.Run("roles and tenants are the ids the panel binds to", func(t *testing.T) {
		rbac := auth.NewMemoryRolesPermissionsStore()
		tenants := auth.NewMemoryTenantStore()
		ctx := context.Background()
		if err := rbac.CreateRole(ctx, "editor", []string{"posts:write"}); err != nil {
			t.Fatalf("seed role: %v", err)
		}
		// The tenant is the empty one, which is what the reference's own
		// getRolesForUser(id) — a call carrying no tenant at all — selects here.
		if err := rbac.AddRoleToUser(ctx, "a-user", "editor", ""); err != nil {
			t.Fatalf("assign role: %v", err)
		}
		if _, err := tenants.CreateTenant(ctx, auth.Tenant{ID: "acme", Name: "Acme", IsActive: true}); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if err := tenants.AssociateUserWithTenant(ctx, "a-user", "acme"); err != nil {
			t.Fatalf("associate: %v", err)
		}
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), seeds: seeds,
			options: []auth.Option{auth.WithRBACProvider(rbac), auth.WithTenantProvider(tenants)},
		})

		body := adminGet(t, env, auth.AdminUsersPath+"/a-user/roles", http.StatusOK)
		AssertKeys(t, body, "roles")
		if roles := adminEntries(t, body, "roles"); len(roles) != 1 || roles[0] != "editor" {
			t.Errorf("roles = %v, want the one assignment", roles)
		}

		// The route asks the store for whole tenants and answers with their ids.
		body = adminGet(t, env, auth.AdminUsersPath+"/a-user/tenants", http.StatusOK)
		AssertKeys(t, body, "tenantIds")
		if ids := adminEntries(t, body, "tenantIds"); len(ids) != 1 || ids[0] != "acme" {
			t.Errorf("tenantIds = %v, want [acme]", ids)
		}

		// Neither is a lookup, so an unknown user is an empty list.
		for route, key := range map[string]string{"/roles": "roles", "/tenants": "tenantIds"} {
			empty := adminGet(t, env, auth.AdminUsersPath+"/nobody"+route, http.StatusOK)
			if len(adminEntries(t, empty, key)) != 0 {
				t.Errorf("%s = %v for an unknown user, want []", key, empty)
			}
		}
	})
}

// testAdminActions is GET <admin>/api/actions (admin.router.ts:946-948), which
// is a registry listing rather than a store read.
func testAdminActions(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: adminOpenOptions(), options: adminAllStores(),
	})
	body := adminGet(t, env, auth.AdminActionsPath, http.StatusOK)
	AssertKeys(t, body, "actions")
	// This port has no ActionRegistry: the settings half of the feature is here
	// (AuthSettings.EnabledWebhookActions, WebhookConfig.AllowedActions) and the
	// sandbox that would execute one is the tools router, which it has not
	// reached. An empty list is what the reference answers when nothing has been
	// decorated, so this is its answer and not a stub of a different shape.
	if entries := adminEntries(t, body, "actions"); len(entries) != 0 {
		t.Errorf("actions = %v, want the empty registry", entries)
	}
	// It is registered whatever the deployment holds — there is no store to
	// 404 for.
	bare := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
	AssertKeys(t, adminGet(t, bare, auth.AdminActionsPath, http.StatusOK), "actions")
}

// testAdminSettings is GET <admin>/api/settings (admin.router.ts:951-959).
func testAdminSettings(t *testing.T, mount Mounter) {
	bare := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
	AssertError(t, bare.Do(bare.adminRequest(http.MethodGet, auth.AdminSettingsPath, "")),
		http.StatusNotFound, "Settings store not configured", "")

	store := auth.NewMemorySettingsStore()
	required := true
	if _, err := store.UpdateSettings(context.Background(), auth.AuthSettings{
		Require2FA:            &required,
		EnabledWebhookActions: []string{},
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   adminOpenOptions(),
		options: []auth.Option{auth.WithSettingsStore(store)},
	})

	// The body is the settings object itself, unwrapped, and a cleared
	// enabledWebhookActions stays on the wire as [] — see AuthSettings.MarshalJSON.
	body := adminGet(t, env, auth.AdminSettingsPath, http.StatusOK)
	AssertKeys(t, body, "require2FA", "enabledWebhookActions")
	if body["require2FA"] != true {
		t.Errorf("require2FA = %v, want the stored true", body["require2FA"])
	}
	if len(adminEntries(t, body, "enabledWebhookActions")) != 0 {
		t.Errorf("enabledWebhookActions = %v, want the cleared list as []", body["enabledWebhookActions"])
	}
}

// testAdminSessionStore implements auth.SessionStore and nothing else — in
// particular not auth.SessionLister. It is the deployment whose sessions cannot
// be enumerated, which is a 501 and not a 404.
type testAdminSessionStore struct{ inner *auth.MemorySessionStore }

func (s testAdminSessionStore) CreateSession(ctx context.Context, session auth.Session) (auth.Session, error) {
	return s.inner.CreateSession(ctx, session)
}

func (s testAdminSessionStore) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (auth.Session, error) {
	return s.inner.GetSessionByRefreshTokenHash(ctx, hash)
}

func (s testAdminSessionStore) UpdateSession(ctx context.Context, session auth.Session) error {
	return s.inner.UpdateSession(ctx, session)
}

// testAdminSessions is GET <admin>/api/sessions (admin.router.ts:1086-1112).
func testAdminSessions(t *testing.T, mount Mounter) {
	t.Run("the projection is PublicSession and total is the same arithmetic", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		env.Seed("session-one@wiretest.example")
		env.Seed("session-two@wiretest.example")

		body := adminGet(t, env, auth.AdminSessionsPath, http.StatusOK)
		AssertKeys(t, body, "sessions", "total")
		entries := adminEntries(t, body, "sessions")
		if len(entries) != 2 {
			t.Fatalf("sessions = %d entries, want the two seeded", len(entries))
		}
		AssertKeys(t, adminObject(t, entries, 0),
			"sessionHandle", "userId", "tenantId", "createdAt", "expiresAt")
		if got := adminTotal(t, body); got != 2 {
			t.Errorf("total = %d for a short page of 2, want 2", got)
		}
		// The same off-by-one as the users table, computed at :1109.
		if got := adminTotal(t, adminGet(t, env, auth.AdminSessionsPath+"?limit=2", http.StatusOK)); got != 3 {
			t.Errorf("total = %d for a full page of 2, want 3", got)
		}
	})

	t.Run("filter matches the user id", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		wanted, _ := env.Seed("session-filter@wiretest.example")
		env.Seed("session-other@wiretest.example")

		// The reference also matches the session's `ipAddress`, defaulted to the
		// empty string; this port's Session carries no such column, so the id is
		// the whole predicate.
		body := adminGet(t, env, auth.AdminSessionsPath+"?filter="+wanted.ID, http.StatusOK)
		entries := adminEntries(t, body, "sessions")
		if len(entries) != 1 || adminObject(t, entries, 0)["userId"] != wanted.ID {
			t.Errorf("filtered sessions = %v, want the one owned by %s", entries, wanted.ID)
		}
		if got := adminTotal(t, body); got != 1 {
			t.Errorf("total = %d under a filter, want the filtered length", got)
		}
	})

	t.Run("a store that cannot enumerate is 501 with an empty page", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:    adminOpenOptions(),
			sessions: testAdminSessionStore{inner: auth.NewMemorySessionStore()},
		})
		body := adminGet(t, env, auth.AdminSessionsPath, http.StatusNotImplemented)
		AssertKeys(t, body, "error", "sessions", "total")
		if body["error"] != "ISessionStore.getAllSessions is not implemented" {
			t.Errorf("error = %v, want the reference's message naming the method", body["error"])
		}
		// There is no 404 arm to reach: NewService requires a session store, so
		// one is always configured and the capability is the only absence.
		if len(adminEntries(t, body, "sessions")) != 0 || adminTotal(t, body) != 0 {
			t.Errorf("501 body = %v, want an empty page", body)
		}
	})
}

// testAdminRoleStore implements auth.RolesPermissionsStore and nothing else — in
// particular not auth.RoleLister. It is the second half of the split this route
// exists to keep: configured, and unable to enumerate.
type testAdminRoleStore struct {
	inner *auth.MemoryRolesPermissionsStore
}

func (s testAdminRoleStore) AddRoleToUser(ctx context.Context, userID, role, tenantID string) error {
	return s.inner.AddRoleToUser(ctx, userID, role, tenantID)
}

func (s testAdminRoleStore) RemoveRoleFromUser(ctx context.Context, userID, role, tenantID string) error {
	return s.inner.RemoveRoleFromUser(ctx, userID, role, tenantID)
}

func (s testAdminRoleStore) GetRolesForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	return s.inner.GetRolesForUser(ctx, userID, tenantID)
}

func (s testAdminRoleStore) CreateRole(ctx context.Context, role string, permissions []string) error {
	return s.inner.CreateRole(ctx, role, permissions)
}

func (s testAdminRoleStore) DeleteRole(ctx context.Context, role string) error {
	return s.inner.DeleteRole(ctx, role)
}

func (s testAdminRoleStore) AddPermissionToRole(ctx context.Context, role, permission string) error {
	return s.inner.AddPermissionToRole(ctx, role, permission)
}

func (s testAdminRoleStore) RemovePermissionFromRole(ctx context.Context, role, permission string) error {
	return s.inner.RemovePermissionFromRole(ctx, role, permission)
}

func (s testAdminRoleStore) GetPermissionsForRole(ctx context.Context, role string) ([]string, error) {
	return s.inner.GetPermissionsForRole(ctx, role)
}

func (s testAdminRoleStore) GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	return s.inner.GetPermissionsForUser(ctx, userID, tenantID)
}

func (s testAdminRoleStore) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	return s.inner.UserHasPermission(ctx, userID, permission, tenantID)
}

// testAdminRoles is GET <admin>/api/roles (admin.router.ts:1129-1146), the route
// that keeps two absences apart: no store at all is a 404, a store that cannot
// enumerate is a 501.
func testAdminRoles(t *testing.T, mount Mounter) {
	t.Run("no store is 404", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		AssertError(t, env.Do(env.adminRequest(http.MethodGet, auth.AdminRolesPath, "")),
			http.StatusNotFound, "RBAC store not configured", "")
	})

	t.Run("a store that cannot enumerate is 501", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(),
			options: []auth.Option{auth.WithRBACProvider(
				testAdminRoleStore{inner: auth.NewMemoryRolesPermissionsStore()})},
		})
		body := adminGet(t, env, auth.AdminRolesPath, http.StatusNotImplemented)
		// roles, and no total: the reference's 501 here carries one key of the
		// page where the users and sessions routes carry two (:1133).
		AssertKeys(t, body, "error", "roles")
		if body["error"] != "IRolesPermissionsStore.getAllRoles is not implemented" {
			t.Errorf("error = %v, want the message naming the optional method", body["error"])
		}
		if len(adminEntries(t, body, "roles")) != 0 {
			t.Errorf("roles = %v, want []", body["roles"])
		}
	})

	t.Run("each role is paired with its permissions", func(t *testing.T) {
		store := auth.NewMemoryRolesPermissionsStore()
		ctx := context.Background()
		if err := store.CreateRole(ctx, "editor", []string{"posts:write", "posts:read"}); err != nil {
			t.Fatalf("seed role: %v", err)
		}
		// A role with no permissions is still a role and is still listed.
		if err := store.CreateRole(ctx, "auditor", nil); err != nil {
			t.Fatalf("seed role: %v", err)
		}
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:   adminOpenOptions(),
			options: []auth.Option{auth.WithRBACProvider(store)},
		})

		body := adminGet(t, env, auth.AdminRolesPath, http.StatusOK)
		AssertKeys(t, body, "roles")
		entries := adminEntries(t, body, "roles")
		if len(entries) != 2 {
			t.Fatalf("roles = %v, want both", entries)
		}
		first := adminObject(t, entries, 0)
		AssertKeys(t, first, "name", "permissions")
		if first["name"] != "auditor" {
			t.Errorf("first role = %v, want the name-ascending order this port imposes", first["name"])
		}
		if len(adminEntries(t, first, "permissions")) != 0 {
			t.Errorf("permissions = %v for a role with none, want []", first["permissions"])
		}
		if got := len(adminEntries(t, adminObject(t, entries, 1), "permissions")); got != 2 {
			t.Errorf("editor has %d permissions, want 2", got)
		}
	})
}

// testAdminTenants is GET <admin>/api/tenants and GET
// <admin>/api/tenants/:id/users (admin.router.ts:1176-1184, :1213-1221).
func testAdminTenants(t *testing.T, mount Mounter) {
	t.Run("no store is 404 on both", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		for _, route := range []string{auth.AdminTenantsPath, auth.AdminTenantsPath + "/acme/users"} {
			AssertError(t, env.Do(env.adminRequest(http.MethodGet, route, "")),
				http.StatusNotFound, "Tenant store not configured", "")
		}
	})

	store := auth.NewMemoryTenantStore()
	ctx := context.Background()
	created := time.Date(2024, 5, 4, 9, 0, 0, 0, time.UTC)
	if _, err := store.CreateTenant(ctx, auth.Tenant{
		ID: "acme", Name: "Acme", IsActive: true,
		Config: map[string]any{"plan": "enterprise"}, CreatedAt: created,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := store.CreateTenant(ctx, auth.Tenant{ID: "globex", Name: "Globex"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := store.AssociateUserWithTenant(ctx, "a-user", "acme"); err != nil {
		t.Fatalf("associate: %v", err)
	}
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   adminOpenOptions(),
		seeds:   []adminSeed{{email: "tenant@wiretest.example"}},
		options: []auth.Option{auth.WithTenantProvider(store)},
	})

	t.Run("the listing is the reference's Tenant shape", func(t *testing.T) {
		body := adminGet(t, env, auth.AdminTenantsPath, http.StatusOK)
		AssertKeys(t, body, "tenants")
		entries := adminEntries(t, body, "tenants")
		if len(entries) != 2 {
			t.Fatalf("tenants = %v, want both", entries)
		}
		AssertKeys(t, adminObject(t, entries, 0), "id", "name", "isActive", "config", "createdAt")
		// config and createdAt are optional there and are omitted when the store
		// carries neither, as JSON.stringify omits an undefined member.
		AssertKeys(t, adminObject(t, entries, 1), "id", "name", "isActive")
	})

	t.Run("membership is the user ids", func(t *testing.T) {
		body := adminGet(t, env, auth.AdminTenantsPath+"/acme/users", http.StatusOK)
		AssertKeys(t, body, "userIds")
		if ids := adminEntries(t, body, "userIds"); len(ids) != 1 || ids[0] != "a-user" {
			t.Errorf("userIds = %v, want [a-user]", ids)
		}
		// A tenant with no members is [] and never null.
		empty := adminGet(t, env, auth.AdminTenantsPath+"/globex/users", http.StatusOK)
		if len(adminEntries(t, empty, "userIds")) != 0 {
			t.Errorf("userIds = %v, want []", empty)
		}
	})
}

// testAdminTemplates is the pair at admin.router.ts:1448 and :1470, which differ
// from the other twelve in that the reference does not register them at all
// without a template store.
func testAdminTemplates(t *testing.T, mount Mounter) {
	t.Run("without a store the routes do not exist", func(t *testing.T) {
		// Not a guarded 404 naming a store, as the other reads answer, but no
		// route at all: the reference wraps both in `if (featTemplates &&
		// options.templateStore)` (:1444), so an anonymous caller reaches
		// Express's own 404 rather than the guard's 401. The policy here is
		// session-based precisely so that the two are distinguishable.
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
		})
		for _, route := range []string{auth.AdminMailTemplatesPath, auth.AdminUITemplatesPath} {
			rec := env.Do(env.adminRequest(http.MethodGet, route, ""))
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d without a template store, want 404: the route is not registered",
					route, rec.Code)
			}
		}
	})

	store := auth.NewMemoryTemplateStore()
	ctx := context.Background()
	html := "<p>{{T.body}}</p>"
	if _, err := store.UpdateMailTemplate(ctx, "password-reset", auth.MailTemplatePatch{
		BaseHTML:     &html,
		Translations: map[string]map[string]string{"en": {"subject": "Reset"}},
	}); err != nil {
		t.Fatalf("seed mail template: %v", err)
	}
	if _, err := store.UpdateUITranslations(ctx, "login",
		map[string]map[string]string{"en": {"title": "Sign in"}}); err != nil {
		t.Fatalf("seed ui translations: %v", err)
	}
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   adminOpenOptions(),
		options: []auth.Option{auth.WithTemplateStore(store)},
	})

	t.Run("mail templates are the store's records", func(t *testing.T) {
		body := adminGet(t, env, auth.AdminMailTemplatesPath, http.StatusOK)
		AssertKeys(t, body, "templates")
		entry := adminObject(t, adminEntries(t, body, "templates"), 0)
		AssertKeys(t, entry, "id", "baseHtml", "baseText", "translations")
		if entry["id"] != "password-reset" {
			t.Errorf("template id = %v, want the seeded one", entry["id"])
		}
	})

	t.Run("ui translations are the store's records", func(t *testing.T) {
		body := adminGet(t, env, auth.AdminUITemplatesPath, http.StatusOK)
		AssertKeys(t, body, "translations")
		entry := adminObject(t, adminEntries(t, body, "translations"), 0)
		AssertKeys(t, entry, "page", "translations")
		if entry["page"] != "login" {
			t.Errorf("page = %v, want the seeded one", entry["page"])
		}
	})
}
