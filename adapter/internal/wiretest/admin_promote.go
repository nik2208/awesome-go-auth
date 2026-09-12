package wiretest

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The console's fifty-first route and the assertion that closes the set.
//
// Two things live here. The first is POST <admin>/users/{id}/promote, U16's
// route: the only one on this surface that carries a rate limiter, the only one
// not under /api, and the only one the *published* reference does not register
// at all. The second is testAdminRouteSet, which is the point of the milestone
// rather than of this route — the five families before it each asserted that
// their own routes work, and nothing yet asserted that they are all of them.

// testAdminFlagStore is a user store that can write User.IsAdmin and records
// what it was asked to write.
//
// The flag is invisible on the wire: the reference serialises isAdmin nowhere,
// not on /me and not in the admin users table (see auth.User.IsAdmin), so a
// case that only read HTTP back could not tell a promotion from a no-op. This
// is how "the route wrote the flag" becomes a fact rather than an inference.
type testAdminFlagStore struct {
	testAdminUserStore

	mu       sync.Mutex
	promoted map[string]bool
}

func (s *testAdminFlagStore) UpdateIsAdmin(ctx context.Context, userID, tenantID string, isAdmin bool) error {
	if err := s.inner.UpdateIsAdmin(ctx, userID, tenantID, isAdmin); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.promoted == nil {
		s.promoted = map[string]bool{}
	}
	s.promoted[userID] = isAdmin
	return nil
}

func (s *testAdminFlagStore) wrote(userID string) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.promoted[userID]
	return value, ok
}

func testAdminPromote(t *testing.T, mount Mounter) {
	t.Run("Guarded", func(t *testing.T) { testAdminPromoteGuarded(t, mount) })
	t.Run("Role", func(t *testing.T) { testAdminPromoteRole(t, mount) })
	t.Run("Flag", func(t *testing.T) { testAdminPromoteFlag(t, mount) })
	t.Run("Method", func(t *testing.T) { testAdminPromoteMethod(t, mount) })
	t.Run("NotUnderApi", func(t *testing.T) { testAdminPromoteIsNotUnderApi(t, mount) })
	t.Run("RateLimiter", func(t *testing.T) { testAdminPromoteRateLimiter(t, mount) })
	t.Run("Events", func(t *testing.T) { testAdminPromotePublishes(t, mount) })
}

// testAdminPromoteGuarded is the invariant every family here carries, and the
// one it would be worst to get wrong: this is the route that grants the admin
// console. AdminGuard.Protect, never ProtectShell — a promotion reached through
// the reference's Accept: text/html marker branch would let an anonymous
// browser make itself an administrator.
func testAdminPromoteGuarded(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
		options: adminAllStores(),
	})
	for _, route := range adminPromoteRoutes {
		rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")

		rec = env.Do(adminHTML(env.adminRequest(route.method, route.path, "{}")))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	}
}

// testAdminPromoteRole is the default branch: an absent `method` is 'role'
// (node-auth admin.router.ts:1032), which creates the `admin` role and assigns
// it.
func testAdminPromoteRole(t *testing.T, mount Mounter) {
	t.Run("assigns the admin role", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:   adminOpenOptions(),
			seeds:   []adminSeed{{email: "promote@wiretest.example"}},
			options: adminAllStores(),
		})

		// No body at all, which is the branch a caller that sends none takes.
		got := adminSend(t, env, http.MethodPost, adminPromotePath("a-user"), "", http.StatusOK)
		AssertKeys(t, got, "success", "method")
		if got["success"] != true || got["method"] != "role" {
			t.Fatalf("promote = %v, want {\"success\": true, \"method\": \"role\"}", got)
		}

		// The assignment is untenanted — addRoleToUser(userId, 'admin') carries
		// no tenant (node-auth admin.router.ts:1054) — which is the one GET
		// /api/users/:id/roles reads back.
		roles := adminGet(t, env, auth.AdminUsersPath+"/a-user/roles", http.StatusOK)
		entries := adminEntries(t, roles, "roles")
		if len(entries) != 1 || entries[0] != "admin" {
			t.Fatalf("roles = %v, want [admin]", entries)
		}

		// And the role itself now exists, because createRole ran first
		// (:1053). That ordering is not decorative: a store whose assignment
		// has a foreign key to the role table refuses an assignment naming a
		// role it does not hold, which is exactly what
		// auth.MemoryRolesPermissionsStore does.
		defined := adminEntries(t, adminGet(t, env, auth.AdminRolesPath, http.StatusOK), "roles")
		if len(defined) != 1 || adminObject(t, defined, 0)["name"] != "admin" {
			t.Errorf("roles = %v, want the created admin role", defined)
		}
	})

	t.Run("explicit method=role is the same branch", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})
		got := adminSend(t, env, http.MethodPost, adminPromotePath("a-user"), `{"method":"role"}`, http.StatusOK)
		if got["method"] != "role" {
			t.Errorf("method = %v, want role", got["method"])
		}
	})

	t.Run("no RBAC store is the 404 every RBAC route answers", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{admin: adminOpenOptions()})
		rec := env.Do(env.adminRequest(http.MethodPost, adminPromotePath("a-user"), "{}"))
		AssertError(t, rec, http.StatusNotFound, "RBAC store not configured", "")
	})
}

// testAdminPromoteFlag is the other branch: method=flag writes User.IsAdmin
// through the seam, and answers the reference's 501 — naming the reference's
// own method — when the store has none (node-auth admin.router.ts:1035-1040).
func testAdminPromoteFlag(t *testing.T, mount Mounter) {
	t.Run("writes the flag", func(t *testing.T) {
		var store *testAdminFlagStore
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(),
			seeds: []adminSeed{{email: "flag@wiretest.example"}},
			wrapUsers: func(memory *auth.MemoryUserStore) auth.UserStore {
				store = &testAdminFlagStore{testAdminUserStore: testAdminUserStore{inner: memory}}
				return store
			},
			options: adminAllStores(),
		})

		got := adminSend(t, env, http.MethodPost, adminPromotePath("a-user"), `{"method":"flag"}`, http.StatusOK)
		AssertKeys(t, got, "success", "method")
		if got["success"] != true || got["method"] != "flag" {
			t.Fatalf("promote = %v, want {\"success\": true, \"method\": \"flag\"}", got)
		}
		if value, ok := store.wrote("a-user"); !ok || !value {
			t.Errorf("the store was asked to write %v (called: %v), want true", value, ok)
		}

		// The two branches are two different products and neither implies the
		// other: the flag was written and no role was assigned. A deployment
		// guarding the console with an RBAC predicate gets nothing from this
		// call, which is why the route's doc comment says so.
		roles := adminGet(t, env, auth.AdminUsersPath+"/a-user/roles", http.StatusOK)
		if entries := adminEntries(t, roles, "roles"); len(entries) != 0 {
			t.Errorf("roles = %v, want none: method=flag assigns no role", entries)
		}
	})

	t.Run("a store with no writer is the reference's 501", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(),
			seeds: []adminSeed{{email: "noflag@wiretest.example"}},
			// A store that satisfies auth.UserStore and nothing else, which is
			// what the reference's `typeof store.update !== 'function'` meets.
			wrapUsers: func(memory *auth.MemoryUserStore) auth.UserStore {
				return testAdminUserStore{inner: memory}
			},
			options: adminAllStores(),
		})
		rec := env.Do(env.adminRequest(http.MethodPost, adminPromotePath("a-user"), `{"method":"flag"}`))
		AssertError(t, rec, http.StatusNotImplemented,
			"IUserStore.update is required for method=flag", "")
	})
}

// testAdminPromoteMethod pins the two quirks of the `method` field, both of
// which a reader would otherwise assume away.
func testAdminPromoteMethod(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: adminOpenOptions(), options: adminAllStores(),
	})

	// Only the literal 'flag' takes the flag branch: the source's test is
	// `method === 'flag'` and its cast to the union is erased at run time
	// (node-auth admin.router.ts:1034). Everything else falls through to the
	// role branch — and the answer echoes what the caller sent rather than the
	// branch that ran (:1045, :1059).
	for _, sent := range []string{"bogus", "Flag", "", "ROLE"} {
		got := adminSend(t, env, http.MethodPost, adminPromotePath("echo-"+sent),
			`{"method":"`+sent+`"}`, http.StatusOK)
		if got["method"] != sent {
			t.Errorf("method %q was echoed as %v, want the value as sent", sent, got["method"])
		}
		roles := adminGet(t, env, auth.AdminUsersPath+"/echo-"+sent+"/roles", http.StatusOK)
		if entries := adminEntries(t, roles, "roles"); len(entries) != 1 || entries[0] != "admin" {
			t.Errorf("method %q assigned %v, want the role branch to have run", sent, entries)
		}
	}

	// null is nullish, so `?? 'role'` catches it where "" does not.
	got := adminSend(t, env, http.MethodPost, adminPromotePath("null-method"), `{"method":null}`, http.StatusOK)
	if got["method"] != "role" {
		t.Errorf("method = %v for an explicit null, want the default role", got["method"])
	}
}

// testAdminPromoteIsNotUnderApi pins the absence a reader will trip over.
//
// Fifty of the fifty-one routes on this surface are under /api and this one is
// not (node-auth admin.router.ts:1030). The spelling everybody will try first —
// POST <admin>/api/users/{id}/promote — is registered nowhere on either line,
// and this is what says so out loud, so that the quirk is pinned rather than
// incidental.
func testAdminPromoteIsNotUnderApi(t *testing.T, mount Mounter) {
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin: adminOpenOptions(), options: adminAllStores(),
	})

	rec := env.Do(env.adminRequest(http.MethodPost, auth.AdminUsersPath+"/a-user/promote", "{}"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST %s/a-user/promote = %d, want 404: the route is mounted without the /api prefix",
			auth.AdminUsersPath, rec.Code)
	}

	// And nothing is registered below it, or for another method on it.
	for _, route := range []adminRoute{
		{http.MethodGet, adminPromotePath("a-user")},
		{http.MethodDelete, adminPromotePath("a-user")},
		{http.MethodPost, adminPromotePath("a-user") + "/again"},
		{http.MethodPost, auth.AdminPromoteUsersPath},
		{http.MethodGet, auth.AdminPromoteUsersPath},
	} {
		rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404: the reference registers no layer for it",
				route.method, route.path, rec.Code)
		}
	}
}

// testAdminPromoteRateLimiter is AdminOptions.RateLimiter: a second, separate
// slot from HTTPConfig.RateLimiter, spread onto this route and onto nothing
// else (node-auth admin.router.ts:1030, the option at :205-211).
//
// Two facts, and the second is the one that would be easy to ship wrong.
func testAdminPromoteRateLimiter(t *testing.T, mount Mounter) {
	options := auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}
	options.RateLimiter = refusingRateLimiter
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   options,
		seeds:   []adminSeed{{email: "limited@wiretest.example"}},
		options: adminAllStores(),
	})

	// It runs *before* the guard. The policy is AdminIsAdminFlag and no
	// credential is presented, so every other route on this surface answers 401;
	// this one answers the limiter's 429, which it can only do if the limiter
	// wraps the guard rather than the other way round. That ordering is the
	// reference's `...rateLimiter, guard` and it is what makes the slot worth
	// anything against an unauthenticated flood.
	rec := env.Do(env.adminRequest(http.MethodPost, adminPromotePath("a-user"), "{}"))
	AssertStatus(t, rec, http.StatusTooManyRequests)
	if body := strings.TrimSpace(rec.Body.String()); body != rateLimitRefusedBody {
		t.Errorf("body = %s, want the limiter's own %s — something downstream answered", body, rateLimitRefusedBody)
	}

	// It covers this route alone. Its neighbour, which mutates the same user's
	// roles, is unlimited and still answers the guard's 401 — and so does the
	// console's own login, which is the route a reader is most likely to assume
	// this field protects. It does not, on either line.
	for _, route := range []adminRoute{
		{http.MethodPost, auth.AdminUsersPath + "/a-user/roles"},
		{http.MethodGet, auth.AdminPingPath},
	} {
		rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
		AssertError(t, rec, http.StatusUnauthorized, "Unauthorized", "")
	}
	rec = env.Do(env.adminRequest(http.MethodPost, auth.AdminLoginPath,
		`{"email":"limited@wiretest.example","password":"`+testAdminPassword+`"}`))
	if rec.Code == http.StatusTooManyRequests {
		t.Error("POST <admin>/login was rate limited: the admin login carries no limiter on either line")
	}
}

// testAdminPromotePublishes is the event plane reaching this surface through a
// real adapter mount.
//
// The root package pins all four admin publication sites against
// (*Auth).AdminHandler directly (event_publication_test.go). What only this
// package can say is that the provenance survives the adapter: the console is
// deliberately outside EventContextMiddleware on all four, so the correlation
// id, client address and user agent are read off the request at the publication
// site — and an adapter that rewrote the request on its way to the handler
// would break that silently.
func testAdminPromotePublishes(t *testing.T, mount Mounter) {
	bus := auth.NewEventBus()
	var mu sync.Mutex
	var got []auth.Event
	bus.Subscribe(auth.EventBusWildcard, func(ev auth.Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ev)
	})

	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   adminOpenOptions(),
		options: append(adminAllStores(), auth.WithEventBus(bus)),
	})

	req := env.adminRequest(http.MethodPost, adminPromotePath("published"), `{"method":"role"}`)
	req.Header.Set(auth.CorrelationIDHeader, "corr-admin-1")
	req.Header.Set("User-Agent", "wiretest/1.0")
	req.RemoteAddr = "198.51.100.4:40000"
	AssertStatus(t, env.Do(req), http.StatusOK)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("published %d events, want exactly 1", len(got))
	}
	ev := got[0]
	if ev.Name != auth.EventRoleAssigned || ev.UserID != "published" {
		t.Fatalf("published %q for %q, want %q for the promoted user", ev.Name, ev.UserID, auth.EventRoleAssigned)
	}
	if ev.Data["role"] != "admin" || ev.Data["method"] != "role" {
		t.Errorf("data = %v, want {role: admin, method: role}", ev.Data)
	}
	if ev.CorrelationID != "corr-admin-1" || ev.IP != "198.51.100.4" || ev.UserAgent != "wiretest/1.0" {
		t.Errorf("request provenance = {%q, %q, %q}, want it read off the request this adapter passed through",
			ev.CorrelationID, ev.IP, ev.UserAgent)
	}
}

// ── the fifty-one ────────────────────────────────────────────────────────────

// adminReferenceRoute is one layer the dev line's admin router registers, and
// the route this port mounts for it.
type adminReferenceRoute struct {
	// line is the line of node-auth src/router/admin.router.ts that registers
	// it, at DevLineRevision. A bare admin.router.ts citation would be the
	// published tree, which registers fifty of these fifty-one.
	line int
	// pattern is the Express path as registered there, parameters and all.
	pattern string
	// route is how this port mounts it, with a concrete value wherever the
	// pattern carries a parameter.
	route adminRoute
}

// adminReferenceRoutes is the dev line's admin router, transcribed: fifty-one
// layers, one line each, in registration order.
//
// It is written out rather than derived because there is nothing to derive it
// from — the source is a TypeScript file in another repository, and the only
// honest way to hold this port to it is to transcribe it and cite each line so
// a reviewer can check the transcription. Re-derive it with:
//
//	grep -nE "^\s*router\.(get|post|put|patch|delete)\(" \
//	  node-auth/src/router/admin.router.ts
//
// which prints these fifty-one lines and nothing else. The same grep against
// awesome-node-auth prints fifty: POST /users/:id/promote is not there.
var adminReferenceRoutes = []adminReferenceRoute{
	{614, "/login", adminRoute{http.MethodPost, auth.AdminLoginPath}},
	{689, "/logout", adminRoute{http.MethodPost, auth.AdminLogoutPath}},
	{781, "/assets/admin.css", adminRoute{http.MethodGet, auth.AdminCSSPath}},
	{787, "/assets/admin.js", adminRoute{http.MethodGet, auth.AdminJSPath}},
	{829, "/", adminRoute{http.MethodGet, auth.AdminShellPath}},
	{832, "/api/ping", adminRoute{http.MethodGet, auth.AdminPingPath}},
	{839, "/api/users", adminRoute{http.MethodGet, auth.AdminUsersPath}},
	{880, "/api/users/:id", adminRoute{http.MethodGet, auth.AdminUsersPath + "/a-user"}},
	{894, "/api/users/:id", adminRoute{http.MethodDelete, auth.AdminUsersPath + "/a-user"}},
	{911, "/api/2fa-policy", adminRoute{http.MethodPost, auth.AdminTwoFAPolicyPath}},
	{946, "/api/users/:id/metadata", adminRoute{http.MethodGet, auth.AdminUsersPath + "/a-user/metadata"}},
	{957, "/api/users/:id/metadata", adminRoute{http.MethodPut, auth.AdminUsersPath + "/a-user/metadata"}},
	{971, "/api/users/:id/linked-accounts", adminRoute{http.MethodGet, auth.AdminUsersPath + "/a-user/linked-accounts"}},
	{984, "/api/users/:id/roles", adminRoute{http.MethodGet, auth.AdminUsersPath + "/a-user/roles"}},
	{995, "/api/users/:id/roles", adminRoute{http.MethodPost, auth.AdminUsersPath + "/a-user/roles"}},
	{1014, "/api/users/:id/roles/:role", adminRoute{http.MethodDelete, auth.AdminUsersPath + "/a-user/roles/editor"}},
	{1030, "/users/:id/promote", adminRoute{http.MethodPost, adminPromotePath("a-user")}},
	{1068, "/api/users/:id/tenants", adminRoute{http.MethodGet, auth.AdminUsersPath + "/a-user/tenants"}},
	{1081, "/api/actions", adminRoute{http.MethodGet, auth.AdminActionsPath}},
	{1086, "/api/settings", adminRoute{http.MethodGet, auth.AdminSettingsPath}},
	{1097, "/api/settings", adminRoute{http.MethodPut, auth.AdminSettingsPath}},
	{1109, "/api/settings/ui", adminRoute{http.MethodPatch, auth.AdminSettingsUIPath}},
	{1159, "/api/upload/logo", adminRoute{http.MethodPost, auth.AdminUploadLogoPath}},
	{1170, "/api/upload/bg-image", adminRoute{http.MethodPost, auth.AdminUploadBGImagePath}},
	{1182, "/api/upload/files", adminRoute{http.MethodGet, auth.AdminUploadFilesPath}},
	{1201, "/api/upload/:filename", adminRoute{http.MethodDelete, auth.AdminUploadPath + "/logo_1.png"}},
	{1221, "/api/sessions", adminRoute{http.MethodGet, auth.AdminSessionsPath}},
	{1251, "/api/sessions/:handle", adminRoute{http.MethodDelete, auth.AdminSessionsPath + "/a-session"}},
	{1264, "/api/roles", adminRoute{http.MethodGet, auth.AdminRolesPath}},
	{1285, "/api/roles", adminRoute{http.MethodPost, auth.AdminRolesPath}},
	{1298, "/api/roles/:name", adminRoute{http.MethodDelete, auth.AdminRolesPath + "/editor"}},
	{1311, "/api/tenants", adminRoute{http.MethodGet, auth.AdminTenantsPath}},
	{1322, "/api/tenants", adminRoute{http.MethodPost, auth.AdminTenantsPath}},
	{1335, "/api/tenants/:id", adminRoute{http.MethodDelete, auth.AdminTenantsPath + "/acme"}},
	{1348, "/api/tenants/:id/users", adminRoute{http.MethodGet, auth.AdminTenantsPath + "/acme/users"}},
	{1359, "/api/tenants/:id/users", adminRoute{http.MethodPost, auth.AdminTenantsPath + "/acme/users"}},
	{1372, "/api/tenants/:id/users/:userId", adminRoute{http.MethodDelete, auth.AdminTenantsPath + "/acme/users/a-user"}},
	{1388, "/api/api-keys", adminRoute{http.MethodGet, auth.AdminAPIKeysPath}},
	{1430, "/api/api-keys", adminRoute{http.MethodPost, auth.AdminAPIKeysPath}},
	{1469, "/api/api-keys/:id/revoke", adminRoute{http.MethodDelete, auth.AdminAPIKeysPath + "/a-key/revoke"}},
	{1480, "/api/api-keys/:id", adminRoute{http.MethodDelete, auth.AdminAPIKeysPath + "/a-key"}},
	{1498, "/api/webhooks", adminRoute{http.MethodGet, auth.AdminWebhooksPath}},
	{1525, "/api/webhooks", adminRoute{http.MethodPost, auth.AdminWebhooksPath}},
	{1548, "/api/webhooks/:id", adminRoute{http.MethodPatch, auth.AdminWebhooksPath + "/a-hook"}},
	{1563, "/api/webhooks/:id", adminRoute{http.MethodDelete, auth.AdminWebhooksPath + "/a-hook"}},
	{1583, "/api/templates/mail", adminRoute{http.MethodGet, auth.AdminMailTemplatesPath}},
	{1593, "/api/templates/mail", adminRoute{http.MethodPost, auth.AdminMailTemplatesPath}},
	{1605, "/api/templates/ui", adminRoute{http.MethodGet, auth.AdminUITemplatesPath}},
	{1615, "/api/templates/ui", adminRoute{http.MethodPost, auth.AdminUITemplatesPath}},
	{1634, "/api/openapi.json", adminRoute{http.MethodGet, auth.AdminOpenAPIPath}},
	{1652, "/api/docs", adminRoute{http.MethodGet, auth.AdminDocsPath}},
}

// adminUnregisteredProbes are paths and methods the dev line registers no layer
// for, and they are half of what makes "exactly" mean anything below.
//
// The list is not a sample of everything that is not a route — that set is
// infinite — but the near misses: the plausible spelling of a route that is
// spelled otherwise, a method on a path that has a layer for a different one,
// and a segment below a pattern that ends. Each is a shape a careless matcher
// would accept.
var adminUnregisteredProbes = []adminRoute{
	// The promote route's plausible spelling. Fifty of the fifty-one are under
	// /api and this one is not; a matcher that tidied that up would mount this
	// and break every dev-line client.
	{http.MethodPost, auth.AdminUsersPath + "/a-user/promote"},
	// Methods with no layer on a path that has one.
	{http.MethodPost, auth.AdminUsersPath + "/a-user"},
	{http.MethodPut, auth.AdminSettingsUIPath},
	{http.MethodGet, auth.AdminTwoFAPolicyPath},
	{http.MethodDelete, auth.AdminUsersPath},
	{http.MethodPost, auth.AdminSessionsPath + "/a-session"},
	{http.MethodGet, auth.AdminUploadLogoPath},
	{http.MethodPost, auth.AdminWebhooksPath + "/a-hook"},
	// Nothing is registered below a pattern that ends.
	{http.MethodDelete, auth.AdminUsersPath + "/a-user/roles/editor/extra"},
	{http.MethodDelete, auth.AdminTenantsPath + "/acme/users/a-user/extra"},
	{http.MethodGet, auth.AdminPingPath + "/again"},
	// The auth router's routes are not this router's. The admin console mounts
	// beside HTTPConfig.Prefix() rather than under it, and neither knows the
	// other's paths.
	{http.MethodPost, "/api/login"},
	{http.MethodGet, "/api/me"},
}

// testAdminRouteSet is the assertion this milestone exists to be able to make:
// the set of routes this console mounts is exactly the set the dev line's admin
// router registers — fifty-one, no more and no fewer.
//
// # What it asserts
//
//  1. The transcription is complete and has no duplicates: fifty-one entries,
//     fifty-one distinct dev-line lines, fifty-one distinct (method, path)
//     pairs.
//  2. It agrees with adminAllRoutes(), the union of the six family tables the
//     five previous PRs and this one built, in both directions. A route in a
//     family table that the dev line does not register fails here, and so does
//     one the dev line registers that no family table carries.
//  3. Every one of the fifty-one is actually mounted on a fully wired console:
//     the answer to a probe is never the router's own "no such route". A table
//     that agreed with itself while the handler served nothing would pass (1)
//     and (2) and fail this.
//  4. The near misses in adminUnregisteredProbes are not mounted, which is the
//     only direction in which "no more" can be tested at all. See below.
//
// # What it cannot assert, and this is the honest part
//
//   - **Patterns, not URLs.** `/api/users/:id` is one registration matching
//     infinitely many paths, and this probes it with one concrete id. Two
//     routers agreeing on `/api/users/a-user` could still disagree on
//     `/api/users/a%2Fb`; the parameter-shaped cases for that live with the
//     route families, where matchAdminRead's escaping rules are the subject.
//   - **"No more" is bounded by the probes.** (*Auth).AdminHandler is one
//     http.HandlerFunc and Go offers no way to enumerate the paths a handler
//     accepts, so nothing here can sweep the whole URL space. A route mounted
//     in AdminHandler but absent from every family table and from
//     adminUnregisteredProbes is invisible to this test. What closes that in
//     practice is (2): a route nobody put in a table is also a route nobody
//     wrote a case for, and testAdminNotMounted walks the same union.
//   - **Not a claim about the answers.** A mounted route is one that does not
//     answer the router's 404; what it answers instead is the business of the
//     family suite that owns it.
//   - **Not a claim about the published reference.** The set is the dev line's
//     fifty-one, of which the published reference has fifty. The one it lacks
//     is the promote route, and that is registered as a deviation rather than
//     hidden here.
func testAdminRouteSet(t *testing.T, mount Mounter) {
	if len(adminReferenceRoutes) != 51 {
		t.Fatalf("the transcription holds %d layers, want the dev line's 51", len(adminReferenceRoutes))
	}

	lines := make(map[int]bool, len(adminReferenceRoutes))
	reference := make(map[adminRoute]adminReferenceRoute, len(adminReferenceRoutes))
	for _, entry := range adminReferenceRoutes {
		if lines[entry.line] {
			t.Errorf("admin.router.ts:%d appears twice: each layer is one line", entry.line)
		}
		lines[entry.line] = true
		if previous, ok := reference[entry.route]; ok {
			t.Errorf("%s %s is claimed by both admin.router.ts:%d and :%d",
				entry.route.method, entry.route.path, previous.line, entry.line)
		}
		reference[entry.route] = entry
	}

	mounted := make(map[adminRoute]bool, len(adminReferenceRoutes))
	for _, route := range adminAllRoutes() {
		if mounted[route] {
			t.Errorf("%s %s appears in two family tables", route.method, route.path)
		}
		mounted[route] = true
	}

	for route := range mounted {
		if _, ok := reference[route]; !ok {
			t.Errorf("%s %s is mounted and the dev line's admin router registers no such layer. "+
				"A route this port serves and the source does not is a fork, not a port.",
				route.method, route.path)
		}
	}
	for route, entry := range reference {
		if !mounted[route] {
			t.Errorf("%s %s is registered at admin.router.ts:%d (%s) and no family table mounts it. "+
				"A documented route nobody mounted fails here rather than at a consumer.",
				route.method, route.path, entry.line, entry.pattern)
		}
	}

	// And the handler agrees with the tables. Every store is wired and the
	// documentation pair asked for, so a 404 here is the router's and not a
	// feature's.
	//
	// The policy is AdminIsAdminFlag and not AdminOpen, and that is forced: the
	// console's own POST /login and POST /logout exist only under a
	// session-based policy (AdminGuard.LoginRoutesMounted, the reference's
	// sessionBased at admin.router.ts:516-537), so under the open policy two of
	// the fifty-one would be legitimately absent. No credential is presented, so
	// the forty-odd guarded routes answer 401 — which is emphatically not the
	// router's "no such route", and is what this probe is asking about.
	options := auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}
	options.Docs.Enabled = true
	env := newAdminEnv(t, mount, adminEnvOptions{
		admin:   options,
		seeds:   []adminSeed{{email: "routeset@wiretest.example"}},
		options: adminAllStores(),
	})
	for _, entry := range adminReferenceRoutes {
		rec := env.Do(env.adminRequest(entry.route.method, entry.route.path, "{}"))
		if adminUnrouted(rec.Code, rec.Body.String()) {
			t.Errorf("%s %s = %d (%s) — registered at admin.router.ts:%d (%s) and not mounted here",
				entry.route.method, entry.route.path, rec.Code,
				strings.TrimSpace(rec.Body.String()), entry.line, entry.pattern)
		}
	}
	for _, route := range adminUnregisteredProbes {
		rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
		if !adminUnrouted(rec.Code, rec.Body.String()) {
			t.Errorf("%s %s = %d, want the router's own 404: the dev line registers no layer for it",
				route.method, route.path, rec.Code)
		}
	}
}

// adminUnrouted reports whether an answer is "there is no such route" rather
// than a handler's.
//
// The distinction is the body. A handler's own 404 — "RBAC store not
// configured", "User not found" — is this router's `{"error": …}` envelope; the
// router's is whatever the adapter under test writes for an unknown path, which
// is Go's plain-text page for three of the four and a bare 404 for the fourth.
// So an answer counts as unrouted when it is a 404 or 405 that is *not* the
// admin envelope.
func adminUnrouted(code int, body string) bool {
	if code == http.StatusMethodNotAllowed {
		return true
	}
	if code != http.StatusNotFound {
		return false
	}
	return !strings.Contains(body, `"error"`)
}

// ── the document's other direction ───────────────────────────────────────────

// adminUndocumentedRoutes is every route the console mounts that the
// reference's OpenAPI generator does not describe, with the reason.
//
// U15 left this as a hand-written stop-point in the root package
// (TestAdminOpenAPIOmitsWhatTheReferenceOmits), asserting that the document does
// not describe these — a check that catches a document which *grew* an entry and
// says nothing about one that fell behind the router. This list does the other
// job: testAdminDocumentSet holds it to be exactly the complement of the
// document within the mount, so a route added to any family table without a
// document entry has to be named here, deliberately, by whoever added it.
//
// Keys are the route's shape — the Express pattern with each parameter replaced
// by `*` — because the two sides spell parameters differently (`:id` in the
// router, `{id}` in the document) and neither spelling is the subject.
var adminUndocumentedRoutes = map[adminRoute]string{
	{http.MethodGet, "/"}:                     "the SPA shell: the document describes the REST API, not the page",
	{http.MethodGet, "/assets/admin.css"}:     "a static asset",
	{http.MethodGet, "/assets/admin.js"}:      "a static asset",
	{http.MethodPost, "/login"}:               "the console's own login",
	{http.MethodPost, "/logout"}:              "the console's own logout",
	{http.MethodGet, "/api/actions"}:          "the action registry listing, with no flag of its own",
	{http.MethodPatch, "/api/settings/ui"}:    "the branding patch, which hasUi describes at /api/ui-settings instead",
	{http.MethodGet, "/api/templates/mail"}:   "the mail template routes",
	{http.MethodPost, "/api/templates/mail"}:  "the mail template routes",
	{http.MethodGet, "/api/templates/ui"}:     "the UI translation routes",
	{http.MethodPost, "/api/templates/ui"}:    "the UI translation routes",
	{http.MethodPost, "/api/upload/logo"}:     "the logo upload, which hasUi describes at /api/ui/logo instead",
	{http.MethodPost, "/api/upload/bg-image"}: "the background upload",
	{http.MethodGet, "/api/upload/files"}:     "the upload listing",
	{http.MethodDelete, "/api/upload/*"}:      "the upload delete",
	{http.MethodPost, "/users/*/promote"}: "the promote route — absent from the dev line's generator too, " +
		"so the one route that grants the console is the one the document never mentions",
}

// testAdminDocumentSet is the admin OpenAPI document held to the mount in both
// directions, as far as it can honestly be held.
//
// # The forward direction closes
//
// Every operation the served document describes is a route this adapter mounts.
// That is the root package's TestAdminOpenAPIDocumentMatchesTheMount asserted
// again over the bytes a client actually receives, through the router the host
// actually chose.
//
// # The reverse direction does not, and this says exactly how far it gets
//
// It cannot close, and the reason is not this port's: the reference's generator
// describes sixteen fewer operations than its router registers, and reproducing
// the document means reproducing the gaps (openapi_admin.go). What this does
// instead is make the gap *exhaustive* rather than sampled — every mounted
// route is either in the document or named in adminUndocumentedRoutes, and
// every entry in that list is a route that is really mounted and really absent
// from the document. So the list cannot rot in either direction: an entry for a
// route that has since been documented fails, an entry for a route that no
// longer exists fails, and a new route that nobody documented fails until
// somebody writes down why.
//
// That is the whole of the improvement available here. Closing the reverse
// direction properly means the dev line's generator growing the sixteen, which
// is a change to the source and not to the port.
func testAdminDocumentSet(t *testing.T, mount Mounter) {
	options := auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}
	options.Docs.Enabled = true
	env := newAdminEnv(t, mount, adminEnvOptions{admin: options, options: adminAllStores()})

	// The document is unguarded, which is why no credential is presented here
	// and why testAdminDocs pins that on its own.
	rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminOpenAPIPath, ""))
	AssertStatus(t, rec, http.StatusOK)
	paths, ok := Body(t, rec)["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %v, want an object", Body(t, rec)["paths"])
	}

	base := env.Config.AdminDocsBasePath()
	documented := make(map[adminRoute]bool, len(paths))
	for path, item := range paths {
		if !strings.HasPrefix(path, base) {
			t.Errorf("the document describes %q, which is not below the admin base path %q", path, base)
			continue
		}
		operations, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("path item %q = %v, want an object", path, item)
		}
		for method := range operations {
			documented[adminRoute{strings.ToUpper(method), adminRouteShape(path[len(base):])}] = true
		}
	}

	mounted := make(map[adminRoute]string, len(adminReferenceRoutes))
	for _, entry := range adminReferenceRoutes {
		mounted[adminRoute{entry.route.method, adminRouteShape(entry.pattern)}] = entry.pattern
	}

	for route := range documented {
		if _, ok := mounted[route]; !ok {
			t.Errorf("the document describes %s %s and no route mounts it", route.method, route.path)
		}
	}
	for route, pattern := range mounted {
		reason, excused := adminUndocumentedRoutes[route]
		switch {
		case documented[route] && excused:
			t.Errorf("%s %s (%s) is documented and is also listed as undocumented (%q). "+
				"If the document grew it, delete the line.", route.method, pattern, pattern, reason)
		case !documented[route] && !excused:
			t.Errorf("%s %s is mounted and the document does not describe it. Either the document "+
				"should — in which case the generator grows a path item — or it deliberately does "+
				"not, in which case say so in adminUndocumentedRoutes.", route.method, pattern)
		}
	}
	for route := range adminUndocumentedRoutes {
		if _, ok := mounted[route]; !ok {
			t.Errorf("adminUndocumentedRoutes names %s %s, which this console does not mount",
				route.method, route.path)
		}
	}

	// The partition, as arithmetic: thirty-five documented plus sixteen
	// deliberately not is fifty-one. The two loops above already enforce it
	// route by route; this states the total, which is what stops `documented`
	// from being quietly empty — a document that served no paths at all would
	// satisfy every "is documented" check by vacuity and fail only here.
	if len(mounted) != len(adminReferenceRoutes) {
		t.Fatalf("the reference table collapses to %d shapes from %d layers", len(mounted), len(adminReferenceRoutes))
	}
	if len(documented)+len(adminUndocumentedRoutes) != len(mounted) {
		t.Errorf("%d documented + %d deliberately not = %d, want the %d routes this console mounts",
			len(documented), len(adminUndocumentedRoutes),
			len(documented)+len(adminUndocumentedRoutes), len(mounted))
	}
}

// adminRouteShape normalises a path to its shape: every parameter — Express's
// ":name" or OpenAPI's "{name}" — becomes "*", so that the router's spelling and
// the document's can be compared without either being taken as canonical.
func adminRouteShape(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, ":") ||
			(strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")) {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, "/")
}
