package wiretest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Conformance cases for the session-listing and account-management routes:
// GET /sessions, DELETE /sessions/{handle}, POST /sessions/cleanup,
// PATCH /profile, POST /add-phone and DELETE /account.
//
// These are the first authenticated state-changing routes in the port, so they
// are also the first place the CSRF double-submit is enforceable at all. Until
// now the machinery protected nothing.

// bareUserStore implements UserStore and nothing else. A store like this is what
// makes the account routes answer 501 instead of pretending to have written.
type bareUserStore struct{ inner *auth.MemoryUserStore }

func newBareUserStore() bareUserStore { return bareUserStore{inner: auth.NewMemoryUserStore()} }

func (s bareUserStore) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	return s.inner.CreateUser(ctx, user)
}

func (s bareUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	return s.inner.GetUserByEmail(ctx, email, tenantID)
}

func (s bareUserStore) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	return s.inner.GetUserByID(ctx, id, tenantID)
}

// bareSessionStore implements SessionStore and nothing else: it can log a user
// in but cannot list, revoke or clean up.
type bareSessionStore struct{ inner *auth.MemorySessionStore }

func newBareSessionStore() bareSessionStore {
	return bareSessionStore{inner: auth.NewMemorySessionStore()}
}

func (s bareSessionStore) CreateSession(ctx context.Context, session auth.Session) (auth.Session, error) {
	return s.inner.CreateSession(ctx, session)
}

func (s bareSessionStore) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (auth.Session, error) {
	return s.inner.GetSessionByRefreshTokenHash(ctx, hash)
}

func (s bareSessionStore) UpdateSession(ctx context.Context, session auth.Session) error {
	return s.inner.UpdateSession(ctx, session)
}

// nilSessionStore returns a nil slice from the list call, the way a driver that
// found no rows does. It exists to prove the route still serialises [].
type nilSessionStore struct{ *auth.MemorySessionStore }

func (nilSessionStore) ListSessionsForUser(context.Context, string, string) ([]auth.Session, error) {
	return nil, nil
}

func bearerRequest(method, url, token string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// sessionEntries asserts the wrapped envelope and returns the entries.
func sessionEntries(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	body := Body(t, rec)
	AssertKeys(t, body, "sessions")
	raw, ok := body["sessions"].([]any)
	if !ok {
		t.Fatalf("sessions = %T, want a JSON array (body %s)", body["sessions"], rec.Body.String())
	}
	entries := make([]map[string]any, 0, len(raw))
	for i, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("sessions[%d] = %T, want an object", i, item)
		}
		entries = append(entries, entry)
	}
	return entries
}

func findSession(t *testing.T, entries []map[string]any, handle string) map[string]any {
	t.Helper()
	for _, entry := range entries {
		if entry["sessionHandle"] == handle {
			return entry
		}
	}
	t.Fatalf("no session %q in %v", handle, entries)
	return nil
}

func testSessions(t *testing.T, mount Mounter) {
	t.Run("the list is wrapped in a sessions key", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("sessions@example.com")

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)

		entries := sessionEntries(t, rec)
		if len(entries) != 1 {
			t.Fatalf("sessions = %d entries, want 1 (%s)", len(entries), rec.Body.String())
		}
		entry := entries[0]
		// The exact key set, so that a refresh-token hash or any other stored
		// column cannot be added to the projection without failing here.
		AssertKeys(t, entry, "sessionHandle", "userId", "tenantId", "createdAt", "expiresAt")
		if entry["userId"] != user.ID {
			t.Errorf("userId = %v, want %q", entry["userId"], user.ID)
		}
		if entry["tenantId"] != "t1" {
			t.Errorf("tenantId = %v, want \"t1\"", entry["tenantId"])
		}
		created := parseTimestamp(t, entry, "createdAt")
		expires := parseTimestamp(t, entry, "expiresAt")
		// The session outlives the refresh token by nothing: both are the
		// configured 30 days from creation.
		if lifetime := expires.Sub(created); lifetime > 30*24*time.Hour || lifetime < 30*24*time.Hour-2*time.Second {
			t.Errorf("expiresAt - createdAt = %s, want 30 days", lifetime)
		}
	})

	// The browser path, and the CSRF matrix row that says a cookie-authenticated
	// GET is not checked: the clients list sessions without a CSRF header.
	t.Run("cookie mode needs no CSRF header", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "sessionscookie@example.com")

		rec := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil), login))
		AssertStatus(t, rec, http.StatusOK)

		// Two: the seeding register issued one session and the login a second. The
		// route lists every live session of the user, not just the current one.
		if entries := sessionEntries(t, rec); len(entries) != 2 {
			t.Fatalf("sessions = %d entries, want 2 (%s)", len(entries), rec.Body.String())
		}
	})

	t.Run("an empty list serialises as [] and not null", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(nilSessionStore{auth.NewMemorySessionStore()}))
		_, tokens := env.Seed("emptysessions@example.com")

		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		if got := strings.TrimSpace(rec.Body.String()); got != `{"sessions":[]}` {
			t.Fatalf("body = %s, want {\"sessions\":[]}", got)
		}
	})

	t.Run("without a token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/sessions", nil))
		AssertError(t, rec, http.StatusForbidden, "No access token provided", "")
	})

	// The reference simply does not mount the session routes when the store
	// cannot serve them, so it answers 404. This port always mounts them and
	// reports the missing capability, which is the same 501 every other
	// store-gated route in this package returns.
	t.Run("501 when the session store cannot list", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(newBareSessionStore()))
		_, tokens := env.Seed("nolist@example.com")
		rec := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
	})

	// One family client URI-escapes the handle and the other posts it verbatim;
	// both have to revoke the same session.
	for _, tc := range []struct {
		name    string
		handle  string
		request string
	}{
		{name: "verbatim handle", handle: "ses_plain+form:1", request: "ses_plain+form:1"},
		{name: "URI-escaped handle", handle: "ses_escaped+form:2", request: "ses_escaped%2Bform%3A2"},
	} {
		t.Run("DELETE accepts a "+tc.name, func(t *testing.T) {
			store := auth.NewMemorySessionStore()
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
			user, tokens := env.Seed("revoke@example.com")
			seedSession(t, store, tc.handle, user)

			rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/"+tc.request, tokens.AccessToken))
			AssertStatus(t, rec, http.StatusOK)
			AssertKeys(t, Body(t, rec), "success")
			if Body(t, rec)["success"] != true {
				t.Fatalf("success = %v", Body(t, rec)["success"])
			}

			list := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/sessions", tokens.AccessToken))
			entry := findSession(t, sessionEntries(t, list), tc.handle)
			if _, revoked := entry["revokedAt"]; !revoked {
				t.Fatalf("session %q was not revoked: %v", tc.handle, entry)
			}
		})
	}

	// Not found and not yours are the same answer, so the route cannot be used
	// to probe for another account's live sessions.
	t.Run("DELETE an unknown handle", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("unknownhandle@example.com")
		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_nope", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotFound, "Session not found", "")
	})

	t.Run("DELETE somebody else's handle", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		_, tokens := env.Seed("owner@example.com")
		stranger, _ := env.Seed("stranger@example.com")
		seedSession(t, store, "ses_stranger", stranger)

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/sessions/ses_stranger", tokens.AccessToken))
		AssertError(t, rec, http.StatusNotFound, "Session not found", "")
	})

	// The reference mounts cleanup with no auth gate at all (auth.router.ts:736):
	// no token, no admin secret, and — being absent from no middleware — no CSRF
	// check either. That is reproduced here rather than hardened, because a cron
	// job calling it unauthenticated has to keep working. Flagged for upstream.
	t.Run("cleanup is publicly callable", func(t *testing.T) {
		store := auth.NewMemorySessionStore()
		env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithSessionStore(store))
		user, _ := env.Seed("cleanup@example.com")
		expired := auth.Session{
			ID:               "ses_expired",
			UserID:           user.ID,
			TenantID:         user.TenantID,
			RefreshTokenHash: "expired-hash",
			CreatedAt:        time.Now().Add(-48 * time.Hour),
			ExpiresAt:        time.Now().Add(-time.Hour),
		}
		if _, err := store.CreateSession(context.Background(), expired); err != nil {
			t.Fatalf("seed expired session: %v", err)
		}

		rec := env.Do(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/sessions/cleanup", nil))
		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success", "deleted")
		if body["success"] != true {
			t.Errorf("success = %v", body["success"])
		}
		// Exactly the one expired session: the live one the seed created stays.
		if body["deleted"] != float64(1) {
			t.Errorf("deleted = %v, want 1", body["deleted"])
		}
	})
}

func seedSession(t *testing.T, store *auth.MemorySessionStore, handle string, user auth.User) {
	t.Helper()
	now := time.Now()
	session := auth.Session{
		ID:               handle,
		UserID:           user.ID,
		TenantID:         user.TenantID,
		RefreshTokenHash: "hash-" + handle,
		CreatedAt:        now,
		ExpiresAt:        now.Add(time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("seed session %q: %v", handle, err)
	}
}

func parseTimestamp(t *testing.T, entry map[string]any, key string) time.Time {
	t.Helper()
	raw, ok := entry[key].(string)
	if !ok {
		t.Fatalf("%s = %v, want an RFC 3339 string", key, entry[key])
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("%s = %q: %v", key, raw, err)
	}
	return parsed
}

func testAccount(t *testing.T, mount Mounter) {
	t.Run("PATCH /profile", func(t *testing.T) { testUpdateProfile(t, mount) })
	t.Run("POST /add-phone", func(t *testing.T) { testAddPhone(t, mount) })
	t.Run("DELETE /account", func(t *testing.T) { testDeleteAccount(t, mount) })
	t.Run("the store capability gate", func(t *testing.T) { testAccountCapabilityGate(t, mount) })
}

// loginSession logs a seeded user in and returns the response to replay cookies
// from, together with the CSRF token the page would mirror into the header.
func loginSession(t *testing.T, env *Env, email string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	env.Seed(email)
	login := env.Do(env.Request(http.MethodPost, "/login", credentials(email)))
	AssertStatus(t, login, http.StatusOK)
	return login, Cookie(t, login, hostCSRF).Value
}

func meBody(t *testing.T, env *Env, login *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	rec := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), login))
	AssertStatus(t, rec, http.StatusOK)
	return Body(t, rec)
}

func testUpdateProfile(t *testing.T, mount Mounter) {
	// The first route in the port on which the double-submit is actually
	// enforced: a cookie-authenticated PATCH is exactly the request a
	// cross-site form post can forge.
	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "profile@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Mario", "lastName": "Rossi"}), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}

		me := meBody(t, env, login)
		if me["firstName"] != "Mario" || me["lastName"] != "Rossi" {
			t.Fatalf("profile not updated: %v / %v", me["firstName"], me["lastName"])
		}
	})

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "profilecsrf@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged", "lastName": "Request"}), login)
		rec := env.Do(req)

		AssertError(t, rec, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		// Rejecting is only half of it: the write must not have happened.
		if me := meBody(t, env, login); me["firstName"] != nil {
			t.Fatalf("the rejected request still wrote the profile: %v", me["firstName"])
		}
	})

	t.Run("cookie mode with a mismatched X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "profilemismatch@example.com")

		req := Replay(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Forged"}), login)
		req.Header.Set(auth.CSRFHeaderName, "0123456789abcdef0123456789abcdef")
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})

	// A bearer caller cannot be driven by a cross-site form post and never reads
	// the CSRF cookie, so it is exempt — the reference skips the check entirely
	// for Authorization-header requests (auth.middleware.ts:35).
	t.Run("bearer mode needs no CSRF header", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		user, tokens := env.Seed("profilebearer@example.com")

		req := env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Anna", "lastName": "Bianchi"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		AssertNoCookies(t, rec)

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		if Body(t, me)["firstName"] != "Anna" {
			t.Fatalf("profile not updated for %s: %s", user.ID, me.Body.String())
		}
	})

	// [DEVIATION] The reference enforces CSRF inside its auth middleware, so an
	// unauthenticated PATCH is refused with "No access token provided". Here the
	// CSRF middleware wraps the auth middleware — that is what makes the cookie
	// auto-init router-level, as the reference's is — so the unsafe method is
	// judged first and the caller sees CSRF_INVALID. Both are 403; pinned so the
	// precedence cannot change unnoticed.
	t.Run("without a token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		rec := env.Do(env.Request(http.MethodPatch, "/profile", map[string]string{"firstName": "Nobody"}))
		AssertError(t, rec, http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
	})
}

func testAddPhone(t *testing.T, mount Mounter) {
	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("phone@example.com")

		req := env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+390123456789"})
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		if Body(t, me)["phoneNumber"] != "+390123456789" {
			t.Fatalf("phone not stored: %s", me.Body.String())
		}
	})

	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, csrf := loginSession(t, env, "phonecookie@example.com")

		req := Replay(env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+390000000000"}), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")
		if me := meBody(t, env, login); me["phoneNumber"] != "+390000000000" {
			t.Fatalf("phone not stored: %v", me["phoneNumber"])
		}
	})

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "phonecsrf@example.com")

		req := Replay(env.Request(http.MethodPost, "/add-phone", map[string]string{"phoneNumber": "+391111111111"}), login)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		if me := meBody(t, env, login); me["phoneNumber"] != nil {
			t.Fatalf("the rejected request still wrote the phone number: %v", me["phoneNumber"])
		}
	})
}

func testDeleteAccount(t *testing.T, mount Mounter) {
	t.Run("cookie mode with a matching X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		env.Seed("delete@example.com")
		// A second credential for the same user, so that the cleanup can be
		// checked against a session the deleting request did not present.
		login := env.Do(env.Request(http.MethodPost, "/login", credentials("delete@example.com")))
		AssertStatus(t, login, http.StatusOK)
		csrf := Cookie(t, login, hostCSRF).Value

		req := Replay(httptest.NewRequest(http.MethodDelete, env.Config.Prefix()+"/account", nil), login)
		req.Header.Set(auth.CSRFHeaderName, csrf)
		rec := env.Do(req)

		AssertStatus(t, rec, http.StatusOK)
		body := Body(t, rec)
		AssertKeys(t, body, "success")
		if body["success"] != true {
			t.Fatalf("success = %v", body["success"])
		}
		// Every name variant is expired, exactly as logout does: a deleted
		// account must not leave the browser holding a credential.
		for _, name := range []string{
			hostAccess, "__Secure-accessToken", "accessToken",
			hostRefresh, "__Secure-refreshToken", "refreshToken",
			hostCSRF, "__Secure-csrf-token", "csrf-token",
		} {
			AssertCleared(t, rec, name)
		}

		// The user record is gone, so the access token no longer resolves.
		me := env.Do(Replay(httptest.NewRequest(http.MethodGet, env.Config.Prefix()+"/me", nil), login))
		AssertError(t, me, http.StatusForbidden, "Invalid or expired access token", "")

		// And the session was revoked before the record was deleted, so the
		// refresh credential reports the family's fast-logout code.
		refresh := env.Do(Replay(httptest.NewRequest(http.MethodPost, env.Config.Prefix()+"/refresh", nil), login))
		AssertError(t, refresh, http.StatusUnauthorized, "Session has been revoked", auth.CodeSessionRevoked)
	})

	t.Run("cookie mode without X-CSRF-Token", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		login, _ := loginSession(t, env, "deletecsrf@example.com")

		req := Replay(httptest.NewRequest(http.MethodDelete, env.Config.Prefix()+"/account", nil), login)
		AssertError(t, env.Do(req), http.StatusForbidden, "CSRF token validation failed", auth.CodeCSRFInvalid)
		// The account survived the refused request.
		if me := meBody(t, env, login); me["email"] != "deletecsrf@example.com" {
			t.Fatalf("account was deleted by a request that was refused: %v", me["email"])
		}
	})

	t.Run("bearer mode", func(t *testing.T) {
		env := NewEnv(t, mount, auth.DefaultHTTPConfig())
		_, tokens := env.Seed("deletebearer@example.com")

		rec := env.Do(bearerRequest(http.MethodDelete, env.Config.Prefix()+"/account", tokens.AccessToken))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "success")

		me := env.Do(bearerRequest(http.MethodGet, env.Config.Prefix()+"/me", tokens.AccessToken))
		AssertError(t, me, http.StatusForbidden, "Invalid or expired access token", "")
	})
}

// A user store that cannot write the profile, the phone number or the deletion
// reports the missing capability rather than answering 200 without writing. The
// reference answers 501 here too, with its own per-method message.
func testAccountCapabilityGate(t *testing.T, mount Mounter) {
	for _, tc := range []struct {
		name   string
		method string
		route  string
		body   any
	}{
		{name: "PATCH /profile", method: http.MethodPatch, route: "/profile", body: map[string]string{"firstName": "Mario"}},
		{name: "POST /add-phone", method: http.MethodPost, route: "/add-phone", body: map[string]string{"phoneNumber": "+3900"}},
		{name: "DELETE /account", method: http.MethodDelete, route: "/account", body: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := NewEnv(t, mount, auth.DefaultHTTPConfig(), auth.WithUserStore(newBareUserStore()))
			_, tokens := env.Seed("gate@example.com")

			req := env.Request(tc.method, tc.route, tc.body)
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			rec := env.Do(req)

			AssertError(t, rec, http.StatusNotImplemented, "Feature not supported by the configured stores", auth.CodeNotImplemented)
		})
	}
}
