package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── The exhaustive enforcement matrix ────────────────────────────────────────
//
// This is the matrix the review asked for, driven as a cross-product rather
// than as hand-picked rows, so that a cell nobody thought about cannot quietly
// go unchecked.
//
// Dimensions:
//   - access-token cookie: absent / bare / __Secure- / __Host-
//   - Authorization: absent / real "Bearer …"
//   - X-Auth-Strategy: absent / "bearer"
//   - method: GET (safe) / POST (unsafe)
//   - route: in-prefix non-exempt / in-prefix exempt / out-of-prefix /
//     group-mounted non-exempt / POST /link-request
//
// The expected status is computed from the *specification* of enforcement:
//
//	enforced == unsafe && mounted && !exempt && no real bearer credential
//	            && (access-token cookie present || manual-check route)
//
// An earlier revision of this file computed `want` without the last clause, as a
// canary against scoping enforcement to cookie-authenticated requests. That
// scoping is now the intended behaviour — it is how the port recovers the
// reference's ordering, where the access token is extracted first and a request
// with no token never reaches the CSRF branch at all
// (auth.middleware.ts:29-35). The canary's concern was real, though, and it is
// answered by the manualCheck term rather than dropped: see
// TestCSRFManualCheckRouteIsEnforcedWithoutAnyCredential below and the
// full-stack cases in the wiretest suite.
func TestCSRFEnforcementMatrixExhaustive(t *testing.T) {
	routes := []struct {
		name    string
		path    string
		mounted bool
		exempt  bool
		manual  bool
	}{
		{name: "in-prefix non-exempt", path: "/auth/add-phone", mounted: true, exempt: false},
		{name: "in-prefix exempt", path: "/auth/login", mounted: true, exempt: true},
		{name: "group-mounted non-exempt", path: "/api/auth/add-phone", mounted: true, exempt: false},
		{name: "out-of-prefix", path: "/api/orders", mounted: false, exempt: false},
		// The unauthenticated-but-CSRF-protected route: no auth middleware in the
		// reference, but a hand-written double-submit check inside the handler
		// (auth.router.ts:1489-1495). It must be enforced with no credential of
		// any kind on the request, which is what manual=true asserts.
		{name: "link-request", path: "/auth/link-request", mounted: true, exempt: false, manual: true},
		{name: "group-mounted link-request", path: "/api/auth/link-request", mounted: true, exempt: false, manual: true},
	}
	accessCookies := []struct{ name, cookie string }{
		{name: "no access cookie", cookie: ""},
		{name: "bare access cookie", cookie: AccessTokenCookieName},
		{name: "__Secure- access cookie", cookie: secureCookiePrefix + AccessTokenCookieName},
		{name: "__Host- access cookie", cookie: hostCookiePrefix + AccessTokenCookieName},
	}
	authzs := []struct{ name, header string }{
		{name: "no authorization", header: ""},
		{name: "real bearer", header: "Bearer abc"},
	}
	strategies := []struct{ name, header string }{
		{name: "no strategy", header: ""},
		{name: "bearer strategy", header: AuthStrategyBearer},
	}
	methods := []struct {
		name   string
		method string
		unsafe bool
	}{
		{name: "GET", method: http.MethodGet, unsafe: false},
		{name: "POST", method: http.MethodPost, unsafe: true},
	}

	for _, rt := range routes {
		for _, ac := range accessCookies {
			for _, az := range authzs {
				for _, st := range strategies {
					for _, m := range methods {
						cookieAuthenticated := ac.cookie != ""
						// `az.header == ""` applies to the manual-check route too, which is
						// a deliberate deviation from the reference rather than a property
						// of it: auth.router.ts:1489 has no usingBearer term, so the
						// reference would refuse a bearer POST /link-request with no pair.
						// Stated on its own in
						// TestCSRFManualCheckRouteExemptsARealBearerCredential, because a
						// term hidden inside a cross-product is not a documented decision.
						enforced := m.unsafe && rt.mounted && !rt.exempt && az.header == "" &&
							(cookieAuthenticated || rt.manual)
						want := http.StatusOK
						if enforced {
							want = http.StatusForbidden
						}
						name := rt.name + "/" + ac.name + "/" + az.name + "/" + st.name + "/" + m.name
						t.Run(name, func(t *testing.T) {
							req := httptest.NewRequest(m.method, rt.path, nil)
							// A CSRF cookie the caller never mirrors into the header:
							// the shape of every cross-site forgery.
							req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
							if ac.cookie != "" {
								req.AddCookie(&http.Cookie{Name: ac.cookie, Value: "session-value"})
							}
							if az.header != "" {
								req.Header.Set("Authorization", az.header)
							}
							if st.header != "" {
								req.Header.Set(AuthStrategyHeader, st.header)
							}
							rec := httptest.NewRecorder()
							csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)

							if rec.Code != want {
								t.Fatalf("status = %d, want %d (enforced=%v): %s",
									rec.Code, want, enforced, rec.Body.String())
							}
						})
					}
				}
			}
		}
	}
}

// TestCSRFEnforcementIsScopedToCookieAuthentication states the scoping directly
// rather than as a side effect of the matrix, in both directions: on a protected
// mutating route a session cookie turns enforcement on, and its absence hands the
// request to the auth gate instead.
//
// The second half is not a hole. Every route here sits behind the access-token
// middleware, which answers a credential-less request with
// 403 {"error":"No access token provided"} — the reference's own literal, pinned
// end to end in the wiretest suite. The 200 below is the stub handler standing in
// for that gate, and it is only sound for routes that have one.
func TestCSRFEnforcementIsScopedToCookieAuthentication(t *testing.T) {
	authGated := []string{"/auth/add-phone", "/auth/profile", "/auth/account", "/auth/change-password"}
	cookies := []string{
		AccessTokenCookieName,
		secureCookiePrefix + AccessTokenCookieName,
		hostCookiePrefix + AccessTokenCookieName,
	}

	for _, path := range authGated {
		for _, cookie := range cookies {
			if got := csrfDrive(t, http.MethodPost, path, cookie); got != http.StatusForbidden {
				t.Errorf("POST %s with %s = %d, want 403: a cookie-authenticated forgery must be refused", path, cookie, got)
			}
		}
		if got := csrfDrive(t, http.MethodPost, path, ""); got != http.StatusOK {
			t.Errorf("POST %s with no session = %d, want 200: it belongs to the auth gate", path, got)
		}
	}
}

// TestCSRFManualCheckRouteIsEnforcedWithoutAnyCredential is the property the
// scoping above would otherwise break, and the reason csrfManualCheckRoutes
// exists.
//
// POST /link-request has no auth middleware in the reference and none here, so
// there is no second line of defence behind it: linkRequest performs no manual
// check of its own, and decodeJSON never inspects Content-Type, so a plain
// auto-submitting <form enctype="text/plain"> reaches the handler. The handler
// then treats a stashed pending link as authentication for about an hour
// (auth.router.ts:1513-1524) and writes: it overwrites any in-flight account-link
// token and mails the victim's address. The double-submit is the only thing in the
// way, so it must hold with no cookies, no Authorization and no headers at all.
func TestCSRFManualCheckRouteIsEnforcedWithoutAnyCredential(t *testing.T) {
	for _, path := range []string{"/auth/link-request", "/api/auth/link-request"} {
		t.Run(path, func(t *testing.T) {
			// The pure forgery: nothing at all on the request.
			bare := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, bare)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s with zero credentials = %d, want 403", path, rec.Code)
			}

			// An unmirrored CSRF cookie, with and without a session, is still a
			// forgery: the attacker's origin cannot read the cookie to mirror it.
			for _, cookie := range []string{"", AccessTokenCookieName, hostCookiePrefix + AccessTokenCookieName} {
				if got := csrfDrive(t, http.MethodPost, path, cookie); got != http.StatusForbidden {
					t.Errorf("POST %s with access cookie %q = %d, want 403", path, cookie, got)
				}
			}

			// And it passes for a caller that really can read the cookie.
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
			req.Header.Set(CSRFHeaderName, "tok")
			ok := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(ok, req)
			if ok.Code != http.StatusOK {
				t.Errorf("POST %s with a matching pair = %d, want 200: %s", path, ok.Code, ok.Body.String())
			}
		})
	}
}

// TestCSRFManualCheckRouteExemptsARealBearerCredential pins the one condition the
// manual-check carve-out does NOT make unconditional, and the fact that it is a
// deviation rather than a transcription.
//
// The reference gates its hand-written check on `config.csrf.enabled` alone
// (auth.router.ts:1489), with no `usingBearer` term, so it would answer 403
// CSRF_INVALID here. This port exempts a real bearer credential on /link-request as
// it does on every other route. That is safe — Authorization is not CORS-safelisted,
// so a cross-site page cannot set it and has no token to set it to — and it is the
// direction the family contract asks for: wire-contract.md records the reference's
// behaviour as a MISMATCH that breaks native bearer clients, and as [UNTESTED]
// upstream.
//
// Both halves are asserted, because the exemption is only defensible while it is
// keyed on a credential the attacker cannot supply: a *declared* strategy must not
// buy it. That is the #26 property this route must not quietly lose.
func TestCSRFManualCheckRouteExemptsARealBearerCredential(t *testing.T) {
	for _, path := range []string{"/auth/link-request", "/api/auth/link-request"} {
		t.Run(path, func(t *testing.T) {
			// A real bearer credential and no double-submit pair: exempt here,
			// refused by the reference. Deliberate — see the doc comment.
			bearer := httptest.NewRequest(http.MethodPost, path, nil)
			bearer.Header.Set("Authorization", "Bearer abc")
			rec := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, bearer)
			if rec.Code != http.StatusOK {
				t.Errorf("POST %s with a real bearer credential = %d, want 200 (deliberate deviation): %s",
					path, rec.Code, rec.Body.String())
			}

			// The declared strategy header is not a credential and must buy nothing,
			// with or without an unmirrored CSRF cookie. If this ever passed, the
			// exemption above would be reachable by a plain cross-site form post.
			for _, withCookie := range []bool{false, true} {
				declared := httptest.NewRequest(http.MethodPost, path, nil)
				declared.Header.Set(AuthStrategyHeader, AuthStrategyBearer)
				if withCookie {
					declared.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
				}
				got := httptest.NewRecorder()
				csrfHandler(insecureHTTPConfig()).ServeHTTP(got, declared)
				if got.Code != http.StatusForbidden {
					t.Errorf("POST %s with a declared bearer strategy (csrf cookie=%v) = %d, want 403",
						path, withCookie, got.Code)
				}
			}

			// An empty Authorization header is not a credential either.
			empty := httptest.NewRequest(http.MethodPost, path, nil)
			empty.Header.Set("Authorization", "Bearer ")
			blank := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(blank, empty)
			if blank.Code != http.StatusForbidden {
				t.Errorf("POST %s with an empty bearer token = %d, want 403", path, blank.Code)
			}
		})
	}
}

// TestCSRFManualCheckSurvivesAPrefixCollidingBasePath is the regression test for a
// hole the cookie-scoping opened and this file's earlier revisions did not reach.
//
// The middleware is told the mount prefix, never the base path a host mounted it
// under, so it finds the prefix by searching the served path. When the base ends in
// the same segment as the prefix — a group based at /auth with the default /auth
// prefix, which is the most obvious way to write it — the served path is
// /auth/auth/<route> and the leftmost occurrence resolves to "/auth/<route>". That
// string is in neither table, so before this fix POST /auth/auth/link-request fell
// through to the cookie test, carried no cookie, and was not enforced: a pure
// cross-site forgery reached the handler and performed the write. Pinned end to end
// in the wiretest suite as well.
//
// The pre-narrowing code enforced this path by accident — an unrecognised route was
// simply "not exempt", so it was checked. Scoping to cookie authentication turned
// that accident into a hole, which is why the check now reads every resolution.
func TestCSRFManualCheckSurvivesAPrefixCollidingBasePath(t *testing.T) {
	// Every candidate resolution is offered, leftmost first.
	rels, mounted := csrfRelativePaths("/auth/auth/link-request", "/auth")
	if !mounted || len(rels) != 2 || rels[0] != "/auth/link-request" || rels[1] != "/link-request" {
		t.Fatalf("csrfRelativePaths = %q,%v; want [/auth/link-request /link-request],true", rels, mounted)
	}

	// The forgery is refused under a colliding base, a non-colliding base and no
	// base at all.
	for _, path := range []string{
		"/auth/link-request",
		"/api/auth/link-request",
		"/auth/auth/link-request",
		"/auth/auth/auth/link-request",
	} {
		t.Run(path, func(t *testing.T) {
			bare := httptest.NewRequest(http.MethodPost, path, nil)
			rec := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, bare)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s with zero credentials = %d, want 403", path, rec.Code)
			}
			// And it still passes for a caller that can read the cookie, so the fix
			// widened enforcement without breaking the legitimate client.
			ok := httptest.NewRequest(http.MethodPost, path, nil)
			ok.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
			ok.Header.Set(CSRFHeaderName, "tok")
			good := httptest.NewRecorder()
			csrfHandler(insecureHTTPConfig()).ServeHTTP(good, ok)
			if good.Code != http.StatusOK {
				t.Errorf("POST %s with a matching pair = %d, want 200: %s", path, good.Code, good.Body.String())
			}
		})
	}
}

// TestCSRFExemptionIsNotReadFromALaterPrefixOccurrence is the other half of the fix
// above, and the reason enforcement and exemption read the candidate list from
// opposite ends.
//
// Path parameters are part of the path, so an attacker picks some of its segments.
// DELETE <prefix>/linked-accounts/auth/login resolves at its second occurrence to
// "/login", which is exempt. Honouring a later occurrence for *exemptions* would
// therefore let any cookie-authenticated protected route be unprotected by naming
// a provider "auth". Only the mount the middleware was configured with may exempt.
func TestCSRFExemptionIsNotReadFromALaterPrefixOccurrence(t *testing.T) {
	rels, mounted := csrfRelativePaths("/auth/linked-accounts/auth/login", "/auth")
	if !mounted || len(rels) != 2 || rels[1] != "/login" {
		t.Fatalf("csrfRelativePaths = %q,%v; want a second resolution of /login", rels, mounted)
	}
	// A cookie-authenticated DELETE with no mirrored header must still be refused,
	// even though one resolution of its path names an exempt route.
	if got := csrfDrive(t, http.MethodDelete, "/auth/linked-accounts/auth/login", hostCookiePrefix+AccessTokenCookieName); got != http.StatusForbidden {
		t.Errorf("DELETE /auth/linked-accounts/auth/login = %d, want 403: an exempt entry was read from a later prefix occurrence", got)
	}
	// The genuinely exempt route, at the configured mount, is still exempt.
	if got := csrfDrive(t, http.MethodPost, "/auth/login", hostCookiePrefix+AccessTokenCookieName); got != http.StatusOK {
		t.Errorf("POST /auth/login = %d, want 200: the real exemption was lost", got)
	}
}

// csrfDrive posts an unmirrored CSRF cookie, optionally with an access-token
// cookie under the given name. accessCookie == "" means no session at all.
func csrfDrive(t *testing.T, method, path, accessCookie string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "csrf-token", Value: "tok"})
	if accessCookie != "" {
		req.AddCookie(&http.Cookie{Name: accessCookie, Value: "session-value"})
	}
	rec := httptest.NewRecorder()
	csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
	return rec.Code
}

// TestCSRFEnforcementAndAuthGateReadTheSameCookie pins the mismatch the review
// singled out, which the scoping makes load-bearing: the enforcement predicate
// now asks "is there an access cookie", so it must resolve the name exactly as
// the auth gate does. Every name CookieOptions.CookieName can emit must be found
// by CookieValue and by AccessTokenFromRequest, or the two would disagree about
// whether a request is cookie-authenticated — and a request the gate accepts
// would skip the double-submit.
func TestCSRFEnforcementAndAuthGateReadTheSameCookie(t *testing.T) {
	emitted := map[string]bool{}
	for _, o := range []CookieOptions{
		{Secure: false},
		{Secure: true, Path: "/"},
		{Secure: true, Path: ""},
		{Secure: true, Path: "/api"},
		{Secure: true, Path: "/", Domain: "example.com"},
	} {
		emitted[o.CookieName(AccessTokenCookieName)] = true
	}
	// The three prefixes the write side can produce.
	for _, want := range []string{
		AccessTokenCookieName,
		hostCookiePrefix + AccessTokenCookieName,
		secureCookiePrefix + AccessTokenCookieName,
	} {
		if !emitted[want] {
			t.Errorf("CookieName never emits %q; the matrix below is incomplete", want)
		}
	}
	for name := range emitted {
		req := httptest.NewRequest(http.MethodPost, "/auth/add-phone", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: "session-value"})
		if got := CookieValue(req, AccessTokenCookieName); got != "session-value" {
			t.Errorf("CookieValue does not see %q (got %q): enforcement would read a different cookie than the auth gate", name, got)
		}
		if got := AccessTokenFromRequest(req); got != "session-value" {
			t.Errorf("AccessTokenFromRequest does not see %q (got %q)", name, got)
		}
		// The predicate itself, not just the helper it is built from.
		if !csrfEnforced(req, "/auth") {
			t.Errorf("csrfEnforced is false for a request authenticated by %q", name)
		}
	}
}

// TestCSRFEmptyCookieValueDoesNotDisableTheCheck covers the degenerate token: a
// present-but-empty CSRF cookie must not make the comparison trivially
// satisfiable by an empty header.
func TestCSRFEmptyCookieValueDoesNotDisableTheCheck(t *testing.T) {
	for _, header := range []string{"", "   ", "anything"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/add-phone", nil)
		req.AddCookie(&http.Cookie{Name: "csrf-token", Value: ""})
		// Cookie-authenticated, so the route is enforced at all.
		req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
		req.Header.Set(AuthStrategyHeader, AuthStrategyBearer) // suppress minting
		if header != "" {
			req.Header.Set(CSRFHeaderName, header)
		}
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("empty csrf cookie with header %q = %d, want 403", header, rec.Code)
		}
	}
}

// TestCSRFDistributionUnchanged re-pins the distribution half by test: a caller
// with no readable CSRF cookie is minted one, a bearer *client* is not, and an
// existing cookie is never rotated. Narrowing enforcement must not move any of
// this — "bearer requests set no cookies" is asserted of whole responses across
// the adapter suites.
func TestCSRFDistributionUnchanged(t *testing.T) {
	t.Run("mints for a plain caller", func(t *testing.T) {
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/me", nil))
		c := findCookie(rec, "csrf-token")
		if c == nil || len(c.Value) != 32 {
			t.Fatalf("expected a freshly minted 32-hex cookie, got %v", c)
		}
	})
	t.Run("mints for a cookie-authenticated caller", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if c := findCookie(rec, "csrf-token"); c == nil || len(c.Value) != 32 {
			t.Fatalf("expected a freshly minted 32-hex cookie, got %v", c)
		}
	})
	t.Run("mints nothing for a declared bearer client", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set(AuthStrategyHeader, AuthStrategyBearer)
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if c := findCookie(rec, "csrf-token"); c != nil {
			t.Fatalf("declared bearer client got a cookie: %s", c.String())
		}
	})
	t.Run("mints nothing for a real bearer credential", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer abc")
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if c := findCookie(rec, "csrf-token"); c != nil {
			t.Fatalf("bearer credential got a cookie: %s", c.String())
		}
	})
	t.Run("does not rotate an existing cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: hostCookiePrefix + "csrf-token", Value: "existing"})
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if c := findCookie(rec, "csrf-token"); c != nil {
			t.Fatalf("rotated a readable cookie: %s", c.String())
		}
	})
	t.Run("mints on a refused request too", func(t *testing.T) {
		// Distribution runs before enforcement, so even the request that is about
		// to be refused is handed a cookie it can mirror on the retry.
		req := httptest.NewRequest(http.MethodPost, "/auth/add-phone", nil)
		req.AddCookie(&http.Cookie{Name: AccessTokenCookieName, Value: "session-value"})
		rec := httptest.NewRecorder()
		csrfHandler(insecureHTTPConfig()).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if c := findCookie(rec, "csrf-token"); c == nil || len(c.Value) != 32 {
			t.Fatalf("a refused request was not handed a cookie to retry with: %v", c)
		}
	})
}

// TestCSRFExemptionTableIsKeyedOnMethodAndPath drives the property straight
// through the middleware for every entry: the listed method passes, and a
// different mutating method on the same path is still checked.
func TestCSRFExemptionTableIsKeyedOnMethodAndPath(t *testing.T) {
	for entry := range csrfExemptRoutes {
		t.Run(entry.method+entry.path, func(t *testing.T) {
			if got := statusFor(t, entry.method, "/auth"+entry.path); got != http.StatusOK {
				t.Errorf("%s %s = %d, want 200: table entry is not honoured", entry.method, entry.path, got)
			}
			// A mutating method the table does not list for this path.
			other := http.MethodDelete
			if entry.method == http.MethodDelete {
				other = http.MethodPost
			}
			if csrfExemptRoutes[csrfExemption{method: other, path: entry.path}] {
				return // genuinely exempt under both methods
			}
			// statusFor is cookie-authenticated, so the request really is enforced
			// and the 403 can only come from the table missing the method.
			if got := statusFor(t, other, "/auth"+entry.path); got != http.StatusForbidden {
				t.Errorf("%s %s = %d, want 403: the key is not carrying the method", other, entry.path, got)
			}
		})
	}
}
