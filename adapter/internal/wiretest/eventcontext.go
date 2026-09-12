package wiretest

import (
	"context"
	"net/http"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The request-event-context carrier: auth.EventContextMiddleware, this port of
// the dev line's getRequestEventContext (node-auth auth.router.ts:402-416).
//
// The reference has no middleware here because it has no need of one — its
// publisher is handed the *Request and reads the three headers at the moment it
// publishes (node-auth auth.router.ts:418-434). A Service method in this port
// sees a context.Context and nothing else, so the read moves to the adapter and
// the value travels on the request context. That split is only sound if every
// adapter performs it, which is why these cases live in the shared suite rather
// than beside one adapter: three routers out of four would make an event's
// correlation id depend on which router the host chose, and would be invisible
// to every other group here.
//
// Five things to pin, and the first two are the ones a regression would break:
// the carrier reaches the service layer at all, on every adapter and through
// each framework's own request-swapping (gin reassigns c.Request, echo calls
// SetRequest — a guard that dropped either would install a carrier nothing
// downstream could see); and it is installed outermost, ahead of the
// rate-limiter slot, which is where EventContextMiddleware says it belongs.
// Then the three header rules: an absent header is empty and not invented, a
// repeated one takes its first value, and HTTPConfig.ClientIP overrides the
// socket address when the host sets it.
//
// Nothing here publishes an event, because nothing in this library publishes
// one yet. The carrier is asserted where it can be observed — inside the store
// the login path calls — which is also where the events will be published from
// once Service publishes them.

// eventContextStore records the carrier as the service layer sees it.
//
// It embeds the interface rather than a concrete store so the wrapper is three
// lines and one override: GetUserByEmail is the first store call on the login
// path (login_2fa.go, loginPassword) and runs whether or not the account
// exists, so a login with an unknown address is enough to observe the context
// and needs no seeding.
type eventContextStore struct {
	auth.UserStore
	mu    sync.Mutex
	seen  []auth.EventContext
	found []bool
}

func (s *eventContextStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	ec, ok := auth.EventContextFromContext(ctx)
	s.mu.Lock()
	s.seen = append(s.seen, ec)
	s.found = append(s.found, ok)
	s.mu.Unlock()
	return s.UserStore.GetUserByEmail(ctx, email, tenantID)
}

// last returns the single observation, failing when there is not exactly one.
func (s *eventContextStore) last(t *testing.T) auth.EventContext {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) != 1 {
		t.Fatalf("store observed %d contexts, want exactly 1: the login path did not reach the store, "+
			"or reached it more than once and the assertions below would be ambiguous", len(s.seen))
	}
	if !s.found[0] {
		t.Fatal("no auth.EventContext on the context the service was called with: this adapter's guard " +
			"does not install auth.EventContextMiddleware, or installs it on a request it then discards")
	}
	return s.seen[0]
}

// newEventContextEnv mounts an adapter over a recording user store.
func newEventContextEnv(t *testing.T, mount Mounter, cfg auth.HTTPConfig) (*Env, *eventContextStore) {
	t.Helper()
	store := &eventContextStore{UserStore: auth.NewMemoryUserStore()}
	return NewEnv(t, mount, cfg, auth.WithUserStore(store)), store
}

// loginRequest builds the POST /login this group observes. The credentials are
// never valid — the route answers 401 and that is fine, because the store call
// this group asserts on happens before the password is compared.
func (e *Env) eventContextLogin() *http.Request {
	return e.Request(http.MethodPost, "/login", map[string]any{
		"email": "carrier@example.com", "password": "password1",
	})
}

func testEventContext(t *testing.T, mount Mounter) {
	t.Run("ReachesTheServiceLayer", func(t *testing.T) {
		env, store := newEventContextEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.eventContextLogin()
		req.Header.Set(auth.CorrelationIDHeader, "corr-9e1f")
		req.Header.Set("User-Agent", "family-client/1.9.0")
		env.Do(req)

		got := store.last(t)
		if got.CorrelationID != "corr-9e1f" {
			t.Errorf("CorrelationID = %q, want %q from %s", got.CorrelationID, "corr-9e1f", auth.CorrelationIDHeader)
		}
		if got.UserAgent != "family-client/1.9.0" {
			t.Errorf("UserAgent = %q, want the User-Agent header", got.UserAgent)
		}
		// httptest.NewRequest's RemoteAddr is 192.0.2.1:1234, so the default
		// resolution — socket peer, port stripped — is exactly assertable.
		if got.IP != "192.0.2.1" {
			t.Errorf("IP = %q, want the socket peer 192.0.2.1 with its port stripped", got.IP)
		}
	})

	// The carrier is installed ahead of the rate-limiter slot, which is the
	// position EventContextMiddleware documents: it cannot refuse a request and
	// the two middlewares after it can, so host code in the slot must find the
	// correlation id already there. A limiter is the only host-supplied handler
	// in the chain, which makes it the only place this ordering is observable.
	t.Run("IsOutermostInTheGuardChain", func(t *testing.T) {
		var (
			mu    sync.Mutex
			found bool
			seen  auth.EventContext
		)
		cfg := auth.DefaultHTTPConfig()
		cfg.RateLimiter = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ec, ok := auth.EventContextFromContext(r.Context())
				mu.Lock()
				found, seen = ok, ec
				mu.Unlock()
				next.ServeHTTP(w, r)
			})
		}
		env, _ := newEventContextEnv(t, mount, cfg)
		req := env.eventContextLogin()
		req.Header.Set(auth.CorrelationIDHeader, "corr-outer")
		env.Do(req)

		mu.Lock()
		defer mu.Unlock()
		if !found {
			t.Fatal("the rate-limiter slot ran before the event-context carrier was installed: " +
				"host code in the slot cannot see the correlation id")
		}
		if seen.CorrelationID != "corr-outer" {
			t.Errorf("limiter saw CorrelationID = %q, want %q", seen.CorrelationID, "corr-outer")
		}
	})

	// An absent correlation header is an empty field, never a generated id. The
	// reference does not mint one either (node-auth auth.router.ts:407-408,
	// :412), and an id this library invented would join nothing to anything
	// while being indistinguishable from one a caller's gateway assigned.
	t.Run("AbsentHeadersAreEmptyNotInvented", func(t *testing.T) {
		env, store := newEventContextEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.eventContextLogin()
		req.Header.Del("User-Agent")
		env.Do(req)

		got := store.last(t)
		if got.CorrelationID != "" {
			t.Errorf("CorrelationID = %q for a request that sent no %s, want empty",
				got.CorrelationID, auth.CorrelationIDHeader)
		}
		if got.UserAgent != "" {
			t.Errorf("UserAgent = %q for a request that sent none, want empty", got.UserAgent)
		}
		if got.IP == "" {
			t.Error("IP is empty: the address does not depend on any header and must still be resolved")
		}
	})

	// A header sent twice takes its first value: the reference's
	// `Array.isArray(h) ? h[0] : h` (node-auth auth.router.ts:407-408).
	t.Run("RepeatedHeaderTakesTheFirstValue", func(t *testing.T) {
		env, store := newEventContextEnv(t, mount, auth.DefaultHTTPConfig())
		req := env.eventContextLogin()
		req.Header.Add(auth.CorrelationIDHeader, "first")
		req.Header.Add(auth.CorrelationIDHeader, "second")
		env.Do(req)

		if got := store.last(t).CorrelationID; got != "first" {
			t.Errorf("CorrelationID = %q, want %q — a repeated header takes its first value, "+
				"not its last and not the two joined", got, "first")
		}
	})

	// HTTPConfig.ClientIP is the trust-proxy seam: Express's req.ip depends on
	// an application setting this port cannot see, so the host supplies the
	// resolution and its answer is used as given.
	t.Run("ClientIPOverridesTheSocketAddress", func(t *testing.T) {
		cfg := auth.DefaultHTTPConfig()
		cfg.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") }
		env, store := newEventContextEnv(t, mount, cfg)
		req := env.eventContextLogin()
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
		env.Do(req)

		if got := store.last(t).IP; got != "203.0.113.7" {
			t.Errorf("IP = %q, want the value HTTPConfig.ClientIP returned; the socket peer "+
				"must not win over a host-supplied resolution", got)
		}
	})
}
