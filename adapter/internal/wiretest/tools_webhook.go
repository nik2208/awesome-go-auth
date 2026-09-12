package wiretest

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// POST <tools>/webhook/{provider} for all four adapters: the route with no
// guard, and the seam that keeps a JavaScript engine out of this repository.
//
// Three things are pinned here and each is a decision somebody could undo by
// accident:
//
//   - That the guard is *not* in front of it. A refusing ToolsAccess must not
//     refuse this route, because the reference spreads no protect onto it
//     (tools.router.ts:251) and a provider has no session to present. The case
//     below configures a guard that would refuse everything and asserts the
//     webhook still lands.
//   - What crosses the seam. The runner is handed the script, the body and the
//     resolved action allowlist — and the allowlist is the intersection of the
//     administrator's global list with the webhook's own, resolved in the core
//     from the core's settings store. A change that widened it, or that moved
//     the resolution across the seam, fails here.
//   - That a script which cannot be run is refused rather than acknowledged.
//     Both halves — a nil runner and a runner that fails — each answering 400
//     with nothing tracked, so the provider redelivers.

// toolsScriptRunner records what it was given and answers what the case told it
// to. The mutex is for the adapters that serve on their own goroutines.
type toolsScriptRunner struct {
	mu       sync.Mutex
	calls    int
	last     auth.InboundScriptRequest
	deadline bool
	result   auth.InboundScriptResult
	emit     bool
	err      error
}

func (r *toolsScriptRunner) RunInboundScript(
	ctx context.Context, req auth.InboundScriptRequest,
) (auth.InboundScriptResult, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.last = req
	_, r.deadline = ctx.Deadline()
	return r.result, r.emit, r.err
}

func (r *toolsScriptRunner) snapshot() (int, auth.InboundScriptRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.last, r.deadline
}

// toolsFailingSettings is a settings store whose read fails, which is the
// `.catch(() => ({}))` case: no actions rather than all of them.
type toolsFailingSettings struct{}

func (toolsFailingSettings) GetSettings(context.Context) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errors.New("settings store unavailable")
}

func (toolsFailingSettings) UpdateSettings(context.Context, auth.AuthSettings) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errors.New("settings store unavailable")
}

// toolsInboundStore is a MemoryWebhookStore holding one inbound configuration,
// with the id the store assigned it — AddWebhook owns the identifier and
// ignores the one it is handed, so the only way to know it is to read it back.
func toolsInboundStore(t *testing.T, config auth.WebhookConfig) (*auth.MemoryWebhookStore, string) {
	t.Helper()
	store := auth.NewMemoryWebhookStore()
	stored, err := store.AddWebhook(context.Background(), config)
	if err != nil {
		t.Fatalf("AddWebhook: %v", err)
	}
	return store, stored.ID
}

// toolsWebhookRequest is a POST to one named provider with a JSON body. It is
// toolsPost with the provider spelled out rather than probed, because these
// cases care which provider they name.
func toolsWebhookRequest(env *Env, provider, body string) *http.Request {
	return toolsPost(env, auth.ToolsWebhookPath+"/"+provider, body)
}

// toolsInboundConfig is the configuration every scripted case starts from: one
// provider, one script, two allowed actions and a duplicate.
func toolsInboundConfig() auth.WebhookConfig {
	return auth.WebhookConfig{
		ID:             "ignored-by-the-store",
		URL:            "https://example.test/unused",
		Events:         []string{"*"},
		Provider:       "stripe",
		AllowedActions: []string{"billing.cancelSubscription", "user.suspend", "billing.cancelSubscription"},
		JSScript:       "result = { event: 'identity.tenant.user.removed' };",
	}
}

func testToolsInboundWebhook(t *testing.T, mount Mounter) {
	scriptConfig := toolsInboundConfig()

	// scriptedEnv mounts the router with that configuration, the given runner and
	// a settings store holding the enabled ids. It returns the recorder as well,
	// because what a case usually wants to know is whether anything was tracked,
	// and the webhook id the store assigned, which is what crosses the seam.
	type scripted struct {
		env       *Env
		rec       *toolsRecorder
		webhookID string
	}
	scriptedEnv := func(t *testing.T, runner auth.InboundScriptRunner, enabled []string,
		edit ...func(*auth.ToolsOptions),
	) scripted {
		t.Helper()
		settings := auth.NewMemorySettingsStore()
		if enabled != nil {
			if _, err := settings.UpdateSettings(context.Background(),
				auth.AuthSettings{EnabledWebhookActions: enabled}); err != nil {
				t.Fatalf("UpdateSettings: %v", err)
			}
		}
		store, id := toolsInboundStore(t, scriptConfig)
		cfg, rec := toolsRecordingConfig(t, append([]func(*auth.ToolsOptions){func(o *auth.ToolsOptions) {
			o.InboundWebhooks = store
			o.ScriptRunner = runner
			o.OnWebhook = nil
		}}, edit...)...)
		return scripted{env: NewEnv(t, mount, cfg, auth.WithSettingsStore(settings)), rec: rec, webhookID: id}
	}

	t.Run("neither a store nor a callback means no route", func(t *testing.T) {
		// `if (webhook && (options.onWebhook || options.webhookStore?.findByProvider))`
		// (tools.router.ts:250). The flag alone mounts nothing, because there
		// would be nothing to do with a body.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.OnWebhook = nil }))
		assertToolsUnrouted(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")))
	})

	t.Run("the webhook flag gates it", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.DisableWebhook = true }))
		assertToolsUnrouted(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")))
	})

	t.Run("the document describes it even when it is not mounted", func(t *testing.T) {
		// The reference's quirk, reproduced deliberately: the path item is
		// emitted under the webhook flag alone (openapi.ts:1525) while the route
		// wants a store or a callback as well (:250). So this configuration
		// documents an operation that answers 404 — and a consumer generating a
		// client from either tree still gets the same operation list, which is
		// the point.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.OnWebhook = nil }))
		paths := toolsDocumentPaths(t, toolsDocument(t, env))
		if _, ok := paths[env.Config.ToolsPath()+auth.ToolsWebhookPath+"/{provider}"]; !ok {
			t.Errorf("the document does not describe the inbound webhook")
		}
		assertToolsUnrouted(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")))
	})

	t.Run("no guard runs in front of it", func(t *testing.T) {
		// The whole posture of this route in one case. ToolsAccess is configured
		// with a guard that refuses everything; the webhook still lands, because
		// the reference registers this route with no protect at all (:251).
		refused := 0
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					refused++
					w.WriteHeader(http.StatusForbidden)
				})
			})
		}))
		rec := env.Do(toolsWebhookRequest(env, "stripe", `{"type":"ping"}`))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "ok")
		if refused != 0 {
			t.Errorf("the guard ran %d times on the inbound webhook, want 0", refused)
		}
		// And nothing is set on the way out: this router carries none of the auth
		// router's middleware.
		AssertNoCookies(t, rec)
	})

	t.Run("the provider is the path parameter", func(t *testing.T) {
		var seen []string
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(_ *http.Request, provider string, _ []byte) (auth.InboundScriptResult, bool, error) {
				seen = append(seen, provider)
				return auth.InboundScriptResult{}, false, nil
			}
		}))
		for _, provider := range []string{"stripe", "github", "a%20b"} {
			AssertStatus(t, env.Do(toolsWebhookRequest(env, provider, "{}")), http.StatusOK)
		}
		want := []string{"stripe", "github", "a b"}
		if strings.Join(seen, ",") != strings.Join(want, ",") {
			t.Errorf("providers = %v, want %v (the parameter is decoded after the split)", seen, want)
		}
	})

	t.Run("a missing or multi-segment provider is not routed", func(t *testing.T) {
		// router.post('/webhook/:provider') matches exactly one segment.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, path := range []string{
			auth.ToolsWebhookPath,
			auth.ToolsWebhookPath + "/",
			auth.ToolsWebhookPath + "/a/b",
		} {
			assertToolsUnrouted(t, env.Do(httptest.NewRequest(http.MethodPost, env.Config.ToolsPath()+path, nil)))
		}
	})

	t.Run("GET is not routed", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t))
		assertToolsUnrouted(t, env.Do(httptest.NewRequest(http.MethodGet,
			env.Config.ToolsPath()+auth.ToolsWebhookPath+"/stripe", nil)))
	})

	t.Run("the runner is handed the script, the body and the resolved actions", func(t *testing.T) {
		// The seam, in one assertion. The allowlist is the intersection of the
		// settings store's enabled ids with the configuration's allowed ids, in
		// the configuration's order and deduplicated, which is what
		// `new Set(allowedIds.filter(id => enabledIds.includes(id)))` produces
		// (webhook-action.ts:105).
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, []string{"user.suspend", "billing.cancelSubscription", "tenant.delete"})
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", `{"type":"ping","n":1}`)), http.StatusOK)

		calls, req, deadline := runner.snapshot()
		if calls != 1 {
			t.Fatalf("the runner was called %d times, want 1", calls)
		}
		if req.Provider != "stripe" || req.WebhookID != s.webhookID || req.Script != scriptConfig.JSScript {
			t.Errorf("request = %#v, want the provider, the config id and the script verbatim", req)
		}
		if string(req.Body) != `{"type":"ping","n":1}` {
			t.Errorf("body = %s, want the bytes as sent", req.Body)
		}
		want := []string{"billing.cancelSubscription", "user.suspend"}
		if strings.Join(req.Actions, ",") != strings.Join(want, ",") {
			t.Errorf("actions = %v, want %v", req.Actions, want)
		}
		if !deadline {
			t.Errorf("the runner was called with no deadline; ToolsOptions.ScriptTimeout must bound it")
		}
	})

	t.Run("an action the administrator has not enabled does not cross", func(t *testing.T) {
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, []string{"user.suspend"})
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}")), http.StatusOK)
		if _, req, _ := runner.snapshot(); strings.Join(req.Actions, ",") != "user.suspend" {
			t.Errorf("actions = %v, want only the enabled one", req.Actions)
		}
	})

	t.Run("no settings store means no actions at all", func(t *testing.T) {
		// `options.settingsStore ? … : {}` and then `?? []` (:261-264). A
		// deployment that never configured one has an empty global allowlist
		// forever, so no script can ever call anything.
		runner := &toolsScriptRunner{}
		store, _ := toolsInboundStore(t, scriptConfig)
		cfg, _ := toolsRecordingConfig(t, func(o *auth.ToolsOptions) {
			o.InboundWebhooks = store
			o.ScriptRunner = runner
			o.OnWebhook = nil
		})
		env := NewEnv(t, mount, cfg)
		AssertStatus(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")), http.StatusOK)
		if _, req, _ := runner.snapshot(); len(req.Actions) != 0 {
			t.Errorf("actions = %v, want none", req.Actions)
		}
	})

	t.Run("a failing settings store fails into an empty allowlist", func(t *testing.T) {
		// The `.catch(() => ({}))` (:262). It reads as failing open and is
		// failing closed: an empty object has no enabledWebhookActions, so the
		// intersection is empty. The script still runs.
		runner := &toolsScriptRunner{}
		store, _ := toolsInboundStore(t, scriptConfig)
		cfg, _ := toolsRecordingConfig(t, func(o *auth.ToolsOptions) {
			o.InboundWebhooks = store
			o.ScriptRunner = runner
			o.OnWebhook = nil
		})
		env := NewEnv(t, mount, cfg, auth.WithSettingsStore(toolsFailingSettings{}))
		AssertStatus(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")), http.StatusOK)
		calls, req, _ := runner.snapshot()
		if calls != 1 {
			t.Fatalf("the runner was called %d times, want 1 — a settings failure must not stop the script", calls)
		}
		if len(req.Actions) != 0 {
			t.Errorf("actions = %v, want none", req.Actions)
		}
	})

	t.Run("a declared result is tracked", func(t *testing.T) {
		// `if (result) { await tools.track(result.event, result.data, {userId,
		// tenantId}) }` (:317-322).
		runner := &toolsScriptRunner{
			emit: true,
			result: auth.InboundScriptResult{
				Event:    "identity.tenant.user.removed",
				Data:     map[string]any{"subscription": "sub_1"},
				UserID:   "user-9",
				TenantID: "tenant-9",
			},
		}
		s := scriptedEnv(t, runner, []string{"user.suspend"})
		rec := s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}"))
		AssertStatus(t, rec, http.StatusOK)
		AssertKeys(t, Body(t, rec), "ok")

		got := s.rec.onlyTracked(t)
		if got.EventName != "identity.tenant.user.removed" || got.UserID != "user-9" || got.TenantID != "tenant-9" {
			t.Errorf("tracked = %#v, want the result's event and principals", got)
		}
		if got.Meta["subscription"] != "sub_1" {
			t.Errorf("tracked data = %#v, want the result's data", got.Meta)
		}
		// Four identifiers the reference does not pass and this route must not
		// invent: the request they would describe is a stranger's.
		if got.IP != "" || got.UserAgent != "" || got.SessionID != "" || got.CorrelationID != "" {
			t.Errorf("tracked = %#v, want no ip, user agent, session or correlation id", got)
		}
	})

	t.Run("a script that declares nothing is acknowledged in silence", func(t *testing.T) {
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, []string{"user.suspend"})
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}")), http.StatusOK)
		if events := s.rec.tracked(t); len(events) != 0 {
			t.Errorf("tracked %d events, want none", len(events))
		}
	})

	t.Run("a script that declared nothing falls through to OnWebhook", func(t *testing.T) {
		// `if (result === null && options.onWebhook)` (:308-310).
		runner := &toolsScriptRunner{}
		called := 0
		s := scriptedEnv(t, runner, nil, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(_ *http.Request, _ string, _ []byte) (auth.InboundScriptResult, bool, error) {
				called++
				return auth.InboundScriptResult{Event: "identity.fallback"}, true, nil
			}
		})
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}")), http.StatusOK)
		if called != 1 {
			t.Fatalf("OnWebhook ran %d times, want 1", called)
		}
		if got := s.rec.onlyTracked(t); got.EventName != "identity.fallback" {
			t.Errorf("tracked = %#v, want the fallback's event", got)
		}
	})

	t.Run("a nil runner refuses rather than acknowledges", func(t *testing.T) {
		// The fail-closed decision. A 200 here would tell the provider the event
		// was handled, and a provider that has been told that does not send it
		// again — the event would be gone, silently and permanently.
		called := 0
		s := scriptedEnv(t, nil, []string{"user.suspend"}, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(_ *http.Request, _ string, _ []byte) (auth.InboundScriptResult, bool, error) {
				called++
				return auth.InboundScriptResult{}, false, nil
			}
		})
		rec := s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}"))
		AssertStatus(t, rec, http.StatusBadRequest)
		if body := Body(t, rec); body["error"] != "Webhook processing failed" {
			t.Errorf("body = %#v, want the reference's single failure message", body)
		}
		if called != 0 {
			t.Errorf("OnWebhook ran %d times; a script that could not run must not fall through", called)
		}
		if events := s.rec.tracked(t); len(events) != 0 {
			t.Errorf("tracked %d events, want none", len(events))
		}
	})

	t.Run("a runner that fails refuses too", func(t *testing.T) {
		// The same rule for the same reason: a runner error means the script did
		// not run to completion, and the deployment does not know what it would
		// have decided. A script that *threw* is not this case — a runner reports
		// that as "no result", because the reference acknowledges it.
		runner := &toolsScriptRunner{err: errors.New("runner unreachable")}
		s := scriptedEnv(t, runner, nil)
		rec := s.env.Do(toolsWebhookRequest(s.env, "stripe", "{}"))
		AssertStatus(t, rec, http.StatusBadRequest)
		if body := rec.Body.String(); strings.Contains(body, "unreachable") {
			t.Errorf("the failure describes the runner to the caller: %s", body)
		}
		if events := s.rec.tracked(t); len(events) != 0 {
			t.Errorf("tracked %d events, want none", len(events))
		}
	})

	t.Run("a deactivated configuration still runs its script", func(t *testing.T) {
		// The reproduced trap. FindByProvider does not filter on IsActive and
		// this caller tests for a jsScript alone (:257-259), so deactivating a
		// webhook stops its outgoing deliveries and leaves its inbound script
		// running. U9 stated it on the interface; this is where it is observable.
		inactive := scriptConfig
		inactive.IsActive = new(bool) // false
		runner := &toolsScriptRunner{}
		store, _ := toolsInboundStore(t, inactive)
		cfg, _ := toolsRecordingConfig(t, func(o *auth.ToolsOptions) {
			o.InboundWebhooks = store
			o.ScriptRunner = runner
			o.OnWebhook = nil
		})
		env := NewEnv(t, mount, cfg)
		AssertStatus(t, env.Do(toolsWebhookRequest(env, "stripe", "{}")), http.StatusOK)
		if calls, _, _ := runner.snapshot(); calls != 1 {
			t.Errorf("the runner was called %d times, want 1 — IsActive is not read on this path", calls)
		}
	})

	t.Run("a provider with no configuration reaches OnWebhook", func(t *testing.T) {
		runner := &toolsScriptRunner{}
		called := 0
		s := scriptedEnv(t, runner, nil, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(_ *http.Request, _ string, _ []byte) (auth.InboundScriptResult, bool, error) {
				called++
				return auth.InboundScriptResult{}, false, nil
			}
		})
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "github", "{}")), http.StatusOK)
		if calls, _, _ := runner.snapshot(); calls != 0 {
			t.Errorf("the runner was called %d times for a provider with no configuration, want 0", calls)
		}
		if called != 1 {
			t.Errorf("OnWebhook ran %d times, want 1", called)
		}
	})

	t.Run("OnWebhook is handed the request and the bytes", func(t *testing.T) {
		// Which is what a signature check needs: this route authenticates nothing,
		// and the header the document advertises is verified by nobody.
		var gotBody, gotHeader string
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(r *http.Request, _ string, body []byte) (auth.InboundScriptResult, bool, error) {
				gotBody = string(body)
				gotHeader = r.Header.Get("X-Hub-Signature-256")
				return auth.InboundScriptResult{}, false, nil
			}
		}))
		req := toolsWebhookRequest(env, "stripe", `{"id":"evt_1"}`)
		req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
		AssertStatus(t, env.Do(req), http.StatusOK)
		if gotBody != `{"id":"evt_1"}` {
			t.Errorf("body = %q, want the bytes as sent", gotBody)
		}
		if gotHeader != "sha256=deadbeef" {
			t.Errorf("signature header = %q, want it readable from the request", gotHeader)
		}
	})

	t.Run("an OnWebhook that fails is the 400", func(t *testing.T) {
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) {
			o.OnWebhook = func(*http.Request, string, []byte) (auth.InboundScriptResult, bool, error) {
				return auth.InboundScriptResult{}, false, errors.New("signature mismatch")
			}
		}))
		rec := env.Do(toolsWebhookRequest(env, "stripe", "{}"))
		AssertStatus(t, rec, http.StatusBadRequest)
		if body := Body(t, rec); body["error"] != "Webhook processing failed" {
			t.Errorf("body = %#v, want the reference's single failure message", body)
		}
	})

	t.Run("an empty body is an empty object", func(t *testing.T) {
		// express.json() leaves an empty body as {}, and a provider pinging an
		// endpoint should reach the same script it otherwise would.
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, nil)
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", "")), http.StatusOK)
		if _, req, _ := runner.snapshot(); string(req.Body) != "{}" {
			t.Errorf("body = %s, want {}", req.Body)
		}
	})

	t.Run("a body that is not JSON is refused", func(t *testing.T) {
		// express.json() answers before the handler there; here the route reads
		// the body itself, so the refusal is the route's own 400. Its `strict`
		// option defaults to true, which is why a bare scalar is refused as well.
		env := NewEnv(t, mount, toolsConfig(t))
		for _, body := range []string{"not json", `{"unterminated":`, `"a string"`, "5"} {
			AssertStatus(t, env.Do(toolsWebhookRequest(env, "stripe", body)), http.StatusBadRequest)
		}
	})

	t.Run("a body over the limit is refused", func(t *testing.T) {
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, nil, func(o *auth.ToolsOptions) { o.WebhookMaxBytes = 64 })
		big := `{"pad":"` + strings.Repeat("x", 200) + `"}`
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", big)), http.StatusBadRequest)
		if calls, _, _ := runner.snapshot(); calls != 0 {
			t.Errorf("the runner was called %d times for an oversized body, want 0", calls)
		}
		// And a body under it still lands.
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", `{"ok":1}`)), http.StatusOK)
	})

	t.Run("the body reaches the runner byte for byte", func(t *testing.T) {
		// Raw rather than decoded: a deployment whose script cares about key
		// order, number formatting or a duplicated key sees what was sent, and a
		// signature computed over those bytes still verifies.
		runner := &toolsScriptRunner{}
		s := scriptedEnv(t, runner, nil)
		body := `{"b":1,"a":2,"a":3,"n":1.50,"big":12345678901234567890}`
		AssertStatus(t, s.env.Do(toolsWebhookRequest(s.env, "stripe", body)), http.StatusOK)
		if _, req, _ := runner.snapshot(); !bytes.Equal(req.Body, []byte(body)) {
			t.Errorf("body = %s, want %s", req.Body, body)
		}
	})
}
