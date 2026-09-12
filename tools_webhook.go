package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// POST <tools>/webhook/{provider}, the inbound webhook (tools.router.ts:250-326),
// and InboundScriptRunner, the seam that runs its scripts somewhere else.
//
// This is the one route of this router with no guard in front of it, there and
// here. The reference registers it with no ...protect at all (:251) and its
// OpenAPI operation carries no security entry (openapi.ts:1526-1563), because
// the caller is a third-party provider that has no session to present: whatever
// authentication this route has is the provider's own signature over the body,
// and nothing in the reference verifies one. See "What is not authenticated"
// below before mounting it.
//
// # The decision this file exists to implement
//
// The reference executes administrator-authored JavaScript in a node vm:
//
//	const wrappedScript = `(async () => { ${config.jsScript} })()`;
//	const sandbox = vm.createContext({ body: req.body, actions, result: null, console });
//	const returnValue = vm.runInContext(wrappedScript, sandbox, { timeout: 5_000 });
//
// (:269-292). This package will not do that, and not because it is hard. The
// dependency rule here is stdlib plus golang.org/x/crypto, and a JavaScript
// engine is not going to be the exception — every Go engine is either cgo
// around a C++ VM or a large pure-Go interpreter, and both would put script an
// administrator typed into an admin form in the same address space as the
// signing keys, the session store and the password hashes, with a sandbox
// written by someone else as the only boundary. node's own vm module documents
// that it is not a security mechanism.
//
// The decision taken by the repository owner on 2026-09-12 is therefore: the
// core exposes a seam, and the product implements it with a dedicated Lambda
// whose IAM role is the real sandbox. What is designed here is the seam, and
// the whole design is one sentence — the core resolves policy and nothing else,
// the runner executes and nothing else:
//
//   - Into the runner: the script, the request body, and the already-resolved
//     action allowlist. Nothing else. There is no field for the webhook's
//     secret, none for the settings store, none for the request headers, and
//     none for anything holding a method this process could be made to call.
//     Every member is a value encoding/json can write, because the product's
//     implementation puts this struct on the wire.
//   - Out of the runner: the reference's own result — an event name and three
//     optional members — or nothing at all.
//
// # The actions: declared, not called back
//
// In the reference the script *calls* its actions: `actions` is a
// Record<id, fn> of registered functions (webhook-action.ts:104-115) and a
// script may await one and use what it returns. Out of process that could be
// two things — a round trip per call back into this process, or a one-shot
// exchange — and it is the second, for three reasons that are worth writing
// down because they are the seam's whole shape.
//
// The first is that there is nothing here to call back into. This package has
// no action registry: GET <admin>/api/actions answers an empty list and says
// why (adminListActions in admin_read.go), because registering what a webhook
// may execute is the product's decision and not the library's. A round trip
// would mean inventing a Go ActionRegistry whose functions run in *this*
// process — which is the opposite of the decision above, since the effects
// would then be bounded by this process's credentials rather than by the
// runner's IAM role. The sandbox would be back where it started.
//
// The second is that nothing is lost. In the reference the script and its
// actions share one address space; here they also share one address space —
// the runner's. Return values, control flow, awaiting an action and branching
// on what it answered all still work, because all of it happens on the far
// side of one call. What the core gives up is not semantics, it is the ability
// to implement an action at all, which it never had.
//
// The third is that a declarative allowlist is exactly the part that must not
// move. The intersection of AuthSettings.EnabledWebhookActions and
// WebhookConfig.AllowedActions is policy — the administrator's circuit breaker
// and the per-webhook subset — and it is resolved here, in the core, from the
// core's own settings store, and handed across as a closed list of ids. A
// runner may narrow it further; a runner that widens it is broken. See
// resolveInboundActions for which of the registry's four rules the core can
// apply and which it cannot.
//
// # What is not authenticated
//
// Nothing about the caller. There is no guard (:251), no signature check
// anywhere in the reference's handler, and no rate limiter on this router at
// all. The reference's own document advertises an optional
// X-Hub-Signature-256 header (openapi.ts:1540-1546) that no line of its code
// reads — an invitation with nothing behind it, reproduced in the document
// below for the same reason every other quirk is, and worth knowing when you
// read it.
//
// So the provider's signature is the whole authentication story and this
// package verifies none of it. The place to do it is ToolsOptions.OnWebhook,
// which is handed the *http.Request and the exact bytes the signature covers,
// in this process, where the secret is — or a middleware the host wraps the
// mount in. It is deliberately not the runner's job: the runner never receives
// the secret, so it cannot be tricked into verifying anything, and a signature
// checked after the body has crossed a process boundary has been checked too
// late.
//
// Two things the reference leaves to its host are done here, because there is
// no host layer to leave them to: the body is read under a size limit
// (ToolsOptions.WebhookMaxBytes, defaulting to what express.json defaults to)
// and the runner call is given a deadline (ToolsOptions.ScriptTimeout,
// defaulting to the reference's own vm timeout). Both are on the route because
// this route takes a stranger's body with nothing in front of it.
//
// # The order, which is the reference's
//
// Look the provider up, run the script if there is one, fall back to
// onWebhook if the script declared nothing, track whatever came out of either,
// and answer 200 {"ok": true} (:255-322). Every failure the reference can have
// lands in one catch and one answer, 400 {"error": "Webhook processing
// failed"} (:323-325), and a script that *throws* is not one of them: the
// reference logs it, leaves result null, and acknowledges anyway (:293-304).
// That collapse is preserved exactly, and it is the reason the seam separates
// "the script decided nothing" from "the script could not be run" — see
// InboundScriptRunner.

// InboundScriptRunner executes one inbound webhook script somewhere this
// process is not.
//
// It is the port's answer to tools.router.ts:269-292, and the contract is
// deliberately narrow: everything it is given is in InboundScriptRequest,
// everything it may answer is in InboundScriptResult, and both are plain data
// so that an implementation can put them on a wire. The intended implementation
// is a dedicated function in its own execution environment — a Lambda with a
// JavaScript engine, the deployment's own action implementations, and an IAM
// role scoped to exactly what those actions are allowed to touch. That role is
// the sandbox. Nothing else here is one.
//
// # The three answers, and why they are three
//
//   - (result, true, nil) — the script assigned a result. The route tracks it,
//     exactly as the reference does with a sandbox result whose event is a
//     string (:299-301, :317-322).
//   - (zero, false, nil) — the script ran and declared nothing. This covers
//     both of the reference's silent cases: a script that left result null, and
//     a script that *threw*, which the reference logs and then treats as no
//     result (:293-304). A runner must report a script's own exception this
//     way, because the reference acknowledges such a webhook and a provider
//     that retried it would only fail again.
//   - (zero, false, err) — the script could not be run to completion: the
//     runner was unreachable, throttled, misconfigured, or took longer than its
//     deadline. This is not a case the reference has, because an in-process vm
//     cannot fail to be invoked. The route treats it as a refusal: it does not
//     acknowledge, so the provider's own redelivery is preserved and the
//     webhook arrives again once the deployment is fixed.
//
// That split is the single most important thing an implementation has to get
// right. Reporting a script exception as an error turns every bad script into
// an infinite redelivery loop; reporting an invocation failure as "no result"
// silently drops webhooks that the provider believed were delivered and will
// never send again.
//
// # Concurrency and time
//
// RunInboundScript is called once per inbound request, from the request's
// goroutine, and may be called concurrently. ctx already carries the deadline
// ToolsOptions.ScriptTimeout sets, and it is deliberately *not* cancelled when
// the provider hangs up: a script that has already applied half its actions
// must not be abandoned because a caller closed a socket, which is the same
// reasoning WebhookEmitter.Emit applies to an outgoing delivery.
type InboundScriptRunner interface {
	RunInboundScript(ctx context.Context, req InboundScriptRequest) (InboundScriptResult, bool, error)
}

// InboundScriptRequest is everything that crosses into the runner, and the
// absence of everything else is the design.
//
// The JSON names are part of the contract rather than an implementation detail:
// an out-of-process runner encodes this struct, and two implementations that
// spelled it differently would not be interchangeable. They are the sandbox's
// own vocabulary where it has one — `body` and `actions` are the two variables
// the reference puts in scope (:284-289).
type InboundScriptRequest struct {
	// Provider is the path parameter, decoded: the reference's
	// req.params['provider'] (:252). It is a value the caller chose, so a runner
	// that uses it to select a code path must treat it as untrusted input.
	Provider string `json:"provider"`
	// WebhookID is WebhookConfig.ID, for correlating a run with the
	// configuration it came from. The reference has no counterpart — its sandbox
	// knows nothing about which config it came from — and it is here because a
	// run that happens in another process has to be traceable back to a row
	// somebody edited in the admin UI.
	WebhookID string `json:"webhookId,omitempty"`
	// Script is WebhookConfig.JSScript verbatim, unwrapped. The reference wraps
	// it in an async IIFE before evaluating (:269) and that wrapping belongs to
	// whatever evaluates it, not to the transport: a runner that is not a
	// JavaScript engine at all — a WebAssembly module, a container running
	// something else entirely — would have no use for the wrapper.
	Script string `json:"script"`
	// Body is the request body exactly as it arrived, already checked to be
	// valid JSON. It is the sandbox's `body` (:285). Raw rather than decoded so
	// that no re-encoding happens between the provider and the script: a
	// deployment whose script cares about key order, number formatting or a
	// duplicated key sees what was sent.
	Body json.RawMessage `json:"body"`
	// Actions is the resolved allowlist: the ids of the actions this script may
	// call, and the complete list of them. It is the sandbox's `actions` reduced
	// to its keys (:266, :288) — the values, being functions, are what cannot
	// cross a process boundary, and are what the runner supplies.
	//
	// It is a closed list. A runner may drop an id it does not implement or
	// whose dependencies are unmet; a runner that exposes an action not named
	// here has broken the administrator's allowlist, which is the only thing
	// standing between an inbound webhook and the actions it can perform.
	Actions []string `json:"actions"`
}

// InboundScriptResult is the reference's sandbox `result`
// (webhook-store.interface.ts:59-61, read at tools.router.ts:299-301): what the
// script decided should be emitted, or — when the runner answers false — that
// nothing should be.
//
// The four members are the reference's four. There is deliberately no fifth:
// the route tracks with UserID and TenantID alone (:318-321), so a script
// cannot set the IP, the user agent, the session or the correlation id on a
// record. Those belong to a real request and this record has none.
type InboundScriptResult struct {
	// Event is the event name handed to AuthTools.Track. The reference accepts
	// the result when typeof result.event === 'string' (:299), and the empty
	// string passes that test, so a script that declares {event: ''} tracks an
	// event with no name — reproduced, because the emptiness is observable at
	// all four sinks and inventing a refusal here would hide a broken script
	// rather than fix it.
	Event string `json:"event"`
	// Data is the payload. It is a JSON object because Track's is: the reference
	// types its track data as unknown, and this port settled on map[string]any
	// in U21. A runner whose script assigned a non-object — an array, a string —
	// has nothing to put here and should send no data rather than wrap it.
	Data map[string]any `json:"data,omitempty"`
	// UserID and TenantID become TrackOptions.UserID and TenantID (:319-320),
	// which are what decide the topics the tracked event is broadcast to. A
	// script that sets them is naming a principal on a record nothing
	// authenticated, which is worth remembering when reading a telemetry row
	// that came from this route.
	UserID   string `json:"userId,omitempty"`
	TenantID string `json:"tenantId,omitempty"`
}

// DefaultInboundScriptTimeout is the deadline on one RunInboundScript call, and
// ToolsOptions.ScriptTimeout's default. The number is the reference's own
// (tools.router.ts:290): { timeout: 5_000 }.
//
// What it bounds is not the reference's. vm.runInContext's timeout applies to
// synchronous execution, and the script it is given is an async IIFE, which
// returns a promise the moment it first awaits — so in the reference the five
// seconds bound the prefix before the first await, and the route then awaits
// the rest with no deadline at all (:291-299). A script that awaits a hanging
// action hangs that request for as long as the socket lives. Here the deadline
// is on the whole call, which is the one difference this route registers:
// inbound-webhook-script-runs-out-of-process.
const DefaultInboundScriptTimeout = 5 * time.Second

// DefaultInboundWebhookMaxBytes is the largest body this route reads, and
// ToolsOptions.WebhookMaxBytes's default.
//
// The reference's router has no limit of its own because it never reads a body:
// it reads req.body, which is whatever the host's parser left there, and the
// parser every example mounts is express.json()
// (examples/generic-oauth-and-linking.example.ts:198), whose default limit is
// 100kb. This route reads the body itself, so the limit has to live here, and it
// is that number — the same default reached in the only place this port has to
// put it. A deployment whose provider sends more raises it; a body over the
// limit is the route's one failure answer, 400.
const DefaultInboundWebhookMaxBytes int64 = 100 << 10

// HTTPErrWebhookFailed is the inbound webhook's single failure answer:
// res.status(400).json({ error: 'Webhook processing failed' })
// (tools.router.ts:323-325). No code field, because the reference's literal has
// one key.
//
// It is the answer to every failure the reference's catch covers — a store
// lookup that threw, an onWebhook that rejected — and to the two this port adds
// because it reads the body and crosses a process boundary: a body that is not
// JSON or is over the limit, and a script that could not be run. There is
// deliberately no second, more specific status: the reference has exactly one
// failure shape on this route, every provider treats any non-2xx as "not
// delivered and retry later", and a second shape would be a difference a
// caller has to handle for no gain to the caller.
var HTTPErrWebhookFailed = HTTPError{
	Status:  http.StatusBadRequest,
	Message: "Webhook processing failed",
}

// toolsInboundMounted is the reference's registration condition (:250):
//
//	if (webhook && (options.onWebhook || options.webhookStore?.findByProvider))
//
// The feature flag alone is not enough — with neither a callback nor an inbound
// store there is nothing the route could do with a body — so a deployment that
// configures neither gets a 404 rather than an endpoint that acknowledges and
// discards.
//
// A script runner is deliberately *not* part of the condition. A runner with no
// store to find a script in is a configuration that never runs anything, and a
// store with no runner is the fail-closed case documented on
// toolsInboundWebhookHandler: both are misconfigurations, and neither is
// repaired by moving the route's existence around.
func toolsInboundMounted(cfg HTTPConfig) bool {
	return cfg.Tools.Features().Webhook &&
		(cfg.Tools.OnWebhook != nil || cfg.Tools.InboundWebhooks != nil)
}

// toolsInboundWebhookHandler serves POST <tools>/webhook/{provider}
// (tools.router.ts:251-326). Read the head of this file first; what follows is
// the order, and the order is the reference's.
//
// # The one place it fails closed
//
// A configuration whose WebhookConfig carries a JSScript and whose
// ToolsOptions.ScriptRunner is nil answers 400 and tracks nothing. That is a
// choice, and the alternative — skip the script, fall through to OnWebhook,
// answer 200 — is defensible: it is what the reference does when a script
// produces no result, and it keeps a provider from retrying against a
// deployment that will not improve.
//
// It is refused anyway, because the two failures are not the same size. A
// script is how a deployment reacts to an event it does not otherwise see: the
// subscription cancellation that deprovisions a tenant, the payment failure
// that suspends an account. Acknowledging a webhook whose script never ran
// tells the provider the event was handled, and a provider that has been told
// that does not send it again — the event is gone, silently and permanently,
// and the deployment's own state is wrong in a way nothing will correct. A
// refusal costs redeliveries and an entry in someone's provider dashboard, and
// it is recoverable: configure the runner and the backlog arrives.
//
// The same rule covers a runner that returns an error, for the same reason, and
// deliberately does not cover a script that threw — see InboundScriptRunner for
// why those are two answers and not one.
func (a *Auth) toolsInboundWebhookHandler(cfg HTTPConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// req.params['provider'] (:252), through the shared split U23 wrote for
		// the same pattern on track and notify. The switch in ToolsHandler has
		// already matched it, the way the admin router matches its parameterised
		// routes twice; a miss here is unreachable and answers the route's own
		// failure rather than pretending to have a provider.
		provider := toolsPathParam(r, cfg, ToolsWebhookPath)
		if provider == "" {
			WriteHTTPError(w, HTTPErrWebhookFailed)
			return
		}

		body, err := toolsInboundBody(w, r, cfg)
		if err != nil {
			// A body over the limit, or one express.json() would have refused.
			// The reference never reaches its handler in either case: the parser
			// answers first, one layer up.
			a.logInbound(provider, "body rejected: %v", err)
			WriteHTTPError(w, HTTPErrWebhookFailed)
			return
		}

		result, emit, err := a.toolsInboundResult(r, cfg, provider, body)
		if err != nil {
			a.logInbound(provider, "%v", err)
			WriteHTTPError(w, HTTPErrWebhookFailed)
			return
		}

		// if (result) { await tools.track(...) } (:317-322). Four identifiers are
		// deliberately not passed: the record carries no IP, user agent, session
		// or correlation id, because the reference passes none and because none
		// of them would describe anything — the request they would describe is a
		// stranger's.
		if emit {
			cfg.Tools.AuthTools.Track(r.Context(), result.Event, result.Data, TrackOptions{
				UserID:   result.UserID,
				TenantID: result.TenantID,
			})
		}
		// res.status(200).json({ ok: true }) (:322). Note the status: track and
		// notify answer 202, this one answers 200, and both are the reference's.
		WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
}

// toolsInboundResult is the middle of the handler: the script path, then the
// onWebhook fallback (:256-315). It returns what should be tracked, whether
// anything should be, and an error only for the failures that must not be
// acknowledged.
func (a *Auth) toolsInboundResult(
	r *http.Request, cfg HTTPConfig, provider string, body json.RawMessage,
) (InboundScriptResult, bool, error) {
	// --- the script path (:257-306) ---
	if store := cfg.Tools.InboundWebhooks; store != nil {
		config, found, err := store.FindByProvider(r.Context(), provider)
		if err != nil {
			// The reference's await is inside the try, so a store that throws is
			// the 400 (:255, :323). Not an empty result: an inbound lookup that
			// failed is not the same as a provider nobody configured, and the
			// contract on InboundWebhookStore says so.
			return InboundScriptResult{}, false, err
		}
		// if (config?.jsScript) (:259). Note what is *not* tested: IsActive.
		// FindByProvider does not filter on it and this caller does not check it,
		// so deactivating a webhook stops its outgoing deliveries and leaves its
		// inbound script running. U9 registered that trap on the interface; it is
		// reproduced here rather than corrected, because a deployment that
		// deactivated a row and kept receiving its effects is reproducing the
		// reference exactly, and a host that wants otherwise clears the script.
		if found && config.JSScript != "" {
			result, emit, err := a.runInboundScript(r, cfg, provider, config, body)
			if err != nil {
				return InboundScriptResult{}, false, err
			}
			if emit {
				return result, true, nil
			}
			// Not a return: a script that declared nothing falls through to the
			// callback below, which is `result === null && options.onWebhook`
			// (:308). A script that could not be *run* does not — that path has
			// already returned an error above.
		}
	}

	// --- the onWebhook fallback (:308-315) ---
	//
	// Reached when there is no inbound store, no configuration for this
	// provider, no script on it, or a script that declared nothing —
	// `if (result === null && options.onWebhook)`. It is not reached when the
	// script could not be run: that path has already returned an error.
	if hook := cfg.Tools.OnWebhook; hook != nil {
		result, emit, err := hook(r, provider, body)
		if err != nil {
			// The reference's onWebhook returns a promise inside the try, so a
			// rejection is the 400.
			return InboundScriptResult{}, false, err
		}
		return result, emit, nil
	}
	return InboundScriptResult{}, false, nil
}

// runInboundScript is the vm block (:260-305) with the evaluation taken out of
// this process: resolve the allowlist here, hand the script and the body across
// the seam, and interpret the three answers InboundScriptRunner documents.
func (a *Auth) runInboundScript(
	r *http.Request, cfg HTTPConfig, provider string, config WebhookConfig, body json.RawMessage,
) (InboundScriptResult, bool, error) {
	actions := resolveInboundActions(a.inboundEnabledActions(r.Context()), config.AllowedActions)

	runner := cfg.Tools.ScriptRunner
	if runner == nil {
		// The fail-closed case. See the head of toolsInboundWebhookHandler for
		// the argument; the message is what an operator needs to see, since the
		// caller is told only that processing failed.
		return InboundScriptResult{}, false, errors.New(
			"a webhook script is configured and ToolsOptions.ScriptRunner is nil: " +
				"this package runs no JavaScript in process, so the script cannot run and " +
				"the webhook is refused rather than acknowledged")
	}

	// context.WithoutCancel before the deadline, deliberately. The reference's vm
	// knows nothing about the request and keeps running when the provider hangs
	// up; a script that has already applied half its actions must not be
	// abandoned mid-way because a socket closed. The deadline is then this
	// route's own, since a call that crosses a process boundary can hang in ways
	// an in-process vm cannot.
	timeout := cfg.Tools.ScriptTimeout
	if timeout <= 0 {
		timeout = DefaultInboundScriptTimeout
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), timeout)
	defer cancel()

	result, emit, err := runner.RunInboundScript(ctx, InboundScriptRequest{
		Provider:  provider,
		WebhookID: config.ID,
		Script:    config.JSScript,
		Body:      body,
		Actions:   actions,
	})
	if err != nil {
		return InboundScriptResult{}, false, err
	}
	if !emit {
		// The reference's "result stayed null" — including the script that threw,
		// which it logs and then ignores (:293-304). The onWebhook fallback runs
		// next, exactly as it does there.
		return InboundScriptResult{}, false, nil
	}
	return result, true, nil
}

// inboundEnabledActions is the settings read (:261-264):
//
//	const settings = options.settingsStore
//	  ? await options.settingsStore.getSettings().catch(() => ({}))
//	  : {};
//	const enabledIds = settings.enabledWebhookActions ?? [];
//
// Two things about it are load-bearing and both are reproduced.
//
// It fails *open into an empty allowlist*, which is closed: the .catch swallows
// the error into an empty object, and an empty object has no
// enabledWebhookActions, so a settings store that is down means no actions at
// all rather than all of them. The script still runs and can still declare a
// result — only its ability to act is withdrawn.
//
// And no settings store at all is the same answer. A deployment that never
// called WithSettingsStore has an empty global allowlist forever, so every
// per-webhook AllowedActions list intersects to nothing and no script can ever
// call an action. That is worth knowing before debugging a script that appears
// to do nothing.
//
// There is no settingsStore field on ToolsOptions because there does not need to
// be: ToolsHandler is a method on Auth and Config.Settings is already here,
// which is the note U22 left.
func (a *Auth) inboundEnabledActions(ctx context.Context) []string {
	if a.service == nil || a.service.cfg.Settings == nil {
		return nil
	}
	settings, err := a.service.cfg.Settings.GetSettings(ctx)
	if err != nil {
		// The .catch(() => ({})). It is logged, because the reference's silence
		// here is the kind that turns "my webhook stopped doing anything" into an
		// afternoon.
		a.service.logf("auth: tools inbound webhook: settings read failed, no actions will be available: %v", err)
		return nil
	}
	return settings.EnabledWebhookActions
}

// resolveInboundActions is the intersection rule
// (ActionRegistry.buildContext, webhook-action.ts:104-115):
//
//	const effectiveSet = new Set(allowedIds.filter((id) => enabledIds.includes(id)));
//
// enabled is AuthSettings.EnabledWebhookActions, the administrator's global
// switch; allowed is WebhookConfig.AllowedActions, the subset assigned to this
// one webhook. An action needs both, which is the least-privilege rule the
// reference states in that file's header, and it is resolved *here* — in the
// core, from the core's stores — because it is policy, and policy does not
// cross the seam.
//
// The order and the deduplication are the Set's: allowed's order, first
// occurrence kept. Nothing downstream depends on it, and reproducing it costs
// one map.
//
// Two of buildContext's four rules are deliberately not applied here, because
// both need the registry and the registry lives with the runner:
//
//   - Registration. buildContext iterates the registry, so an id in both lists
//     that nobody registered is simply absent from the sandbox. Here it is
//     present in the list, and the runner drops it.
//   - dependsOn. An action whose declared dependencies are not all in the
//     effective set is excluded (:111-113), and the dependency graph is
//     registry metadata this package has never seen.
//
// That makes the list this function returns an *upper bound* on what the script
// may call, and the runner's own filtering the lower one. It is the right way
// round: narrowing is safe from either side, widening is not, and the core's
// half of the rule — the administrator's two lists — is the half that cannot be
// delegated.
func resolveInboundActions(enabled, allowed []string) []string {
	if len(enabled) == 0 || len(allowed) == 0 {
		return nil
	}
	enabledSet := make(map[string]struct{}, len(enabled))
	for _, id := range enabled {
		enabledSet[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowed))
	resolved := make([]string, 0, len(allowed))
	for _, id := range allowed {
		if _, ok := enabledSet[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		resolved = append(resolved, id)
	}
	if len(resolved) == 0 {
		return nil
	}
	return resolved
}

// toolsInboundBody reads the request body under the route's size limit and
// checks that it is JSON the reference's own parser would have accepted.
//
// This is the layer the reference does not have and cannot avoid needing: there
// req.body is whatever express.json() left behind, which means the parser has
// already enforced a limit, already refused a body that is not JSON with its own
// 400, and already turned an empty body into {}. Reproducing that here is three
// rules:
//
//   - The limit. http.MaxBytesReader, so the process stops reading rather than
//     buffering whatever a stranger decided to send. Over it is the route's 400,
//     which is also express.json's answer (a 413 there, but the reference's own
//     catch is the shape a client of this route sees).
//   - Empty is {}. express.json() leaves an empty body as an empty object, and a
//     provider that pings an endpoint with no body should reach the same script
//     it would otherwise.
//   - Object or array only. express.json's `strict` option defaults to true,
//     which accepts only those two at the top level, so `5` and `"hello"` are
//     refused there and are refused here.
//
// The bytes are returned raw and unmodified. Nothing here decodes the body: the
// runner receives what the provider sent, and a host verifying a signature in
// OnWebhook is verifying the bytes the signature was computed over.
func toolsInboundBody(w http.ResponseWriter, r *http.Request, cfg HTTPConfig) (json.RawMessage, error) {
	limit := cfg.Tools.WebhookMaxBytes
	if limit <= 0 {
		limit = DefaultInboundWebhookMaxBytes
	}
	if r.Body == nil {
		return json.RawMessage("{}"), nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}
	trimmed := trimJSONSpace(body)
	if len(trimmed) == 0 {
		return json.RawMessage("{}"), nil
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return nil, errors.New("body is not a JSON object or array")
	}
	if !json.Valid(trimmed) {
		return nil, errors.New("body is not valid JSON")
	}
	return json.RawMessage(trimmed), nil
}

// trimJSONSpace drops the four characters JSON counts as whitespace, so that a
// body of spaces and newlines is the empty body express.json() reads it as.
func trimJSONSpace(b []byte) []byte {
	start, end := 0, len(b)
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

// logInbound writes one line about a webhook this route refused. The caller is
// told only that processing failed — the reference's single message — so this is
// the only place a deployment can learn which of the several failures it was.
//
// It goes through Config.Logger, which defaults to nil and discards, exactly as
// every other diagnostic in this package does. The reference writes its
// equivalents with console.error (:296, :303).
func (a *Auth) logInbound(provider, format string, args ...any) {
	if a.service == nil {
		return
	}
	a.service.logf("auth: tools inbound webhook %q: "+format, append([]any{provider}, args...)...)
}
