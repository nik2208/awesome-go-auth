package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// The tools router's first two feature routes: POST <tools>/track/:eventName
// (tools.router.ts:140-160) and POST <tools>/notify/:target (:165-179).
//
// Both are one call to the facade U21 built and nothing else. The fan-out
// order, what each sink receives and the failure isolation per sink are
// AuthTools.Track's and AuthTools.Notify's business, settled and pinned there;
// these routes read a path parameter, read a body, call, and answer 202 with
// {"ok": true}. Neither reports anything about the fan-out, because neither
// facade method has anything to report — which is the reference's own
// arrangement: track is awaited and the 202 is written regardless of what the
// four sinks did (:149-158), and notify is not awaited at all (:170-177).
//
// Both go behind ToolsProtectMiddleware, which is where the reference spreads
// `...protect` (:141, :166): whatever guard the host configured, and nothing
// else. The tools router carries none of the auth router's middleware, so there
// is no CSRF check, no rate limiter and no event-context carrier in front of
// either — the head of tools.go says why. The last of those has a consequence
// here rather than a note: nothing installs an EventContext on this request, so
// both routes pass the request provenance as options, exactly as the
// reference's routes do (:144-145, :154-155).
//
// # The client address
//
// This is the substantive decision of these two routes, because the reference
// resolves the address at the route and resolves it differently from everything
// else in this port.
//
// There:
//
//	const ip = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim()
//	        ?? req.socket.remoteAddress;
//
// (:144) — the left-most element of X-Forwarded-For, trusted unconditionally,
// with the socket peer only as the fallback. Here every event the auth router
// raises takes its address from HTTPConfig.ClientIP (event_context.go), added
// at v0.9.0, whose default is the socket peer with the port stripped and which
// deliberately ships no X-Forwarded-For parser at all — on the grounds that a
// parser is only as good as the trust configuration behind it, that an
// untrusted one is a spoofable client address in a security log, and that the
// trust configuration is the host's knowledge and not the library's.
//
// Two address rules in one binary is the thing that must not happen quietly, so
// this route reads cfg.clientIP(r): the same seam, the same answer, and the
// difference from the reference is registered as
// tools-track-ip-comes-from-the-configured-seam. What decided it, in the order
// it mattered:
//
//   - Reproducing :144 would not add a second rule beside the host's, it would
//     override it. A deployment that has set ClientIP has stated in its own
//     source which hop it trusts and which header that hop writes; a route that
//     read element 0 of X-Forwarded-For anyway would discard that statement on
//     the one surface where the address is written into a durable record. A
//     seam one route is free to ignore is not a seam, it is a suggestion.
//   - The record is the one the reference calls telemetry and an operator reads
//     as a log. Track's address lands on the TelemetryEvent the store keeps, on
//     the SSE frame every connection holding the topic receives
//     (auth-tools.ts:240), and — once a host calls Bridge — in the same column
//     as the library's own identity.* events. A caller-chosen value there is
//     precisely what ClientIP refuses to ship by default, and the tools router
//     is the surface where an unauthenticated caller is most likely to be
//     standing: see tools-router-requires-an-explicit-guard-decision.
//   - Nothing is lost that one line does not restore, and that line says what
//     it asserts. A deployment behind a proxy it operates sets
//     cfg.ClientIP — and gets the forwarded address here *and* on the auth
//     router's events, which is the point: one statement about the deployment,
//     one meaning everywhere.
//   - No shipped client is affected. ng-awesome-node-auth, the Flutter client
//     and the served auth.js never call /tools; the callers of this route are a
//     host's own services.
//
// What an operator behind a proxy they have not configured for gets, said
// plainly rather than left to be discovered: every tracked event records the
// proxy's address instead of the caller's — the same value the auth router's
// events already carry in that deployment, and a value no caller can choose.
// The reference, in that same deployment, records whatever the caller put in
// X-Forwarded-For. A lost client address is recovered by one line of
// configuration; a forged one already written into a telemetry store is not
// recovered at all.
//
// The header itself is read nowhere on this route. Not even as a fallback: a
// fallback consulted when ClientIP is unset would be the untrusted parser under
// another name, and would make the default deployment the spoofable one.
//
// # The bodies are decoded, not cast
//
// The reference reads its fields off `req.body as Record<string, unknown>` and
// casts each one (:143, :168). A TypeScript cast is a no-op at runtime, so
// `{"userId": 5}` reaches the telemetry record as the number 5 in a field the
// store interface declares a string, and `{"data": 42}` is tracked as 42 where
// this port's Track takes a map[string]any — the narrowing Event.Data already
// carries and Track cannot widen (events.go, auth_tools.go).
//
// Go decodes instead, and a body whose fields do not have the declared types is
// a 400 carrying this router's own error envelope, {"error": ...}, the shape
// its other refusals use (:194, :232, :319). That is
// tools-request-bodies-are-typed, and the alternative was worse: reading each
// field leniently and dropping the ones that do not fit would answer 202 —
// "accepted" — to a caller whose payload was silently discarded.
//
// An absent or empty body is not an error on either route, and that is not
// leniency but the reference: express.json leaves req.body = {}, both handlers
// read undefined off it, and a bodyless POST therefore tracks an event with no
// payload and answers 202. It is why the document marks track's requestBody
// `required: false` (openapi.ts:1400-1401). Notify's is marked `required: true`
// (openapi.ts:1473-1474) and is not enforced by the handler either way, there or
// here; the document is describing the intent and the route accepts a bodyless
// call.

// toolsOKBody is `res.json({ ok: true })`, the success body both routes write
// (:158, :177) and the OkResponse schema of the tools document
// (openapi.ts:1599-1603). A struct rather than a map so the key is spelled once.
type toolsOKBody struct {
	OK bool `json:"ok"`
}

// toolsInvalidBody is the message a body this port cannot decode is refused
// with. The reference has no such refusal on either route — see the file head —
// so the wording is this port's; the envelope is the reference's.
const toolsInvalidBody = "Invalid request body"

// writeToolsError writes the tools router's error envelope: a bare
// {"error": "..."} with no success flag and no code, which is what every
// failure of this router answers with (tools.router.ts:194, :230, :323).
//
// It is deliberately not WriteHTTPError. That writes the auth router's
// envelope — {"success": false, "error": ..., "code": ...} — which is a
// different contract on a different router, and the family's clients read it
// only on the auth routes.
func writeToolsError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// toolsTrackHandler serves POST <tools>/track/:eventName
// (tools.router.ts:140-160).
//
// It takes the configuration and not the *Auth because it needs nothing from
// the service layer: the facade is on HTTPConfig.Tools, and ToolsHandler has
// already established that it is non-nil — ToolsMounted is false otherwise and
// no route is registered at all.
func toolsTrackHandler(cfg HTTPConfig) http.Handler {
	tools := cfg.Tools.AuthTools
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// UserID is a *string so that the reference's `??` is reproduced
		// exactly (:147): an explicit "" in the body wins, because it is not
		// nullish there, and only an absent or null userId falls back to the
		// authenticated principal.
		var body struct {
			Data          map[string]any `json:"data"`
			UserID        *string        `json:"userId"`
			TenantID      string         `json:"tenantId"`
			SessionID     string         `json:"sessionId"`
			CorrelationID string         `json:"correlationId"`
		}
		if err := DecodeOptionalJSONBody(r, &body); err != nil {
			writeToolsError(w, http.StatusBadRequest, toolsInvalidBody)
			return
		}

		// `userId ?? req.user?.id ?? req.user?.sub` (:147). The two halves of
		// the reference's fallback collapse to one field here: the principal
		// this package puts on the context is a User, whose ID is the subject.
		// ContextWithUser is what the adapters' Middleware installs, and
		// Tools.Access is ordinarily that same middleware, so a guarded call
		// with no userId in the body is attributed to whoever made it.
		userID := ""
		if body.UserID != nil {
			userID = *body.UserID
		} else if user, ok := UserFromContext(r.Context()); ok {
			userID = user.ID
		}

		tools.Track(r.Context(), toolsPathParam(r, cfg, ToolsTrackPath), body.Data, TrackOptions{
			UserID:        userID,
			TenantID:      body.TenantID,
			SessionID:     body.SessionID,
			CorrelationID: body.CorrelationID,
			// The two the reference reads off the request rather than the body
			// (:144-145). The address is the file head's decision; the user
			// agent is firstHeaderValue for the reason event_context.go gives —
			// Node keeps the first User-Agent line and discards repeats.
			IP:        cfg.clientIP(r),
			UserAgent: firstHeaderValue(r.Header, "User-Agent"),
		})

		WriteJSON(w, http.StatusAccepted, toolsOKBody{OK: true})
	})
}

// toolsNotifyHandler serves POST <tools>/notify/:target
// (tools.router.ts:165-179).
//
// # What :target means
//
// An SSE topic, and nothing about it is checked. The vocabulary both ends of
// the stream agree on is `global`, `tenant:<id>`, `user:<id>` and
// `session:<id>` — the four constants at the head of auth_tools.go — and the
// document's example is `user:123` (openapi.ts:1470). The route validates none
// of it: it hands the segment to Notify, which broadcasts to that one topic and
// to no other, so a target nobody holds is delivered to nobody and is still
// answered 202. That is the reference's behaviour and it is kept, because the
// topic space is open by construction — a host that calls SseManager.Serve with
// topics of its own invention has those topics, and a route that refused
// anything outside the four prefixes would refuse a deployment its own
// channels.
//
// What is refused is a target that is not one segment. Express's `:target`
// captures a single segment, so <tools>/notify, <tools>/notify/ and
// <tools>/notify/a/b match no layer and end at the router's own 404 — before
// the guard, as there, so an unauthenticated caller sees 404 and not 401. A
// target containing a colon needs no encoding, `:` being legal in a path
// segment; a percent-encoded one is decoded before Notify sees it, as Express
// decodes its captured parameters. See toolsPathParam.
//
// # Which of the facade's sinks this route can reach
//
// One: the SSE stream. NotifyOptions.Channels is the reference's `channels`,
// which selects sse, email and sms (auth-tools.ts:293), and this route never
// reads it — the reference destructures exactly data, type, tenantId, userId
// and metadata from the body (:168) and passes exactly those four options
// (:171-176), so `channels` falls to its default ['sse'] on every request and
// the email and SMS channels are unreachable over HTTP.
//
// That looks like an oversight — multi-channel notify arrived in 1.8.0 and this
// route was not extended with it — and it is reproduced rather than repaired,
// for the ordinary reason and for one more. A host that wants mail or SMS calls
// the facade, where Channels is one field away; a route that accepted a
// channels array off the wire would let whoever gets past the guard spend the
// deployment's mail and SMS budget, which is the cost
// tools-router-requires-an-explicit-guard-decision prices. The quirk is also
// the safer shape.
func toolsNotifyHandler(cfg HTTPConfig) http.Handler {
	tools := cfg.Tools.AuthTools
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Data is `any` and not map[string]any: Notify's payload becomes a
		// frame's data and an encoded message body, neither of which narrows,
		// and AuthTools.Notify takes `any` for exactly that reason. So this
		// route accepts the scalar and the array that track's does not.
		var body struct {
			Data     any            `json:"data"`
			Type     string         `json:"type"`
			TenantID string         `json:"tenantId"`
			UserID   string         `json:"userId"`
			Metadata map[string]any `json:"metadata"`
		}
		if err := DecodeOptionalJSONBody(r, &body); err != nil {
			writeToolsError(w, http.StatusBadRequest, toolsInvalidBody)
			return
		}

		// No Channels, as there (:171-176). An empty Type is Notify's
		// `?? 'notification'` and is left to it rather than resolved twice.
		tools.Notify(r.Context(), toolsPathParam(r, cfg, ToolsNotifyPath), body.Data, NotifyOptions{
			Type:     body.Type,
			TenantID: body.TenantID,
			UserID:   body.UserID,
			Metadata: body.Metadata,
		})

		WriteJSON(w, http.StatusAccepted, toolsOKBody{OK: true})
	})
}

// toolsPathParam is the single path parameter of a tools route: the one segment
// below prefix, percent-decoded, or "" when the request does not match that
// route at all.
//
// It reads r.URL.EscapedPath() for the reason matchAdminRead does. Express
// matches its patterns against the raw pathname and decodes each captured
// parameter afterwards (layer.js decode_param), so `/track/a%2Fb` is one
// segment there and reaches the handler as "a/b"; r.URL.Path is already decoded
// and would be split into two segments and matched by nothing.
//
// "" is the miss, and a match cannot produce it: Express's `:param` needs at
// least one character, and no non-empty escaped segment decodes to the empty
// string. So ToolsHandler can test the result instead of carrying a second
// boolean, and <tools>/track, <tools>/track/ and <tools>/track/a/b all fall
// through to the router's 404 — which is where Express leaves them too. A
// segment whose encoding does not decode is likewise a miss rather than a
// status of its own; net/http has already refused a request whose path would
// not parse, so the branch is unreachable in practice.
func toolsPathParam(r *http.Request, cfg HTTPConfig, prefix string) string {
	rel := toolsRelativePath(r.URL.EscapedPath(), cfg.ToolsPath())
	if !strings.HasPrefix(rel, prefix+"/") {
		return ""
	}
	segment := rel[len(prefix)+1:]
	if segment == "" || strings.Contains(segment, "/") {
		return ""
	}
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		return ""
	}
	return decoded
}
