package auth

import (
	"errors"
	"net/http"
	"strings"
)

// GET <tools>/stream, the tools router's SSE endpoint (tools.router.ts:184-221).
//
// The handler itself is six lines of work — refuse when there is no manager,
// read the principal, parse one query parameter, call StreamTopics, hand the
// response to SseManager.Serve — because U20 and U21 already own the two hard
// parts. What is decided here is the posture in front of it, and that is the
// whole of this file's comment.
//
// # extractSseToken: a credential in a query string
//
// The route is registered behind one middleware of its own before the guard:
//
//	const extractSseToken: RequestHandler = (req, _res, next) => {
//	  if (req.query['token'] && typeof req.query['token'] === 'string') {
//	    req.headers['authorization'] = `Bearer ${req.query['token']}`;
//	  }
//	  next();
//	};
//
// (tools.router.ts:185-190). It exists because the browser API this route is
// written for cannot do anything else: EventSource takes a URL and nothing
// else — no headers, and before its `withCredentials` option no cookies
// cross-origin — so a client that authenticates with a bearer token has one
// place to put it, the query string. The family's shipped clients rely on it,
// so it is reproduced, whole, including which credential wins when there are
// two.
//
// What it costs, stated because a route that moves a credential into a URL has
// to say so: a query string is not a header. It is written to the access log of
// every proxy, load balancer and web server on the path, by default and usually
// at a lower retention class than anything that holds credentials; it is kept
// in browser history and in the session-restore file; it is sent in the Referer
// header of any request the page makes afterwards; it appears in an exception
// report, an APM trace and a `ps` listing of a curl command. None of that is
// true of the Authorization header this middleware copies it into. A deployment
// that serves this route is therefore leaking access tokens into its own logs,
// and the mitigations are the deployment's rather than this library's: keep the
// access-token TTL short (Config.AccessTokenTTL, fifteen minutes by default),
// scrub `token` from the access-log format, and prefer the cookie path —
// AccessTokenFromRequest falls back to the __Host-accessToken cookie, so a
// same-origin EventSource with no `?token=` at all is already authenticated.
//
// It is not registered as a deviation, and that is a deliberate reading of what
// the register is for. compatibility.go admits "a deliberate, client-visible
// difference in behaviour" and nothing else; this is the reference's own
// behaviour reproduced exactly, so an entry would have to say that the port
// does X and the reference does X, which is not a deviation but a security note
// wearing one's clothes. Putting it there would also dilute the list a consumer
// reads to find the places the two trees disagree. So it is documented instead:
// here, on ToolsSseTokenMiddleware, in the route's OpenAPI description, and in
// the PR that added it. A host that considers the trade unacceptable has a
// one-line answer that needs no library support — do not mount the stream
// (ToolsOptions.DisableStream), or serve SseManager.Serve from its own route
// with its own guard, which is the shape the manager was given for exactly this
// reason.
//
// # Which credential wins, and why it is worth knowing
//
// The assignment is unconditional: `req.headers['authorization'] = …`
// overwrites whatever was there. So when a request carries both a real
// Authorization header and `?token=`, the query token wins and the header is
// discarded — a caller that sends a valid bearer header and a stale `?token=`
// is refused, and the refusal names the query token's failure, not the header's.
// The same holds against the cookie path, one step further down:
// AccessTokenFromRequest reads the Authorization header before the
// __Host-accessToken cookie, so a browser that is already authenticated by
// cookie and appends `?token=` to the EventSource URL is authenticated as the
// query token and not as its session. Reproduced as it is; it is observable
// either way, and the reference's order is the one the family's clients were
// written against.
//
// Two edges of the reference's own parse come with it, because Express's query
// parser makes them observable. `?token=` with an empty value is falsy and no
// header is written; `?token=a&token=b` parses to an array, fails the
// `typeof === 'string'` test, and no header is written either — so a duplicated
// parameter silently falls back to whatever credential the request already
// carried. Both are reproduced in toolsSseQueryToken by requiring exactly one
// non-empty value, which is the same predicate written for net/url.
//
// # What this port does not carry over
//
// The reference mutates the request in place. This one hands the guard a
// shallow clone with its own header map, so the synthesised
// `Authorization: Bearer …` is not visible to anything that holds the original
// request — a framework's access-log middleware in particular, which on gin and
// echo runs after this handler returns and would otherwise record a credential
// header the client never sent. Nothing downstream of the guard can tell the
// difference, because everything downstream is handed the clone.
//
// # The topics, and who decides them
//
// The client's `?topics=` is a request and not a decision (:203-216): the
// authorised list is built from the authenticated principal and the request is
// intersected with it, so a client cannot subscribe itself to another user's
// channel by naming it. That rule is StreamTopics (auth_tools.go), written
// there beside EventTopics so that what a publisher sends to and what a
// subscriber may hold stay one decision — this route parses the parameter and
// calls it, and deliberately re-derives none of it. It matches the reference
// line for line, including the order of the authorised list, the fact that
// requesting a topic one is not entitled to drops it silently rather than
// failing the request, and the fact that requesting *only* such topics yields an
// empty list and a stream that connects, says `connected` and then never fires.
//
// With no principal at all — which is what ToolsPublic means on this route —
// the authorised list is the single topic `global`. That is not a small
// permission: `global` carries every tracked event as a whole telemetry record,
// with user id, session id, IP and user agent on it. SseConnectionMeta's empty
// TenantID compounds it, because an empty tenant on a connection is a privilege
// rather than an omission: the manager withholds a tenant's event only from a
// connection whose tenant id is set and different. See the
// tools-router-requires-an-explicit-guard-decision entry.

// HTTPErrSseNotEnabled is the answer when the facade was built without SSE:
// `res.status(503).json({ error: 'SSE not enabled' })` (tools.router.ts:193-196).
// No code field, because the reference's literal has one key.
var HTTPErrSseNotEnabled = HTTPError{Status: http.StatusServiceUnavailable, Message: "SSE not enabled"}

// The two query parameters of GET <tools>/stream, named because two files read
// them — this one and the OpenAPI document that describes them.
const (
	// ToolsStreamTokenParam is extractSseToken's parameter (tools.router.ts:186).
	// Read the head of this file before building a client that sets it.
	ToolsStreamTokenParam = "token"
	// ToolsStreamTopicsParam is the requested-topic list (tools.router.ts:203).
	ToolsStreamTopicsParam = "topics"
)

// ToolsSseTokenMiddleware is the port of extractSseToken
// (tools.router.ts:185-190): it copies a `?token=` query parameter into an
// `Authorization: Bearer …` header so that the guard behind it — which reads
// headers, as every guard does — can authenticate a browser EventSource, which
// cannot set one.
//
// It is applied to GET <tools>/stream ahead of ToolsProtectMiddleware, in that
// order, because the reference registers it ahead of ...protect (:192). It is
// exported for a host serving its own stream route off SseManager.Serve: the
// posture is the route's, not the manager's, and a host that wants the same one
// should not have to rewrite it.
//
// Read the head of this file before mounting it anywhere else. A token in a URL
// is a token in access logs, in Referer headers and in browser history, and
// this middleware is the thing that makes that trade.
func ToolsSseTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := toolsSseQueryToken(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		// Overwriting, as the reference does: with both a header and a query
		// token, the query token is the credential. The clone is so that the
		// synthesised header reaches the guard and nothing else; see the head of
		// this file.
		forwarded := r.Clone(r.Context())
		forwarded.Header.Set("Authorization", "Bearer "+token)
		next.ServeHTTP(w, forwarded)
	})
}

// toolsSseQueryToken is `req.query['token'] && typeof req.query['token'] ===
// 'string'` (tools.router.ts:186) in net/url's terms: present exactly once —
// Express parses a repeated parameter to an array, which fails the typeof test
// — and not empty, which is the falsy half of the condition. url.Values.Get
// would answer the first of a repeated pair instead, so the values are read
// directly.
func toolsSseQueryToken(r *http.Request) (string, bool) {
	values := r.URL.Query()[ToolsStreamTokenParam]
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

// toolsStreamHandler serves GET <tools>/stream (tools.router.ts:192-220).
//
// It blocks for the life of the connection, because SseManager.Serve does and
// because a Go handler that returns has ended its response — see Serve, which
// explains why the reference can return from `connect` and this cannot. The
// consequence for an operator is that every open stream holds one goroutine and
// one connection out of whatever pool fronts the process; the consequence for a
// host is that Server.WriteTimeout must be unset or generous on a deployment
// that mounts this route, or the server will cut every stream at the timeout.
//
// HEAD reaches it too, as it does in Express — router.get serves HEAD when no
// HEAD layer is registered — and opens a stream whose every frame the protocol
// then discards. It is not special-cased here because it is not special-cased
// there.
func (a *Auth) toolsStreamHandler(cfg HTTPConfig) http.Handler {
	tools := cfg.Tools.AuthTools
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// `if (!tools.sseManager)` (:193-196). The facade is built without a
		// manager unless AuthToolsOptions.SSE was set, which is the reference's
		// default, so this is the ordinary answer rather than an error path.
		if tools == nil || tools.SSE == nil {
			WriteHTTPError(w, HTTPErrSseNotEnabled)
			return
		}

		// `req.user`, with `id ?? sub` collapsed into one field (:199-201):
		// UserFromRS256Claims already fills User.ID from the `sub` claim, so a
		// principal that arrived through the resource-server path needs no
		// second read. A request with no principal — ToolsPublic, or a guard
		// that authenticates without storing one — leaves both empty, which is
		// the reference's undefined and resolves to the topic `global` alone.
		user, _ := UserFromContext(r.Context())
		requested := toolsStreamRequestedTopics(r.URL.Query()[ToolsStreamTopicsParam])
		topics := StreamTopics(user.ID, user.TenantID, requested)

		// `tools.sseManager.connect(res, finalTopics, { userId, tenantId })`
		// (:218). Everything after it belongs to Serve, whose call is the rest
		// of this request's life.
		err := tools.SSE.Serve(w, r, topics, SseConnectionMeta{UserID: user.ID, TenantID: user.TenantID})
		if errors.Is(err, ErrSseStreamingUnsupported) {
			// Serve promises it wrote nothing in this case, so the route still
			// owns the response. The reference has no shape to copy here — an
			// Express response is always flushable — and the honest status is
			// the generic one: the deployment cannot stream, which is neither
			// the client's fault nor a configuration the host switched off, so
			// it is not the 503 above. It is reachable only behind a
			// ResponseWriter that is not an http.Flusher and cannot be unwrapped
			// to one, which in practice means a middleware in the host's own
			// chain that wrapped the writer without forwarding Flush.
			//
			// The nil check is for the zero Auth the package's own unit tests
			// build a handler from; a mounted Auth always has a service.
			if a.service != nil {
				a.service.logf("auth: tools stream cannot be served: the ResponseWriter cannot be flushed, " +
					"which is usually a middleware that wrapped it without forwarding Flush")
			}
			WriteHTTPError(w, HTTPErrInternal)
			return
		}
		// Every other error ends a stream that had already begun — a write that
		// missed its deadline, a client that went away, a queue that overflowed
		// (see the sse-slow-consumer-is-disconnected deviation). The response is
		// long since committed, so there is nothing to answer and nothing to
		// log that an operator could act on: a disconnect is the ordinary end of
		// an SSE connection, not a fault.
	})
}

// toolsStreamRequestedTopics is the `topics` parameter parsed
// (tools.router.ts:203-205): split on commas, each entry trimmed, the empty
// ones dropped.
//
// values is the raw query values rather than a single string for the reason
// toolsSseQueryToken takes the same shape: Express parses a repeated `?topics=`
// to an array, `typeof … === 'string'` is then false, and the branch that runs
// is the one that requests nothing at all — which means the whole authorised
// list rather than an intersection. A single empty `?topics=` lands on the
// same answer by a different route: it splits to one empty entry, which the
// filter drops, and an empty request is "no request" on both sides.
//
// The result is handed to StreamTopics, which owns the authorisation. Nothing
// here decides anything.
func toolsStreamRequestedTopics(values []string) []string {
	if len(values) != 1 {
		return nil
	}
	parts := strings.Split(values[0], ",")
	topics := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			topics = append(topics, trimmed)
		}
	}
	return topics
}
