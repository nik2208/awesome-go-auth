package auth

import (
	"context"
	"net"
	"net/http"
)

// This file is the port of one function: the dev line's getRequestEventContext
// (node-auth auth.router.ts:402-416, and the byte-identical copy at node-auth
// admin.router.ts:218-232), which reads three things off the request and which
// publishRouterEvent spreads under every payload it publishes.
//
// The reference can do that in one place because its publisher has the request:
// publishRouterEvent's second-to-last parameter is the Express `req` (node-auth
// auth.router.ts:421). This port's publisher is a Service method, whose only
// handle on the request is a context.Context — deliberately, because the
// service layer is what a host calls from a gRPC server, a queue consumer or a
// test with no HTTP anywhere. So the one function splits into two halves that
// meet on the context:
//
//	adapter                              service
//	EventContextFromRequest(r)  ──►  ctx  ──►  Event.WithRequestContext(ctx)
//	ContextWithEventContext
//
// EventContextMiddleware is the first half packaged as a middleware, and all
// four adapters install it as the outermost element of their guard chain. That
// is not decoration: a carrier installed on three adapters out of four is worse
// than none, because the correlation id then depends on which router the host
// happened to choose and a missing one reads as "this request had none".
//
// The precedent for the shape is in the product rather than in the reference.
// awesome-lambda-auth's rotationScopeMiddleware installs a per-request value on
// r.Context() and every later handler reads it from there, and the rule it
// encodes is the one rule that matters for a carrier: install on the request's
// context, never on the process's. A value put on the context an adapter was
// constructed with would be shared by every request the process ever serves,
// and the first request's correlation id would be published for all of them.

// CorrelationIDHeader is the request header the correlation id is read from:
// the reference's 'x-correlation-id' (node-auth auth.router.ts:407).
//
// It is spelled in canonical MIME header form here because that is the form
// http.Header.Get and http.Header.Values want. Header matching is
// case-insensitive on both sides, so a client sending X-Correlation-ID or
// x-correlation-id is read identically; Express lowercases its header keys and
// the reference indexes with the lowercase form, which is the same lookup.
const CorrelationIDHeader = "X-Correlation-Id"

// EventContext is the per-request provenance every published Event carries: the
// return type of the reference's getRequestEventContext (node-auth
// auth.router.ts:402-406).
//
// Three fields and no more. It is deliberately not a general-purpose request
// bag: a second thing that wants to ride the request context should get its own
// carrier and its own key, so that neither can quietly start depending on the
// other's lifetime.
type EventContext struct {
	// CorrelationID is the caller's own trace handle, read from
	// CorrelationIDHeader and never generated. The reference does not mint one
	// when the header is absent (node-auth auth.router.ts:407-408, :412) and
	// neither does this: an id this library invented would join nothing to
	// anything, and a consumer that saw one would have no way to tell it from
	// an id the caller's gateway assigned.
	CorrelationID string
	// IP is the client address. What that means behind a proxy is
	// HTTPConfig.ClientIP's decision; see EventContextFromRequest.
	IP string
	// UserAgent is the User-Agent header value, or empty.
	UserAgent string
}

// eventContextKey is the context key EventContext travels under. It is an empty
// struct type private to this package, as userContextKey is, so that no other
// package can collide with it and no caller can reach the value except through
// the two functions below.
type eventContextKey struct{}

// ContextWithEventContext returns ctx carrying ec as the request provenance.
//
// It is exported for the same reason ContextWithUser is: a host that mounts
// this library behind something other than the four adapters — a gRPC gateway,
// a Lambda handler translating an API Gateway event, a queue consumer replaying
// a recorded request — has the three values and no *http.Request to hand
// EventContextFromRequest, and must still be able to install them.
func ContextWithEventContext(ctx context.Context, ec EventContext) context.Context {
	return context.WithValue(ctx, eventContextKey{}, ec)
}

// EventContextFromContext reads the request provenance a middleware installed.
//
// The bool distinguishes "no carrier" from "a carrier with three empty fields",
// which are different facts: the first says nobody installed one — a publish
// from a background job, or an adapter that was not wired — and the second says
// a request arrived with no correlation header, no User-Agent and an
// unresolvable address. Event.WithRequestContext treats them the same, because
// the fields it would copy are empty either way; a host writing its own
// diagnostics may not want to.
func EventContextFromContext(ctx context.Context) (EventContext, bool) {
	ec, ok := ctx.Value(eventContextKey{}).(EventContext)
	return ec, ok
}

// EventContextFromRequest reads the request provenance off r, resolving the
// client address through cfg.
//
// The two header reads are the reference's, quirks included. The reference
// tests each header for an array and takes the first element when it finds one
// (node-auth auth.router.ts:407-410) — Node hands an array for a header sent
// more than once, and a bare string otherwise — so a client that sends
// X-Correlation-Id twice is read as having sent the first one.
//
// Go stores repeated headers as a slice too, and Header.Get already returns the
// first entry, so Get would produce the identical value. Header.Values with an
// explicit index is used anyway, because the rule being reproduced is the
// reference's array-first choice and not Go's documented default: if Get's
// behaviour is ever what a reader checks this against, they will have checked
// the wrong thing.
//
// The address is HTTPConfig.ClientIP when the host set one, and the socket peer
// otherwise; see that field for why the choice is the host's.
func EventContextFromRequest(r *http.Request, cfg HTTPConfig) EventContext {
	if r == nil {
		return EventContext{}
	}
	return EventContext{
		CorrelationID: firstHeaderValue(r.Header, CorrelationIDHeader),
		IP:            cfg.clientIP(r),
		UserAgent:     firstHeaderValue(r.Header, "User-Agent"),
	}
}

// firstHeaderValue returns the first value sent for name, or "".
//
// This is `Array.isArray(h) ? h[0] : h` (node-auth auth.router.ts:408, :410).
// Header.Values returns one entry per header line, which is Node's array; a
// header sent once yields one entry, which is Node's string.
func firstHeaderValue(h http.Header, name string) string {
	values := h.Values(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// clientIP resolves the client address for r.
//
// The default — no HTTPConfig.ClientIP — is the socket peer with its port
// stripped, falling back to RemoteAddr whole if it does not split. That is
// exactly `req.socket.remoteAddress`, which is also what `req.ip` is in Express
// with `trust proxy` unset, so the default reproduces the reference's default
// deployment rather than approximating it.
func (c HTTPConfig) clientIP(r *http.Request) string {
	if c.ClientIP != nil {
		return c.ClientIP(r)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// EventContextMiddleware installs the request provenance on the request context
// so that anything publishing an event downstream can reach it.
//
// It is the counterpart of RateLimitMiddleware and CSRFMiddleware, takes the
// same HTTPConfig and returns the same shape, and the four adapters compose it
// outermost — ahead of the limiter, which is ahead of the CSRF middleware. That
// position is chosen and worth stating:
//
//   - It cannot refuse a request, so nothing is gained by running it later and
//     one thing is lost. The limiter and the CSRF middleware are the two places
//     a request is turned away, and a host that has replaced either with its
//     own code — HTTPConfig.RateLimiter is a slot for exactly that — may want
//     to publish or log from inside it. Outermost is the only position where
//     the carrier is already there when that happens.
//   - The reference's position is "at publish time", which is outside every
//     middleware in the sense that matters: getRequestEventContext reads the
//     raw headers off the request and no middleware in the chain can have
//     changed them. Installing first is the closest a split carrier gets to
//     that.
//
// It costs one context.WithValue and two header lookups per request, on a chain
// that already allocates a context value for the authenticated user.
//
// A host mounting this library some other way can call it directly, and a host
// that mounts nothing of this package's middleware at all still works — an
// event published without a carrier simply has the three fields empty. See
// EventBus.PublishContext.
func EventContextMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := ContextWithEventContext(r.Context(), EventContextFromRequest(r, cfg))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
