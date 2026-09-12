package auth

import (
	"context"
	"log"
	"sync"
	"time"
)

// Event is one identity event as it travels the bus: the reference's
// AuthEventPayload (auth-event-bus.ts:6-25).
//
// The nine fields are the reference's nine, and each of the four this port did
// not have is justified by something that reads it rather than by symmetry with
// the source:
//
//   - SessionID. The reference's telemetry record carries it
//     (telemetry-store.interface.ts:18) and its outgoing webhook envelope puts
//     it in metadata (auth-tools.ts:260); eight of the dev line's twenty-six
//     publication points pass one, always the session issueTokens just minted.
//     Without it a subscriber cannot tell two concurrent logins by one user
//     apart, which is the one thing a session-management screen needs.
//   - CorrelationID. Read from the request and nothing else — see EventContext.
//     Telemetry stores it (telemetry-store.interface.ts:20), the webhook
//     envelope carries it (auth-tools.ts:261), and it is the only field that
//     joins an event to the request that caused it across service boundaries.
//   - IP and UserAgent. Telemetry stores both
//     (telemetry-store.interface.ts:22-24) and the SSE frame carries them
//     indirectly, because the dev line broadcasts the whole telemetry record as
//     the frame's data rather than a projection of it (auth-tools.ts:250-252,
//     against StreamEvent at sse-manager.ts:8-25). The webhook envelope
//     deliberately does not: its metadata is the four identifiers and not these
//     two, which is a privacy line the port keeps — see WebhookMetadata.
//
// Timestamp stays a time.Time although the reference's is an ISO 8601 string
// (auth-event-bus.ts:11), because this type never crosses the wire. The two
// things that do — OutgoingWebhookEvent.Timestamp and the SSE frame — hold
// strings already, and the reason they do is written on OutgoingWebhookEvent.
//
// Data stays map[string]any although the reference's is `unknown`
// (auth-event-bus.ts:12). Nothing is lost: all twenty-six of the dev line's
// publication points pass an object literal, never a scalar, an array or null
// — the widest of them is the OAuth conflict site, which spreads an error's own
// data under a provider key (node-auth auth.router.ts:1480) and is still an
// object. Keeping the narrower type means Event.Data is assignable to
// WebhookPayload.Data and to TelemetryEvent.Meta with no conversion and no
// runtime type check, and a publisher cannot pass a shape a JSON consumer would
// receive as a bare string.
//
// The field order is the order this struct already had, with the four new
// fields appended. The reference's order is different (event, timestamp, data,
// userId, …) and matching it would reorder fields for no one: nothing in this
// package or in the reference constructs an Event positionally.
type Event struct {
	Name      string
	UserID    string
	TenantID  string
	Timestamp time.Time
	Data      map[string]any
	// SessionID is the session the event concerns, when there is one. Empty at
	// the sites where there is not: a failed login has no session, and neither
	// does an OAuth conflict.
	SessionID string
	// CorrelationID, IP and UserAgent are the request provenance. They are
	// filled by WithRequestContext from the carrier the adapters install, not
	// by the publisher, which in this port has no *http.Request to read. See
	// EventContext.
	CorrelationID string
	IP            string
	UserAgent     string
}

// WithRequestContext returns ev with its request-provenance fields filled from
// the EventContext an adapter installed on ctx, and returns ev unchanged when
// ctx carries none.
//
// This is the port of the spread in the dev line's publishRouterEvent, which
// builds every payload as `{...getRequestEventContext(req), ...payload}`
// (node-auth auth.router.ts:430-433, and the byte-identical publishAdminEvent
// at node-auth admin.router.ts:245-249). There the request context is the base
// and the caller's payload is spread over it, so the caller wins a collision;
// here a non-empty field on ev wins and an empty one is filled. The two rules
// agree everywhere the reference can reach, because the payload parameter's
// type admits only data, userId, tenantId and sessionId (node-auth
// auth.router.ts:422-427) — it has no correlationId, ip or userAgent key to
// collide with. "Fill what is empty" is the rule that survives a caller who
// sets one of the three deliberately, which the spread would silently discard.
//
// Nothing here reads the user from ctx. ContextWithUser is on the same context
// and carries a User with an ID, and it is tempting to default Event.UserID
// from it; the reference does not, and the difference is observable — the dev
// line's logout site publishes the user id it read from the refresh token, not
// from the authenticated principal, and its failed-login site publishes no user
// id at all even though an unauthenticated request has none to offer either.
func (e Event) WithRequestContext(ctx context.Context) Event {
	ec, ok := EventContextFromContext(ctx)
	if !ok {
		return e
	}
	if e.CorrelationID == "" {
		e.CorrelationID = ec.CorrelationID
	}
	if e.IP == "" {
		e.IP = ec.IP
	}
	if e.UserAgent == "" {
		e.UserAgent = ec.UserAgent
	}
	return e
}

// WebhookMetadata returns the `metadata` object of an outgoing webhook envelope
// for this event: OutgoingWebhookEvent.Metadata, built the way the reference
// builds it (auth-tools.ts:257-262).
//
// It exists so that the webhook envelope U19 will send is derived from the
// event rather than assembled a second time beside it. OutgoingWebhookEvent
// already holds Metadata as a map[string]any, and the alternative — a second
// struct with the same four identifiers — would be the thing that drifts.
//
// Four keys, spelled as the reference spells them (camelCase, matching
// OutgoingWebhookEvent's own JSON tags), and an absent one is omitted rather
// than written empty: the reference builds the object with all four members and
// lets JSON.stringify drop the undefined ones, so a receiver sees only the keys
// that had a value. That is the reasoning already written on
// OutgoingWebhookEvent.Metadata, and this method is its producer.
//
// An event with none of the four returns nil, which that field's `omitempty`
// renders as no metadata key at all, where the reference would emit
// `"metadata":{}`. The difference is unreachable rather than resolved: no
// publication point in either tree produces such an event — every one of the
// twenty-six passes a user id, or is an OAuth conflict, which carries the
// correlation id the request supplied. Returning nil for the empty case is
// cheaper than special-casing a state nothing produces.
//
// IP and UserAgent are deliberately not here. The reference's metadata is these
// four and not those two (auth-tools.ts:257-262), and the asymmetry is the
// point: a webhook leaves the deployment, and the client address and browser
// string of an end user are the two fields on this struct that should not
// follow it to a third party by default. Telemetry keeps both because it stays
// inside.
func (e Event) WebhookMetadata() map[string]any {
	meta := make(map[string]any, 4)
	if e.UserID != "" {
		meta["userId"] = e.UserID
	}
	if e.TenantID != "" {
		meta["tenantId"] = e.TenantID
	}
	if e.SessionID != "" {
		meta["sessionId"] = e.SessionID
	}
	if e.CorrelationID != "" {
		meta["correlationId"] = e.CorrelationID
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// EventBus is the in-process pub/sub every downstream consumer of the event
// plane sits on: the reference's AuthEventBus (auth-event-bus.ts:48-82), which
// is a subclass of Node's EventEmitter.
//
// The two were compared axis by axis when the vocabulary landed, because a
// delivery-semantics mismatch discovered by the SSE or webhook work would be
// expensive and one discovered here is not. They agree on four of the five
// axes that matter:
//
//   - Publish is synchronous. EventEmitter.emit calls its listeners inline and
//     returns when the last one returns; publish emits twice and returns
//     (auth-event-bus.ts:61-63). Publish below does the same. Neither defers to
//     a queue, so a handler that blocks blocks the publisher — which for U18
//     means a slow subscriber delays the HTTP response, exactly as it does in
//     the reference.
//   - Ordering within a name is registration order, in both.
//   - The named channel is served before the wildcard, in both: the reference
//     emits eventName and then '*' (auth-event-bus.ts:61-63), and Publish below
//     runs the named handlers and then the wildcard ones.
//   - Both dispatch against a snapshot of the handler list. EventEmitter clones
//     its listener array before iterating; Publish copies under the read lock
//     and releases it before calling. So in both, a handler that subscribes
//     during a dispatch is not called for the event being dispatched, and —
//     for the same reason — a Subscribe from inside a handler cannot deadlock
//     here.
//
// They disagree on the fifth. A handler that throws propagates out of
// EventEmitter.emit, so in the reference it skips every later handler and
// surfaces in whatever published — for the dev line's router that is the route
// handler's own catch, which answers the request 500 for work that already
// succeeded. Here a panicking handler is recovered, logged and stepped over.
// That is the deviation registered as
// event-handler-panic-does-not-fail-the-publisher, and safeCall is where it
// lives.
//
// One piece of the reference's surface has no counterpart yet. AuthEventBus
// exposes offEvent (auth-event-bus.ts:79-81), and this bus has no way to
// unsubscribe at all. The port is not a line-for-line one: Go functions are not
// comparable, so `Unsubscribe(name, handler)` cannot be written, and the Go
// shape is a cancel function returned from Subscribe. That is a change to
// Subscribe's signature, and it belongs with the first consumer that needs it —
// the SSE hub in U20, whose per-connection subscriptions are the only thing in
// the plan that ever ends. Nothing before then subscribes and stops.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]func(Event)
}

func NewEventBus() *EventBus {
	return &EventBus{subscribers: make(map[string][]func(Event))}
}

// Subscribe registers handler for one event name, or for EventBusWildcard to
// receive every event. It is the reference's onEvent (auth-event-bus.ts:72-74).
func (b *EventBus) Subscribe(event string, handler func(Event)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[event] = append(b.subscribers[event], handler)
}

// EventBusWildcard is the subscription name that receives every event: the
// channel the reference's publish emits on a second time (auth-event-bus.ts:63,
// documented at :69).
//
// It is spelled the same as WebhookEventWildcard and means something adjacent
// but not identical — that one selects webhook subscriptions from a store,
// this one selects bus handlers in process — so the two are separate constants
// rather than one shared with two meanings.
const EventBusWildcard = "*"

// Publish delivers ev to the handlers registered for ev.Name and then to the
// wildcard handlers, synchronously, in registration order.
//
// A zero Timestamp is filled with the current time, which is the reference's
// `payload.timestamp ?? new Date().toISOString()` (auth-event-bus.ts:59): a
// caller that has a better instant than "now" may say so, and one that does not
// gets the publish instant.
//
// The library itself calls this from nowhere. Closing that — raising an event
// at each of the twenty-six places the dev line raises one — is U18.
func (b *EventBus) Publish(ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	b.mu.RLock()
	handlers := append([]func(Event){}, b.subscribers[ev.Name]...)
	wildcard := append([]func(Event){}, b.subscribers[EventBusWildcard]...)
	b.mu.RUnlock()
	for _, h := range handlers {
		safeCall(h, ev)
	}
	for _, h := range wildcard {
		safeCall(h, ev)
	}
}

// PublishContext publishes ev with its request-provenance fields filled from
// ctx: Publish(ev.WithRequestContext(ctx)).
//
// This is the method a service publishes through, and it is the whole reason
// the carrier in event_context.go exists. The reference reaches the request
// where it publishes — publishRouterEvent takes the *Request and reads the
// three headers at publish time (node-auth auth.router.ts:418-434) — and a
// Service method here takes a context.Context and nothing else. Splitting the
// read (an adapter, once per request) from the use (a publisher, once per
// event) is what bridges that, and this method is the use.
//
// A ctx with no EventContext on it publishes an event with the three fields
// empty, which is what a publish from outside any request — a background sweep,
// a host calling a Service method from a cron job — should produce. It is not
// an error and is not logged: the reference's equivalent is a publish through
// AuthTools.track with no metadata options (auth-tools.ts:245), which is
// likewise silent.
func (b *EventBus) PublishContext(ctx context.Context, ev Event) {
	b.Publish(ev.WithRequestContext(ctx))
}

// safeCall runs one handler with a panic recovered.
//
// This is the one place the bus does not behave as the reference's does, and it
// is deliberate; see the deviation event-handler-panic-does-not-fail-the-publisher
// and the comment on EventBus. The short version is that the reference's
// failure mode — a telemetry subscriber taking down the HTTP request that
// published — is a Node consequence of extending EventEmitter rather than a
// decision, and reproducing it in Go would mean a panic in a handler unwinding
// the server's request goroutine. Every later handler still runs, because
// containing a failure to one subscriber and stopping at it are different
// things, and the second is not what recovering buys.
func safeCall(handler func(Event), ev Event) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("auth: recovered panic in event handler for %q: %v", ev.Name, r)
		}
	}()
	handler(ev)
}
