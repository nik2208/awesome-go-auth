package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SseTopicGlobal and the three prefixes are the topic vocabulary both sides of
// the stream agree on: the reference's documented scheme, of which these four
// are the part either tree actually produces (sse-manager.ts:88, and the
// convention quoted in full on SseManager).
//
// They are constants rather than string literals at the two call sites because
// the two sites must not drift: EventTopics builds what a publisher sends to
// and StreamTopics builds what a connection is allowed to hold, and a typo in
// either one is silence rather than an error.
const (
	SseTopicGlobal        = "global"
	SseTopicTenantPrefix  = "tenant:"
	SseTopicUserPrefix    = "user:"
	SseTopicSessionPrefix = "session:"
)

// NotifyChannel is one delivery channel of AuthTools.Notify: the reference's
// `'sse' | 'email' | 'sms'` union (auth-tools.ts:119).
type NotifyChannel string

const (
	NotifyChannelSSE   NotifyChannel = "sse"
	NotifyChannelEmail NotifyChannel = "email"
	NotifyChannelSMS   NotifyChannel = "sms"
)

// AuthToolsOptions configures AuthTools: the reference's AuthToolsOptions
// (auth-tools.ts:15-82).
//
// Every field is optional and every one of them off is the zero value, which is
// the reference's "all capabilities are optional and have zero overhead when
// disabled" (auth-tools.ts:140-141) said in Go.
//
// Three of the reference's fields are not here, and each is absent because this
// port already has the seam they exist to reach:
//
//   - `sseOptions` is SSEOptions below, a slice of the SseOption functions
//     NewSseManager already takes, rather than a struct of three settings that
//     would have to be kept in step with it.
//   - `emailConfig` and `smsConfig` are transport *configuration* there, from
//     which the constructor builds a NotificationService
//     (notification.service.ts:99-100). Here they are Mail and SMS, the
//     transports themselves. That is the shape this package already uses for
//     every other message it sends — MailerTransport and SMSTransport are what
//     the six ready-made senders are built on — and taking the interface rather
//     than a config struct means a host that already configured a mailer for
//     password resets passes the same value again instead of a second copy of
//     its endpoint and key.
type AuthToolsOptions struct {
	// Telemetry persists every tracked event. Nil is "do not persist": the
	// reference's optional telemetryStore (auth-tools.ts:20).
	Telemetry TelemetryStore
	// Webhooks holds the outgoing subscriptions. Nil is "no outgoing
	// webhooks": the reference's optional webhookStore (auth-tools.ts:26).
	Webhooks WebhookStore
	// WebhookVersion is OutgoingWebhookEvent.Version. Empty means
	// OutgoingWebhookVersion, which is the reference's `?? '1'`
	// (auth-tools.ts:175).
	WebhookVersion string
	// WebhookSender delivers. Nil means a zero WebhookSender, which POSTs over
	// HTTP in process — the reference's `new WebhookSender()`
	// (auth-tools.ts:174), which likewise takes no arguments.
	//
	// It is here because U19 made WebhookDeliverer the transport seam, and a
	// facade that constructed the sender privately would put that seam out of
	// reach of every host that uses the facade — which, from U22 on, is the
	// ordinary way to use this package. Setting it is how a deployment queues
	// deliveries rather than sending them inline.
	WebhookSender *WebhookSender
	// SSE enables the stream. False is the reference's default
	// (auth-tools.ts:33) and leaves AuthTools.SSE nil, which makes both the SSE
	// step of Track and the `sse` channel of Notify do nothing at all.
	SSE bool
	// SSEOptions are forwarded to NewSseManager. Ignored when SSE is false, as
	// the reference's sseOptions are (auth-tools.ts:176).
	SSEOptions []SseOption
	// Users resolves the recipient of an email or SMS notification. Required
	// for those two channels of Notify and unused by everything else: the
	// reference's userStore (auth-tools.ts:60).
	Users UserStore
	// Mail is the transport the `email` channel of Notify sends on. Nil is
	// the reference's absent notificationService.hasEmail (auth-tools.ts:321).
	Mail MailerTransport
	// SMS is the transport the `sms` channel of Notify sends on. Nil is the
	// reference's absent notificationService.hasSms (auth-tools.ts:333).
	SMS SMSTransport
	// OnError, when set, is called for every failure this facade swallows: a
	// telemetry write that failed, a notification that could not be encoded or
	// delivered, and — forwarded from WebhookEmitter.OnError — a webhook store
	// lookup or delivery that failed.
	//
	// Nil is the default and nil is the reference, which swallows all of them
	// silently (auth-tools.ts:218, :251, :266, :329, :338). The hook is how a
	// deployment buys the observability back without this package inventing a
	// log line the reference never writes. It may be called from a delivery
	// goroutine and must be safe for concurrent use; it must not block, because
	// nothing is waiting on it.
	OnError func(err error)
}

// TrackOptions is the metadata of one tracked event: the reference's
// TrackOptions (auth-tools.ts:87-94), field for field.
//
// All six are optional. Each one that is set both lands on the record the
// telemetry store keeps and — for the three that name a principal — adds a
// topic the event is broadcast to; see EventTopics.
type TrackOptions struct {
	UserID        string
	TenantID      string
	SessionID     string
	CorrelationID string
	IP            string
	UserAgent     string
}

// NotifyOptions is the second argument of AuthTools.Notify: the reference's
// NotifyOptions (auth-tools.ts:99-134).
type NotifyOptions struct {
	// Type is the StreamEvent's `event:` line. Empty means "notification",
	// which is the reference's `?? 'notification'` (auth-tools.ts:298).
	Type string
	// TenantID and UserID are carried on the frame and, for the email and SMS
	// channels, UserID is what the user store is asked for. A notification with
	// no UserID reaches neither of those two channels at all.
	TenantID string
	UserID   string
	// Metadata is carried on the frame and never interpreted.
	Metadata map[string]any
	// Channels are the deliveries attempted. Empty means just the SSE channel,
	// which is the reference's `?? ['sse']` and its backward-compatible default
	// (auth-tools.ts:293). An unknown channel name is ignored rather than
	// refused, as it is there.
	Channels []NotifyChannel
	// EmailSubject overrides the subject line. Empty falls back to Type, and
	// then to "Notification" (auth-tools.ts:322).
	EmailSubject string
	// SMSMessage overrides the message body. Empty falls back to the encoded
	// payload (auth-tools.ts:334).
	SMSMessage string
}

// AuthTools is the facade the tools router is built on: the reference's
// AuthTools (auth-tools.ts:160-360).
//
// It is the one place four sinks are fed from one call. Track takes an event
// name, a payload and six identifiers and turns them into four different
// shapes — a TelemetryEvent for the store, an Event for the bus, a StreamEvent
// for the stream, an OutgoingWebhookEvent for the subscriptions — in an order
// that is observable and is therefore the source's, not this port's. Notify is
// the other half: one payload, one topic, and up to three transports.
//
// # What a deployment gets by default
//
// Silence, for the library's own events.
//
// This is the decision worth reading before anything else here, because it is
// the one place where porting the reference faithfully is not obviously the
// same thing as porting it usefully. There, AuthTools is fed by a host calling
// track and by nothing else: the routers publish onto the bus and stop, and no
// part of the package subscribes the bus back into the telemetry store, the
// stream or the webhooks (auth-tools.ts:199-269 against node-auth
// auth.router.ts:418-433). Here the service layer publishes nineteen
// identity.* events of its own that no track call produced, so a host who
// builds an AuthTools with a webhook store and turns SSE on has, by the
// reference's own wiring, configured four sinks that the library's own events
// never reach. Bridge is the one call that changes that, and nothing calls it
// for the host.
//
// Four things decided it, in the order they mattered:
//
//   - Subscribing by default would deliver every tracked event twice. Track
//     publishes on the bus at step 2 and then broadcasts and fires webhooks at
//     steps 3 and 4. A facade that also subscribed to the bus would hear its
//     own step 2 and run steps 3 and 4 a second time, with a second event id —
//     so the per-connection deduplication, which compares ids, could not
//     collapse the pair and every subscription would receive two POSTs. The
//     only way to break that loop inside the library is to mark the events
//     Track publishes so the subscription can skip them, which means a hidden
//     field on Event that exists to let one type ignore another type's
//     messages. The hazard is not removed by making the subscription automatic;
//     it is only made invisible.
//   - A default that sends is a default that sends to third parties. An
//     outgoing webhook leaves the deployment. Between a default that stays
//     quiet until asked and a default that starts POSTing account events to
//     whatever URLs a store happens to hold, the recoverable mistake is the
//     first one: silence is fixed by adding a line, delivery is not undone by
//     removing one.
//   - U19 drew this line first and said why. WebhookEmitter.Subscribe is a call
//     a host makes rather than something a constructor does, so that a host who
//     wants this facade's ordering later has nothing to switch off. Redrawing
//     that here would strand the deployments that took it at its word.
//   - It is what the reference does. An AuthTools that subscribed would be a
//     behavioural difference to register, and the register is for differences
//     that buy something the reference's behaviour cannot.
//
// The cost is the monitoring gap, and it is real: a deployment can believe it
// is receiving login failures and not be. That is paid for with one line and a
// cancel, and Bridge is written so the line is obvious.
//
// # The loop, for a host that calls both
//
// Bridge and Track fan out through the same code. A host that calls Bridge and
// also calls Track on the same bus therefore gets the doubled delivery
// described above for the events it tracks, because both paths handle them.
// The two are alternatives per event name, not layers: Bridge is for the
// nineteen the library raises, Track is for a host's own. In practice they do
// not overlap — the library's are the identity.* set in event_names.go and a
// host's are its own — but a host that does track an identity.* name should
// call one or the other for it and not both.
type AuthTools struct {
	// Events is the bus, the reference's readonly eventBus (auth-tools.ts:161).
	// Never nil: NewAuthTools refuses one.
	Events *EventBus
	// SSE is the stream manager, the reference's readonly sseManager
	// (auth-tools.ts:162). Nil unless AuthToolsOptions.SSE was set, and every
	// read of it is guarded, because nil is the reference's default and the
	// common case.
	SSE *SseManager

	telemetry TelemetryStore
	webhooks  *WebhookEmitter
	users     UserStore
	mail      MailerTransport
	sms       SMSTransport
	onError   func(err error)
}

// NewAuthTools builds the facade: the reference's constructor
// (auth-tools.ts:170-189).
//
// ctx bounds the SSE manager's distributor subscription and nothing else, so a
// deployment that cancels it stops cross-instance delivery and leaves Track and
// Notify working on this process's own connections. It is a parameter because
// NewSseManager takes one; the reference's constructor needs no equivalent
// because its SseManager's subscription is torn down by process exit alone.
//
// A nil bus is refused rather than accepted as "no bus". The reference's first
// constructor parameter is required and untyped-optional is not available to
// it, and the reasoning WithEventBus already wrote applies here with more force:
// every one of the four sinks is silent when it is misconfigured, so a facade
// that accepted nil would fail in exactly the way that takes longest to notice.
//
// The reference's last constructor act is SseNotifyRegistry.setManager
// (auth-tools.ts:186-188), a process-global slot that its @sseNotify method
// decorator reads (sse-notify.decorator.ts:37-54). It has no counterpart here
// and needs none: Go has no method decorators, the registry exists only to give
// one a manager to reach, and a package-level mutable pointer to the most
// recently constructed AuthTools is a thing this package should not grow. A host
// that wants the decorator's effect holds its AuthTools and calls Notify.
func NewAuthTools(ctx context.Context, bus *EventBus, opts AuthToolsOptions) (*AuthTools, error) {
	if bus == nil {
		return nil, fmt.Errorf("auth: event bus is required")
	}
	t := &AuthTools{
		Events:    bus,
		telemetry: opts.Telemetry,
		users:     opts.Users,
		mail:      opts.Mail,
		sms:       opts.SMS,
		onError:   opts.OnError,
	}
	if opts.SSE {
		manager, err := NewSseManager(ctx, opts.SSEOptions...)
		if err != nil {
			return nil, fmt.Errorf("auth: auth tools sse: %w", err)
		}
		t.SSE = manager
	}
	t.webhooks = &WebhookEmitter{
		Store:   opts.Webhooks,
		Sender:  opts.WebhookSender,
		Version: opts.WebhookVersion,
	}
	if opts.OnError != nil {
		// WebhookEmitter reports per subscription and this facade reports per
		// failure, so the config is folded into the message rather than dropped.
		// A zero config is the store lookup itself, which is what Emit passes.
		t.webhooks.OnError = func(config WebhookConfig, err error) {
			if config.ID == "" {
				opts.OnError(err)
				return
			}
			opts.OnError(fmt.Errorf("auth: webhook %s: %w", config.ID, err))
		}
	}
	return t, nil
}

// Track persists, publishes, broadcasts and delivers one event: the reference's
// track (auth-tools.ts:199-269).
//
// # The order
//
// Telemetry, bus, SSE, webhooks — the source's order (auth-tools.ts:216, :221,
// :233, :249), reproduced because it is observable rather than because it is
// tidy. A bus subscriber that reads the telemetry store sees the record for the
// event it is handling, because the save happened first; a subscriber that
// writes to the store races the broadcast rather than preceding it. Reordering
// these four would be a silent change to what a subscriber can assume.
//
// # What each sink receives
//
// One id and one instant are generated here and shared, which is what makes the
// four shapes describe a single event rather than four events that happened at
// almost the same time (auth-tools.ts:200-201):
//
//   - The telemetry store gets a TelemetryEvent carrying the id, the six
//     identifiers and the payload under Meta. Success and Error are left zero:
//     they are this port's own fields, the reference's telemetry record has no
//     counterpart for either (telemetry-store.interface.ts:4-25), and a tracked
//     event is a thing that happened rather than a thing that succeeded. A host
//     querying telemetry should not read Success on a record Track wrote.
//   - The bus gets the Event, which is the payload plus the six identifiers and
//     nothing else new.
//   - The stream gets a StreamEvent whose Data is the *whole telemetry record*,
//     not the payload — see the frame note below.
//   - Each matching subscription gets the OutgoingWebhookEvent that
//     Event.OutgoingWebhook builds, whose metadata is four identifiers and
//     deliberately not the IP or the user agent.
//
// # The frame carries the record, not the payload
//
// U20 left this open and the source settles it: the StreamEvent's data is
// `telemetryEvent` (auth-tools.ts:240), the same object step 1 persisted, not
// the caller's `data`. So a client parsing a frame reads the payload at
// `rawData.data` and not at `rawData`, and gets the correlation id, the session
// id, the IP and the user agent alongside it. That is a larger frame than the
// payload alone and it is the right one: the stream is the live view of the
// telemetry the store is accumulating, and a client that can see an event but
// not which request caused it cannot line the two up. It also settles what the
// SSE step does *not* do — there is no projection to invent and keep in step
// with the record.
//
// The record is spelled on the wire with the reference's key names, which is
// what trackedRecord exists for. TelemetryEvent's Go field names are not the
// reference's JSON keys, and a frame carrying `EventName` and `Meta` where the
// reference carries `event` and `data` would be a different wire shape for no
// reason.
//
// # Failure isolation
//
// Nothing a sink does can fail this call, and nothing a sink does can stop
// another sink. That is the source's behaviour reproduced sink by sink, and
// Track returns nothing because after reproducing it there is nothing left to
// report:
//
//   - Telemetry. The save is awaited, so a slow store delays the other three,
//     and its error is discarded — `.catch(() => {})` (auth-tools.ts:218). The
//     event is still published, broadcast and delivered.
//   - The bus. The reference publishes unguarded (auth-tools.ts:231), so a
//     throwing subscriber there skips the SSE and webhook steps entirely and
//     fails whatever called track. Here it cannot: EventBus.Publish recovers
//     each handler, which is the deviation
//     event-handler-panic-does-not-fail-the-publisher, already registered by
//     U18. This step inherits that containment rather than adding one.
//   - SSE. Broadcast returns nothing in both trees and falls back to local
//     delivery when a distributor fails, so a stream that reaches nobody is not
//     an error anyone hears about (auth-tools.ts:245).
//   - Webhooks. A store lookup failure is no webhooks rather than a failure —
//     `.catch(() => [])` (auth-tools.ts:251) — and each delivery is
//     fire-and-forget with its own error discarded (:266). WebhookEmitter.Emit
//     already reproduces both.
//
// AuthToolsOptions.OnError hears about every one of these that produced an
// error value. It changes nothing about the flow.
//
// # data is map[string]any
//
// The reference's is `unknown` (auth-tools.ts:199). This narrowing is the one
// Event.Data already carries, for the reasons written there, and Track cannot
// widen it: the payload it is handed becomes Event.Data at step 2. A caller
// with a scalar wraps it in a map and names it, which is what every publication
// point in both trees does anyway.
//
// ctx fills what the caller left empty. The reference's track never reads a
// request — its route reads the two headers and passes them as options
// (tools.router.ts:144-145, :154-155) — and a route here may do exactly that.
// One that does not gets the provenance an adapter captured, because
// Event.WithRequestContext fills only empty fields and so an explicit option
// always wins. Both spellings produce the same event.
func (t *AuthTools) Track(ctx context.Context, eventName string, data map[string]any, opts TrackOptions) {
	if t == nil {
		return
	}
	// Enriched once, here, so that all four sinks see the same event. Doing it
	// at the bus step instead — the way Service.publish does, through
	// PublishContext — would enrich the bus's copy alone and leave the record,
	// the frame and the webhook envelope without the provenance.
	ev := Event{
		Name:          eventName,
		UserID:        opts.UserID,
		TenantID:      opts.TenantID,
		Timestamp:     time.Now(),
		Data:          data,
		SessionID:     opts.SessionID,
		CorrelationID: opts.CorrelationID,
		IP:            opts.IP,
		UserAgent:     opts.UserAgent,
	}.WithRequestContext(ctx)
	t.fanOut(ctx, ev, true)
}

// Bridge runs the library's own publications through the same fan-out Track
// uses, and returns the function that stops doing so.
//
// This is the opt-in described at length on AuthTools: nothing calls it, and
// until a host does, the nineteen identity.* events the service layer raises
// reach the bus and stop. Calling it is the whole of the wiring —
//
//	tools, err := auth.NewAuthTools(ctx, bus, auth.AuthToolsOptions{
//		Telemetry: store, Webhooks: hooks, SSE: true,
//	})
//	stop := tools.Bridge(ctx)
//	defer stop()
//
// — and it replaces the two lower-level calls a host would otherwise write,
// WebhookEmitter.Subscribe and SseManager.BridgeEventBus, with one that also
// persists the telemetry record, applies EventTopics rather than a topic rule
// invented at the call site, and gives a bridged event the same id, the same
// frame shape and the same envelope a tracked one gets. Those two remain for a
// host that wants one sink and not the others.
//
// The bus step is skipped, and only that one: the event being handled arrived
// *from* the bus, and republishing it would feed this subscription its own
// output forever. The other three run in the order Track runs them.
//
// ctx is the bridge's lifetime and is handed to each sink. It carries no
// request, so nothing is filled from it — a bus event already has the
// provenance PublishContext put there when the service published it.
func (t *AuthTools) Bridge(ctx context.Context) (cancel func()) {
	if t == nil || t.Events == nil {
		return func() {}
	}
	return t.Events.Subscribe(EventBusWildcard, func(ev Event) {
		t.fanOut(ctx, ev, false)
	})
}

// fanOut is steps 1 to 4, with the bus step optional. Track runs it with the
// publication, Bridge without; see both for why.
func (t *AuthTools) fanOut(ctx context.Context, ev Event, publishOnBus bool) {
	// One id per event, generated here and reused by the record and by every
	// topic the frame goes to. Broadcast would mint one per call otherwise, and
	// a connection holding both `global` and `user:x` would receive the event
	// twice — the constraint Broadcast and StreamEvent.ID both state.
	//
	// newUUIDv4's error cannot occur on any platform this builds for; the
	// comment in Broadcast covers why the value is taken and the error dropped.
	id, _ := newUUIDv4()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	record := TelemetryEvent{
		ID:            id,
		EventName:     ev.Name,
		UserID:        ev.UserID,
		TenantID:      ev.TenantID,
		SessionID:     ev.SessionID,
		CorrelationID: ev.CorrelationID,
		IP:            ev.IP,
		UserAgent:     ev.UserAgent,
		Timestamp:     ev.Timestamp,
		Meta:          ev.Data,
	}

	// 1. Persist (auth-tools.ts:216-219).
	if t.telemetry != nil {
		if err := t.telemetry.Record(ctx, record); err != nil {
			t.reportError(fmt.Errorf("auth: telemetry record for %q: %w", ev.Name, err))
		}
	}

	// 2. Emit on the event bus (auth-tools.ts:221-231). Publish and not
	// PublishContext: the event was enriched before step 1 so that every sink
	// saw the same one, and re-applying the context here would be a second pass
	// over fields that are already filled.
	if publishOnBus {
		t.Events.Publish(ev)
	}

	// 3. SSE broadcast (auth-tools.ts:233-247).
	if t.SSE != nil {
		frame := StreamEvent{
			ID:        id,
			Type:      ev.Name,
			Timestamp: WebhookTimestamp(ev.Timestamp),
			Data:      newTrackedRecord(record),
			UserID:    ev.UserID,
			TenantID:  ev.TenantID,
		}
		for _, topic := range EventTopics(ev) {
			t.SSE.Broadcast(ctx, topic, frame)
		}
	}

	// 4. Outgoing webhooks (auth-tools.ts:249-268), whole.
	t.webhooks.Emit(ctx, ev)
}

// EventTopics resolves the SSE topics one event is broadcast to: the
// reference's private resolveTopics (auth-tools.ts:353-359).
//
// Always `global`; then `tenant:<id>`, `user:<id>` and `session:<id>` for each
// identifier the event carries. It is exported because a host wiring
// SseManager.BridgeEventBus directly needs the same rule Track applies, and a
// second copy written at the call site is the thing that drifts:
//
//	stop := sse.BridgeEventBus(ctx, bus, auth.EventTopics)
//
// # It does not agree with the subscribe side, and that is the source
//
// StreamTopics authorises three kinds of topic and this produces four. The
// reference has the same gap: its stream route builds `global`, `tenant:<id>`
// and `user:<id>` and nothing else (tools.router.ts:207-210), so the
// `session:<id>` topic this publishes to is one no client connected through
// that route can ever hold. Every event with a session id is therefore
// broadcast to a topic with no subscribers.
//
// It is reproduced rather than corrected in either direction. Dropping the
// session topic here would remove a channel a host serving its own stream can
// use — connections are registered with whatever topics the server passes, and
// nothing but that route restricts them. Adding it to StreamTopics would widen
// what a client can subscribe to beyond what the reference allows, on a surface
// whose entire security property is that the server picks the topics. The
// broadcast to nobody costs a map lookup that matches nothing.
//
// In this port the tenant topic is unreachable too, for now and for a different
// reason: Event.TenantID is empty on everything the library currently publishes,
// so until M8 gives the service layer a tenant to put there, the library's own
// events resolve to `global`, `user:<id>` and `session:<id>`.
func EventTopics(ev Event) []string {
	topics := make([]string, 0, 4)
	topics = append(topics, SseTopicGlobal)
	if ev.TenantID != "" {
		topics = append(topics, SseTopicTenantPrefix+ev.TenantID)
	}
	if ev.UserID != "" {
		topics = append(topics, SseTopicUserPrefix+ev.UserID)
	}
	if ev.SessionID != "" {
		topics = append(topics, SseTopicSessionPrefix+ev.SessionID)
	}
	return topics
}

// StreamTopics resolves the topics one connection may hold: the reference's
// stream route, which builds the authorised list from the authenticated
// principal and filters the client's request against it
// (tools.router.ts:207-216).
//
// `global`, plus `tenant:<id>` and `user:<id>` for whichever the principal has.
// requested is what the client asked for — the `topics` query parameter, split
// and trimmed by whatever serves the route. Nothing requested means the whole
// authorised list; anything requested is intersected with it, so a client that
// asks for a topic it is not entitled to is silently given the rest, and one
// that asks only for such topics gets an empty list and a stream that never
// fires. That silence is the reference's, and it is the correct shape for a
// filter whose job is that a client cannot self-declare a channel.
//
// It lives here, beside EventTopics, because the two are one decision: what a
// publisher sends to has to be what a subscriber is allowed to hold, and the
// one place that is true is the place both are written. Mounting the route that
// calls this is U22's.
func StreamTopics(userID, tenantID string, requested []string) []string {
	authorised := make([]string, 0, 3)
	authorised = append(authorised, SseTopicGlobal)
	if tenantID != "" {
		authorised = append(authorised, SseTopicTenantPrefix+tenantID)
	}
	if userID != "" {
		authorised = append(authorised, SseTopicUserPrefix+userID)
	}
	if len(requested) == 0 {
		return authorised
	}
	final := make([]string, 0, len(requested))
	for _, want := range requested {
		for _, ok := range authorised {
			if want == ok {
				final = append(final, want)
				break
			}
		}
	}
	return final
}

// trackedRecord is the telemetry record as the SSE frame carries it: the
// reference's TelemetryEvent object, which track puts on the frame whole
// (auth-tools.ts:240).
//
// It exists for its JSON tags and for nothing else. TelemetryEvent is the
// package's own type with the package's own field names, and marshalling it
// directly would put `EventName`, `Meta` and a `Success` that Track never
// writes on the wire where the reference puts `event`, `data` and nothing.
//
// omitzero on the seven optional members, for the reason sseFrame gives: it is
// the tag that matches JSON.stringify, which drops an undefined member and
// keeps an explicitly empty one. The reference builds the record with all ten
// members and lets the encoder drop the absent ones (auth-tools.ts:203-214), so
// a frame names only the identifiers the event actually had.
type trackedRecord struct {
	ID            string         `json:"id"`
	Event         string         `json:"event"`
	Timestamp     string         `json:"timestamp"`
	Data          map[string]any `json:"data,omitzero"`
	UserID        string         `json:"userId,omitzero"`
	TenantID      string         `json:"tenantId,omitzero"`
	SessionID     string         `json:"sessionId,omitzero"`
	CorrelationID string         `json:"correlationId,omitzero"`
	IP            string         `json:"ip,omitzero"`
	UserAgent     string         `json:"userAgent,omitzero"`
}

func newTrackedRecord(record TelemetryEvent) trackedRecord {
	return trackedRecord{
		ID:            record.ID,
		Event:         record.EventName,
		Timestamp:     WebhookTimestamp(record.Timestamp),
		Data:          record.Meta,
		UserID:        record.UserID,
		TenantID:      record.TenantID,
		SessionID:     record.SessionID,
		CorrelationID: record.CorrelationID,
		IP:            record.IP,
		UserAgent:     record.UserAgent,
	}
}

// Notify delivers one payload to one topic and, optionally, to the user's inbox
// and handset: the reference's notify (auth-tools.ts:292-342).
//
// The SSE channel broadcasts to target and to target alone — this is the one
// place in the package that does not fan out across EventTopics, because a
// notification is addressed to a channel the caller names rather than derived
// from an event's identifiers. The frame carries no id and no timestamp of its
// own, so Broadcast fills both (auth-tools.ts:297-303).
//
// The email and SMS channels are reached only when a user id is given and a user
// store is configured, and then only for a user the store returns and who has
// the contact detail that channel needs (auth-tools.ts:307, :321, :333). A
// lookup that fails is a user that is absent — the reference catches it into
// null (:310-314) — so neither channel is attempted and the SSE broadcast that
// already happened stands.
//
// # Failure isolation
//
// As with Track, nothing reaches the caller: the reference's notify returns a
// promise that its own route does not await (tools.router.ts:170) and whose
// channel failures are caught individually (:329, :338). Each transport send
// runs on its own goroutine with the caller's values and without its deadline —
// context.WithoutCancel, for the reason WebhookEmitter.Emit gives: a delivery
// cancelled when the response was written is a delivery that never happened.
//
// # data is any
//
// Unlike Track's, which becomes Event.Data. This payload becomes a frame's Data
// and an encoded message body, both of which accept anything JSON accepts, so
// the reference's generic parameter (auth-tools.ts:292) survives the port intact.
func (t *AuthTools) Notify(ctx context.Context, target string, data any, opts NotifyOptions) {
	if t == nil {
		return
	}
	channels := opts.Channels
	if len(channels) == 0 {
		channels = []NotifyChannel{NotifyChannelSSE}
	}

	// 1. SSE (auth-tools.ts:295-304).
	if hasChannel(channels, NotifyChannelSSE) && t.SSE != nil {
		eventType := opts.Type
		if eventType == "" {
			eventType = "notification"
		}
		t.SSE.Broadcast(ctx, target, StreamEvent{
			Type:     eventType,
			Data:     data,
			TenantID: opts.TenantID,
			UserID:   opts.UserID,
			Metadata: opts.Metadata,
		})
	}

	// 2. Email and SMS (auth-tools.ts:306-341).
	wantEmail := hasChannel(channels, NotifyChannelEmail)
	wantSMS := hasChannel(channels, NotifyChannelSMS)
	if (!wantEmail && !wantSMS) || opts.UserID == "" || t.users == nil {
		return
	}
	// GetUserByID takes the tenant the reference's findById does not; the
	// options carry one and an empty one is the untenanted lookup every
	// single-tenant deployment makes.
	user, err := t.users.GetUserByID(ctx, opts.UserID, opts.TenantID)
	if err != nil {
		// The reference's `catch { user = null }` (:312-313): an absent user is
		// not a failure, it is two channels that do not apply.
		t.reportError(fmt.Errorf("auth: notify lookup for user %s: %w", opts.UserID, err))
		return
	}
	detached := context.WithoutCancel(ctx)

	// 2a. Email (auth-tools.ts:320-330).
	if wantEmail && user.Email != "" && t.mail != nil {
		body, err := notifyBody(data, true)
		if err != nil {
			t.reportError(fmt.Errorf("auth: notify email body: %w", err))
		} else {
			subject := opts.EmailSubject
			if subject == "" {
				subject = opts.Type
			}
			if subject == "" {
				subject = "Notification"
			}
			// `<p>${body.replace(/\n/g, '<br>')}</p>` (:327), interpolated raw
			// there and interpolated raw here. Escaping the body would be the
			// safer-looking choice and the wrong one: the payload is the host's
			// own, a host that puts markup in a notification means it, and this
			// package silently rewriting a message it was asked to deliver is a
			// worse surprise than the one it would prevent. The recipient is the
			// host's own user and the transport is email, where the markup a
			// client will render is a narrow subset in the first place.
			msg := MailMessage{
				To:      user.Email,
				Subject: subject,
				Body:    "<p>" + strings.ReplaceAll(body, "\n", "<br>") + "</p>",
				IsHTML:  true,
				Text:    body,
			}
			transport := t.mail
			go func() {
				if err := transport.Send(detached, msg); err != nil {
					t.reportError(fmt.Errorf("auth: notify email to user %s: %w", opts.UserID, err))
				}
			}()
		}
	}

	// 2b. SMS (auth-tools.ts:332-339).
	if wantSMS && user.PhoneNumber != "" && t.sms != nil {
		message := opts.SMSMessage
		if message == "" {
			// Not indented, where the email body is (:334 against :323). The two
			// defaults encode the same payload with different spacing because
			// the reference passes `null, 2` to one JSON.stringify and not to
			// the other, and a message billed by the character should not carry
			// the indentation anyway.
			encoded, err := notifyBody(data, false)
			if err != nil {
				t.reportError(fmt.Errorf("auth: notify sms body: %w", err))
				return
			}
			message = encoded
		}
		phone, transport := user.PhoneNumber, t.sms
		go func() {
			if err := transport.Send(detached, phone, message); err != nil {
				t.reportError(fmt.Errorf("auth: notify sms to user %s: %w", opts.UserID, err))
			}
		}()
	}
}

// notifyBody is the reference's `typeof data === 'string' ? data :
// JSON.stringify(data, …)` (auth-tools.ts:323, :334).
//
// SetEscapeHTML(false) for the reason sseMarshal gives — encoding/json escapes
// <, > and & and JSON.stringify does not — and here it matters twice over,
// since the result is both interpolated into an HTML mail body and used as the
// plain-text alternative, and a reader of the second would see the escapes.
func notifyBody(data any, indent bool) (string, error) {
	if s, ok := data.(string); ok {
		return s, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(data); err != nil {
		return "", err
	}
	// Encoder.Encode appends a newline JSON.stringify does not produce.
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

// hasChannel is `channels.includes(…)`. A linear scan over a slice that is
// never longer than three.
func hasChannel(channels []NotifyChannel, want NotifyChannel) bool {
	for _, c := range channels {
		if c == want {
			return true
		}
	}
	return false
}

// reportError hands one swallowed failure to AuthToolsOptions.OnError, and
// drops it when there is none — which is the default, and is the reference.
func (t *AuthTools) reportError(err error) {
	if t.onError != nil {
		t.onError(err)
	}
}
