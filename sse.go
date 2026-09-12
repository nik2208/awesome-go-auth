package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// StreamEvent is one real-time event as it reaches an SSE subscriber: the
// reference's StreamEvent (sse-manager.ts:8-25).
//
// The JSON tags are not the tags of the SSE frame. They are the shape a
// distributor carries, and that distinction is the first thing an implementor
// of SseDistributor needs: ISseDistributor.publish takes the whole StreamEvent
// object (sse-distributor.interface.ts:17), so a Redis or an SNS
// implementation serialises *this*, while the `data:` line of the frame a
// browser receives is a different, reshaped object — see sseFrame. A
// distributor written against the reference in TypeScript and one written
// against this port in Go therefore agree on the bytes they exchange, which is
// the only reason a mixed fleet can work.
//
// Timestamp is a string rather than a time.Time because it crosses the wire
// verbatim: the reference produces it with Date.prototype.toISOString
// (sse-manager.ts:185), and a round trip through time.Time would renormalise
// the one field whose spelling a client may be matching on. Broadcast fills an
// empty one in toISOString's own form — UTC, exactly three fractional digits, a
// literal Z — which is webhookTimestampLayout, already defined for the outgoing
// webhook envelope in delivery_webhook.go and the same format for the same
// reason.
type StreamEvent struct {
	// ID is the event's identity: the `id:` line of the frame, and the value
	// per-connection deduplication compares. Broadcast fills an empty one with
	// a fresh UUIDv4 (sse-manager.ts:184).
	//
	// A publisher that fans one event out to several topics must generate the
	// id once and reuse it, because that is the only thing that makes the
	// deduplication work — see the comment on Deduplicate.
	ID string `json:"id"`
	// Type is the event name: the `event:` line of the frame, which is what an
	// EventSource dispatches on.
	Type string `json:"type"`
	// Timestamp is ISO 8601. Broadcast fills an empty one.
	Timestamp string `json:"timestamp"`
	// Topic is the channel the event was published to. Broadcast overwrites it
	// with the topic it was called with, so a value set here is not honoured;
	// the reference's input type omits the field for the same reason
	// (sse-manager.ts:181).
	Topic string `json:"topic"`
	// Data is the payload. It reaches the browser under the key `rawData`, not
	// `data` — see sseFrame.
	Data any `json:"data"`
	// UserID and TenantID are optional context. TenantID is not decoration: it
	// is read by the tenant check in broadcastLocal.
	UserID   string `json:"userId,omitzero"`
	TenantID string `json:"tenantId,omitzero"`
	// Metadata is optional extra context, carried and never interpreted.
	Metadata map[string]any `json:"metadata,omitzero"`
}

// sseFrame is the object the reference puts on the `data:` line, and it is not
// StreamEvent.
//
// The reference builds it as `{...event, data: undefined, rawData: event.data}`
// (sse-manager.ts:252). Two things follow, and both are wire facts a client
// parses against: the key `data` is *absent* — JSON.stringify drops an
// undefined value rather than writing null — and the payload arrives under
// `rawData` instead. A client reading `JSON.parse(e.data).data` gets undefined
// against the reference and against this port alike.
//
// The field order is this port's, because the reference does not have one. In
// JavaScript the order is whatever the caller's object literal was, and the
// reference's own two call sites already disagree: AuthTools.track spells the
// event `{id, timestamp, type, data, userId, tenantId}` (auth-tools.ts:236-243)
// and the sseNotify decorator spells it `{type, data, tenantId, userId}`
// (sse-notify.decorator.ts:68-73), so userId and tenantId come out in opposite
// orders depending on which one published. The order below is the one the first
// of those produces, since it is the path every identity event takes. No client
// can see the difference — key order is not information a JSON parser carries —
// and there is no single order to reproduce, so this is a fixed choice rather
// than a deviation.
//
// omitzero rather than omitempty, on all three optional fields, because it is
// the tag that matches JSON.stringify: an absent key is omitted, and an
// explicitly empty one is not. A StreamEvent carrying
// `Metadata: map[string]any{}` therefore writes `"metadata":{}`, exactly as the
// reference would.
type sseFrame struct {
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Topic     string         `json:"topic"`
	Type      string         `json:"type"`
	UserID    string         `json:"userId,omitzero"`
	TenantID  string         `json:"tenantId,omitzero"`
	Metadata  map[string]any `json:"metadata,omitzero"`
	RawData   any            `json:"rawData"`
}

// sseConnectedFrame is the first frame every connection receives
// (sse-manager.ts:140-146). It has its own type rather than going through
// sseFrame because the reference's literal there is ordered differently —
// `{id, type, timestamp, topic, data}`, so `type` precedes `timestamp` — and
// reproducing both orders costs one struct.
//
// It carries no userId, no tenantId and no metadata: the literal sets none, so
// JSON.stringify writes none.
type sseConnectedFrame struct {
	ID        string           `json:"id"`
	Type      string           `json:"type"`
	Timestamp string           `json:"timestamp"`
	Topic     string           `json:"topic"`
	RawData   sseConnectedData `json:"rawData"`
}

// sseConnectedData is the connected frame's payload: the connection's id, so a
// client can name itself, and the topics the server decided it may receive. The
// topics are the slice as given, duplicates and all — the reference sends the
// array it was passed and builds its Set separately (sse-manager.ts:145, :151).
type sseConnectedData struct {
	ConnectionID string   `json:"connectionId"`
	Topics       []string `json:"topics"`
}

// sseHeartbeatFrame is the keep-alive the reference writes, byte for byte
// (sse-manager.ts:159): a colon, a space, the word, and the blank line that ends
// a frame.
//
// The word is written with a leading space although the documentation beside it
// says `:heartbeat` without one (sse-manager.ts:47, :93). The code is the
// contract — it is what a socket carries and what a proxy's buffer sees — so the
// space stays. An SSE comment is any line beginning with a colon and is
// discarded by the parser, so no EventSource handler ever observes it; what it
// is for is keeping an idle connection out of the way of an intermediary's idle
// timeout.
const sseHeartbeatFrame = ": heartbeat\n\n"

// DefaultSseHeartbeatInterval is the reference's default of 30 000 ms
// (sse-manager.ts:105).
const DefaultSseHeartbeatInterval = 30 * time.Second

// defaultSseSendBuffer is how many frames a connection may fall behind by before
// it is disconnected. See the deviation sse-slow-consumer-is-disconnected, which
// is where the policy is argued; this is only its size.
const defaultSseSendBuffer = 64

// sseWriteTimeout bounds one write to one connection.
//
// Without it a write to a client that has stopped reading but has not closed its
// socket blocks the handler's goroutine until TCP gives up, which is minutes.
// The frames are a few hundred bytes, so ten seconds is not a slow link, it is a
// link that is gone.
const sseWriteTimeout = 10 * time.Second

// ErrSseStreamingUnsupported is returned by SseManager.Serve when the
// http.ResponseWriter it was handed cannot be flushed, so nothing it wrote would
// reach the client before the handler returned. Nothing has been written to the
// response when it is returned, so a caller may still answer the request itself.
var ErrSseStreamingUnsupported = errors.New("auth: response writer does not support streaming")

// SseDistributor carries events between instances: the reference's
// ISseDistributor (sse-distributor.interface.ts:10-25).
//
// SSE connections live in the memory of one process. Every deployment that runs
// more than one process therefore has a fan-out problem, and this is the only
// seam that solves it — the manager has no other way to reach a connection it
// does not hold. For awesome-lambda-auth it is not an optional scaling knob at
// all: on a Function URL every connection is its own execution environment, so a
// manager without a distributor can only ever deliver an event to the one
// connection that happens to share an environment with whatever published it.
//
// What a distributor owes, stated here because the reference's interface states
// none of it and an implementor otherwise has to infer it from the manager's
// code:
//
//   - Ordering. Nothing is required. The manager applies no sequence numbers and
//     no reordering: frames go out in the order Subscribe delivers them, so the
//     order a subscriber sees is the distributor's order and not the publisher's.
//     A distributor that preserves per-topic order gives clients per-topic order;
//     one that does not, does not.
//   - Duplication. At-most-once is safe: nothing here retries, acknowledges or
//     replays, so a dropped event is simply not delivered and no state is left
//     inconsistent. At-least-once is also safe, but only just — the manager's
//     deduplication compares an event's id against the *previous* event sent to
//     that connection and nothing older, so a redelivery that arrives
//     immediately is absorbed and one that arrives after another event is
//     delivered twice. A distributor that can redeliver out of order should
//     assume its subscribers will see duplicates.
//   - Unavailability. Publish returning an error makes Broadcast fall back to a
//     local-only delivery (sse-manager.ts:191-194): the event reaches the
//     connections this instance holds and no others. That is the whole of the
//     failure handling — there is no queue, no retry and no signal to the
//     caller, because broadcast returns void in the reference and Broadcast
//     returns nothing here.
//
// The sharpest consequence, and the one to design around: when a distributor is
// configured, Broadcast does *not* deliver locally. It publishes, and the local
// connections are served only when the distributor calls back the subscription
// (sse-manager.ts:190-197). A distributor that does not echo a publisher's own
// events back to it delivers every event to every instance except the one that
// raised it. A distributor that fails silently — returns no error and drops the
// event — delivers it to nobody at all, including the connections in the same
// process.
type SseDistributor interface {
	// Publish sends one event to the distribution bus under topic. An error
	// makes the manager deliver the event to its local connections instead.
	Publish(ctx context.Context, topic string, event StreamEvent) error
	// Subscribe registers fn to receive events from the bus and returns once
	// the subscription is established; the pump that calls fn is the
	// implementation's own. fn may be called from any goroutine and may be
	// called concurrently. ctx bounds the subscription's life: when it is
	// cancelled the implementation must stop calling fn.
	//
	// The reference calls this from its constructor and does not await the
	// promise (sse-manager.ts:110-112), so there a subscription that fails
	// leaves a manager that silently never receives a remote event. Here the
	// error reaches NewSseManager, which refuses to build one.
	Subscribe(ctx context.Context, fn func(topic string, event StreamEvent)) error
}

// SseConnectionMeta is the optional user and tenant context a connection is
// registered with: the reference's `meta` parameter (sse-manager.ts:128).
//
// TenantID is the one that has an effect. An event carrying a tenant id is
// withheld from a connection whose tenant id is set and different — and,
// deliberately, from nobody else. A connection registered with no tenant id
// receives every tenant's events on the topics it holds, which is the
// reference's rule (sse-manager.ts:211) and is a rule the caller has to mean: it
// is there so that an operator-facing connection can watch a whole deployment,
// and it makes an empty TenantID a privilege rather than an omission.
type SseConnectionMeta struct {
	UserID   string
	TenantID string
}

// SseOption configures an SseManager. The options exist rather than an options
// struct because two of the settings are tri-state in the reference — absent
// means one thing and zero means another — and a Go struct field cannot hold
// that distinction. WithSseHeartbeat(0) is the reference's
// `heartbeatIntervalMs: 0`, and passing no option at all is its `undefined`.
type SseOption func(*SseManager)

// WithSseHeartbeat sets the interval between heartbeat comments. Zero disables
// them, as the reference's 0 does (sse-manager.ts:48-51, :156). A negative value
// is treated as zero.
func WithSseHeartbeat(d time.Duration) SseOption {
	return func(m *SseManager) { m.heartbeat = d }
}

// WithSseDeduplicate turns per-connection deduplication by event id off. It is
// on by default, matching `options?.deduplicate !== false` (sse-manager.ts:106).
func WithSseDeduplicate(on bool) SseOption {
	return func(m *SseManager) { m.deduplicate = on }
}

// WithSseDistributor attaches a distributor for cross-instance fan-out. See
// SseDistributor, and note that attaching one changes where local connections
// are served from.
func WithSseDistributor(d SseDistributor) SseOption {
	return func(m *SseManager) { m.distributor = d }
}

// WithSseSendBuffer sets how many frames may be queued for one connection before
// that connection is disconnected. It has no counterpart in the reference, which
// queues without limit; see the deviation sse-slow-consumer-is-disconnected.
// Values below one are raised to one.
func WithSseSendBuffer(frames int) SseOption {
	return func(m *SseManager) { m.sendBuffer = frames }
}

// SseManager holds the open SSE streams and broadcasts StreamEvents to the ones
// subscribed to a topic: the reference's SseManager (sse-manager.ts:88).
//
// Topics are matched by exact string equality against the set a connection was
// registered with (sse-manager.ts:206). The reference documents a hierarchical
// scheme —
//
//	global
//	tenant:{tenantId}
//	tenant:{tenantId}:role:{role}
//	tenant:{tenantId}:group:{groupId}
//	user:{userId}
//	session:{sessionId}
//	custom:{namespace}
//
// — and it is a naming convention and nothing more: no prefix, no wildcard and
// no ancestor matching exists in either implementation, so a connection holding
// `tenant:acme` does not receive `tenant:acme:role:admin`. A publisher that
// wants both sends to both, which is what the deduplication is for.
//
// The server decides a connection's topics. There is no client-supplied channel
// anywhere in the protocol, which is the property that makes SSE here safe to
// expose to a browser at all (sse-manager.ts:85-86).
//
// What this port adds, because Go has no Express Response that stays open on its
// own: Serve blocks the request goroutine for the life of the stream, a bounded
// queue stands between a publisher and a connection so that one slow reader
// cannot stall the publisher, and a connection whose queue overflows is
// disconnected. That last is the one client-visible difference and it is
// registered as sse-slow-consumer-is-disconnected.
//
// What neither implementation does, stated here because it is the question every
// consumer asks second: there is no resume. Nothing reads the Last-Event-ID
// request header a browser sends when its EventSource reconnects, nothing
// retains a delivered event, and the per-connection lastEventID exists only to
// compare against the next event's id (sse-manager.ts:214) — it is never read on
// a new connection, because a new connection is a new entry in the map with an
// empty one. A client that reconnects resumes from *now*, and the events raised
// while it was away are gone. The `id:` line is therefore an identity and a
// deduplication key, not a cursor. Anything that needs delivery across a
// reconnect has to add an event log of its own, and it would be adding a
// guarantee rather than implementing one.
type SseManager struct {
	heartbeat   time.Duration
	deduplicate bool
	sendBuffer  int
	distributor SseDistributor

	mu          sync.RWMutex
	connections map[string]*sseConnection
}

// NewSseManager builds a manager. With no options it is the reference's
// `new SseManager()`: heartbeats every 30 seconds, deduplication on, no
// distributor.
//
// It takes a context and can fail, where the reference's constructor does
// neither. Both follow from the distributor: ISseDistributor.subscribe returns a
// promise the reference neither awaits nor catches (sse-manager.ts:110-112), so
// a distributor that cannot reach its bus yields a manager that looks healthy
// and receives nothing from the rest of the fleet. Here the subscription is
// established before the manager is returned and a failure to establish it is a
// failure to construct, which is the difference between a deployment that fails
// at start-up and one that fails silently under load. ctx bounds the
// subscription and nothing else: cancelling it stops the distributor's
// callbacks, and open connections are ended by their own requests' contexts.
func NewSseManager(ctx context.Context, opts ...SseOption) (*SseManager, error) {
	m := &SseManager{
		heartbeat:   DefaultSseHeartbeatInterval,
		deduplicate: true,
		sendBuffer:  defaultSseSendBuffer,
		connections: make(map[string]*sseConnection),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	if m.heartbeat < 0 {
		m.heartbeat = 0
	}
	if m.sendBuffer < 1 {
		m.sendBuffer = 1
	}
	if m.distributor != nil {
		if err := m.distributor.Subscribe(ctx, m.broadcastLocal); err != nil {
			return nil, fmt.Errorf("auth: sse distributor subscribe: %w", err)
		}
	}
	return m, nil
}

// HeartbeatInterval is the configured heartbeat interval, zero when disabled:
// the reference's readonly heartbeatIntervalMs (sse-manager.ts:97).
func (m *SseManager) HeartbeatInterval() time.Duration { return m.heartbeat }

// Deduplicate reports whether events are deduplicated by id per connection: the
// reference's readonly deduplicate (sse-manager.ts:102).
//
// The name is the reference's and it promises more than it does. What it
// compares is the incoming event's id against the id of the *last* event sent to
// that connection, and nothing older (sse-manager.ts:214), so it suppresses an
// immediate repeat and not a repeat with anything in between. That is enough for
// the case it exists for — one event fanned out to several topics one after
// another, where a connection subscribed to two of them would otherwise receive
// it twice — and it is not a general guard against redelivery. See
// SseDistributor.
func (m *SseManager) Deduplicate() bool { return m.deduplicate }

// ConnectionCount is the number of open connections: the reference's
// connectionCount getter (sse-manager.ts:241-243).
func (m *SseManager) ConnectionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.connections)
}

// Serve registers an SSE connection on w for the given topics and streams to it
// until the client goes away, the request's context is cancelled, or the
// connection is disconnected. It returns nil on an ordinary end and an error
// when the stream failed.
//
// This is the reference's connect (sse-manager.ts:125-172) plus the part Express
// does implicitly. There, connect writes the headers and the first frame, arms a
// setInterval for the heartbeat, registers a `close` listener and returns while
// the Response stays open; the framework holds the socket. Go has nothing that
// holds it: a handler that returns has ended the response. So the whole life of
// the connection is inside this call, the request goroutine is the connection's
// pump, and the two shapes are the same protocol written for two runtimes.
//
// The order of operations is the reference's, and it is observable: the
// connected frame is written *before* the connection is registered, so an event
// broadcast in the window between them reaches this connection not at all. The
// frame also does not seed the deduplication state, because the connection it
// would seed does not exist yet (sse-manager.ts:140 against :166).
//
// topics is the server's decision and is not read from the request. meta is the
// user and tenant context; see SseConnectionMeta for what an empty TenantID
// means.
func (m *SseManager) Serve(w http.ResponseWriter, r *http.Request, topics []string, meta SseConnectionMeta) error {
	// The four headers the reference sets, in its order (sse-manager.ts:133-136).
	// X-Accel-Buffering is the one that is not decoration: nginx buffers a
	// proxied response by default, which holds every frame until the buffer
	// fills and turns a live stream into a batch. Connection is hop-by-hop and
	// Go manages it itself — the HTTP/2 server drops it — which costs nothing
	// and keeps the HTTP/1.1 bytes the same as the reference's.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	// res.flushHeaders() (sse-manager.ts:137). A client that has to wait for the
	// first event to learn the response has begun cannot distinguish a stream
	// from a hung request. The flush is also the probe: a writer that cannot be
	// flushed cannot stream, and ResponseController reports that without having
	// written anything, so the caller still owns the response.
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		h.Del("Content-Type")
		h.Del("Cache-Control")
		h.Del("Connection")
		h.Del("X-Accel-Buffering")
		return ErrSseStreamingUnsupported
	}

	id, err := newUUIDv4()
	if err != nil {
		return err
	}
	if topics == nil {
		// The reference's parameter is a string[] and JSON.stringify writes
		// `[]` for an empty one; a nil Go slice would write null.
		topics = []string{}
	}
	if err := m.writeConnected(w, rc, id, topics); err != nil {
		return err
	}

	conn := &sseConnection{
		id:       id,
		topics:   make(map[string]struct{}, len(topics)),
		userID:   meta.UserID,
		tenantID: meta.TenantID,
		out:      make(chan []byte, m.sendBuffer),
		done:     make(chan struct{}),
	}
	for _, t := range topics {
		conn.topics[t] = struct{}{}
	}

	m.mu.Lock()
	m.connections[id] = conn
	m.mu.Unlock()
	// The reference's res.on('close', …) (sse-manager.ts:169), and every other
	// way out of the loop below.
	defer m.Disconnect(id)

	// A nil channel blocks for ever, which is what a disabled heartbeat is.
	var beat <-chan time.Time
	if m.heartbeat > 0 {
		ticker := time.NewTicker(m.heartbeat)
		defer ticker.Stop()
		beat = ticker.C
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.done:
			return nil
		case frame := <-conn.out:
			if err := sseWrite(w, rc, frame); err != nil {
				return err
			}
		case <-beat:
			if err := sseWrite(w, rc, []byte(sseHeartbeatFrame)); err != nil {
				return err
			}
		}
	}
}

// writeConnected sends the frame the reference writes before it registers the
// connection (sse-manager.ts:140-146). Its event id is a second UUID, distinct
// from the connection id the payload carries.
func (m *SseManager) writeConnected(w http.ResponseWriter, rc *http.ResponseController, connectionID string, topics []string) error {
	eventID, err := newUUIDv4()
	if err != nil {
		return err
	}
	frame, err := sseFrameBytes(eventID, "connected", sseConnectedFrame{
		ID:        eventID,
		Type:      "connected",
		Timestamp: sseTimestamp(),
		Topic:     "meta",
		RawData:   sseConnectedData{ConnectionID: connectionID, Topics: topics},
	})
	if err != nil {
		return err
	}
	return sseWrite(w, rc, frame)
}

// Broadcast sends ev to every connection subscribed to topic: the reference's
// broadcast (sse-manager.ts:179-198).
//
// An empty ID and an empty Timestamp are filled, and Topic is overwritten with
// topic. It returns nothing, as the reference's does, so a failure to reach
// anyone is not reported to the caller; the fallbacks are described on
// SseDistributor.
//
// A caller fanning one event across several topics must build the StreamEvent
// once, with its id, and pass the same value to each call. Letting Broadcast
// generate an id per call defeats the deduplication and delivers the event once
// per matching topic to a connection holding several of them; the reference's
// own caller builds it once for exactly this reason (auth-tools.ts:236-243,
// :245-247).
func (m *SseManager) Broadcast(ctx context.Context, topic string, ev StreamEvent) {
	if ev.ID == "" {
		// crypto/rand.Read does not fail on any platform this builds for — it
		// panics rather than returning an error — so an id is always produced;
		// the error exists only because the shared helper returns one.
		ev.ID, _ = newUUIDv4()
	}
	if ev.Timestamp == "" {
		ev.Timestamp = sseTimestamp()
	}
	ev.Topic = topic

	if m.distributor == nil {
		m.broadcastLocal(topic, ev)
		return
	}
	if err := m.distributor.Publish(ctx, topic, ev); err != nil {
		// sse-manager.ts:191-194. There the fallback runs in a .catch() on a
		// floating promise, so it happens after broadcast has already returned;
		// here it is inline, which is the same delivery in a runtime that has an
		// error to look at.
		m.broadcastLocal(topic, ev)
	}
}

// broadcastLocal delivers to this process's connections only. It is the callback
// a distributor calls back on, and the fallback when one fails: the reference's
// private broadcastLocal (sse-manager.ts:204-221).
func (m *SseManager) broadcastLocal(topic string, ev StreamEvent) {
	frame, err := sseFrameBytes(ev.ID, ev.Type, sseFrame{
		ID:        ev.ID,
		Timestamp: ev.Timestamp,
		Topic:     ev.Topic,
		Type:      ev.Type,
		UserID:    ev.UserID,
		TenantID:  ev.TenantID,
		Metadata:  ev.Metadata,
		RawData:   ev.Data,
	})

	// Selection under the read lock, delivery outside it. The reference iterates
	// its Map and calls disconnect from inside the loop, which a JavaScript Map
	// tolerates; here a write lock cannot be taken while a read lock is held,
	// and a snapshot delivers to the same set either way.
	//
	// The set is in map order, so two connections are not served in the
	// deterministic order the reference's insertion-ordered Map serves them in.
	// No client can observe the order another client's frame was written in, and
	// each connection's own frames stay in publication order because each has
	// one queue and one writer.
	m.mu.RLock()
	targets := make([]*sseConnection, 0, len(m.connections))
	for _, conn := range m.connections {
		if _, ok := conn.topics[topic]; !ok {
			continue
		}
		// Tenant isolation (sse-manager.ts:211). Both sides must be set for the
		// check to bite: an event with no tenant id goes everywhere, and a
		// connection with no tenant id receives everything. See
		// SseConnectionMeta.
		if ev.TenantID != "" && conn.tenantID != "" && conn.tenantID != ev.TenantID {
			continue
		}
		targets = append(targets, conn)
	}
	m.mu.RUnlock()

	if err != nil {
		// An unserialisable payload. The reference calls JSON.stringify inside
		// the per-connection try (sse-manager.ts:213-219, :252), so a throw
		// there disconnects that connection — and then the next, and the next,
		// because the loop carries on and every one of them throws too. The
		// result is that every subscriber of the topic is dropped, which is
		// reproduced here rather than softened into a silent no-op: a caller who
		// broadcasts a value that cannot be encoded has a bug, and an event
		// plane that swallows it is the worse of the two failures.
		for _, conn := range targets {
			m.Disconnect(conn.id)
		}
		return
	}

	for _, conn := range targets {
		if !conn.enqueue(ev.ID, frame, m.deduplicate) {
			m.Disconnect(conn.id)
		}
	}
}

// Disconnect closes and forgets one connection: the reference's disconnect
// (sse-manager.ts:226-236). It is idempotent, and safe to call on an id that is
// already gone.
//
// The id is the one the client read from the connectionId of its connected
// frame, which is the only place it is published.
func (m *SseManager) Disconnect(connectionID string) {
	m.mu.Lock()
	conn, ok := m.connections[connectionID]
	if ok {
		delete(m.connections, connectionID)
	}
	m.mu.Unlock()
	if ok {
		conn.close()
	}
}

// BridgeEventBus broadcasts every event on bus to the topics resolved for it,
// and returns the function that stops doing so.
//
// This is the seam and not the policy. The reference's equivalent lives in
// AuthTools.track, which decides the topics, the payload, and the order the
// telemetry store, the bus, the SSE manager and the webhooks are served in
// (auth-tools.ts:199-269); that belongs to the AuthTools facade and is U21's,
// together with the resolveTopics rules. What is here is the minimum that proves
// the design end to end: a bus event becomes a StreamEvent, reaches a
// connection, and stops when the subscription is cancelled.
//
// The event's id is generated once and reused across the topics, which is what
// makes the deduplication do its job — see Broadcast. The StreamEvent's Data is
// the bus event's own Data; the reference puts the whole telemetry record there
// instead (auth-tools.ts:250-252), and which of the two a client sees is part of
// the wire shape U21 settles.
//
// A nil topics resolver publishes to no topic. That is a bridge that delivers
// nothing rather than a panic recovered once per event in the bus's safeCall.
func (m *SseManager) BridgeEventBus(ctx context.Context, bus *EventBus, topics func(Event) []string) (cancel func()) {
	if topics == nil {
		topics = func(Event) []string { return nil }
	}
	return bus.Subscribe(EventBusWildcard, func(ev Event) {
		names := topics(ev)
		if len(names) == 0 {
			return
		}
		id, _ := newUUIDv4()
		se := StreamEvent{
			ID:        id,
			Type:      ev.Name,
			Timestamp: ev.Timestamp.UTC().Format(webhookTimestampLayout),
			Data:      ev.Data,
			UserID:    ev.UserID,
			TenantID:  ev.TenantID,
		}
		for _, topic := range names {
			m.Broadcast(ctx, topic, se)
		}
	})
}

// sseConnection is one open stream. topics, userID and tenantID are written once
// before the connection is registered and read without a lock after;
// lastEventID is the only mutable state and has its own.
type sseConnection struct {
	id       string
	topics   map[string]struct{}
	userID   string
	tenantID string
	out      chan []byte
	done     chan struct{}

	closeOnce sync.Once

	mu          sync.Mutex
	lastEventID string
}

// enqueue applies the deduplication and queues frame. It reports false when the
// queue is full, which is the caller's signal to disconnect.
//
// The deduplication state is advanced whether or not the event is suppressed and
// whether or not deduplication is on, because the reference assigns
// conn.lastEventId unconditionally on the line after the check
// (sse-manager.ts:214-215). Turning deduplication off therefore does not stop
// the tracking, it stops the comparison.
func (c *sseConnection) enqueue(eventID string, frame []byte, deduplicate bool) bool {
	c.mu.Lock()
	suppress := deduplicate && eventID == c.lastEventID
	c.lastEventID = eventID
	c.mu.Unlock()
	if suppress {
		return true
	}
	select {
	case c.out <- frame:
		return true
	case <-c.done:
		// Already gone; the caller has nothing to disconnect.
		return true
	default:
		return false
	}
}

func (c *sseConnection) close() {
	c.closeOnce.Do(func() { close(c.done) })
}

// sseWrite writes one frame and flushes it, under a deadline.
//
// The deadline is set per write rather than once per connection, so that a
// host's server-wide WriteTimeout cannot end a long-lived stream while a stuck
// write still ends promptly. A writer that does not support deadlines — an
// httptest recorder, a wrapper that does not unwrap — is written to without one.
func sseWrite(w http.ResponseWriter, rc *http.ResponseController, frame []byte) error {
	if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if _, err := w.Write(frame); err != nil {
		return err
	}
	return rc.Flush()
}

// sseFrameBytes renders one SSE frame: the three lines the reference writes and
// the blank line that ends them (sse-manager.ts:250-252).
//
//	id: <event id>\n
//	event: <event type>\n
//	data: <json>\n
//	\n
//
// Both the id and the event line are written unconditionally, empty value and
// all, because the reference writes them unconditionally; an empty `event:`
// resets an EventSource to the default `message` type, which is what an event
// with no type means on both sides.
//
// There is exactly one data line, always. The SSE grammar requires a payload
// containing a newline to be split across one `data:` line per line, and neither
// implementation ever has to: the payload is JSON, and neither JSON.stringify
// nor encoding/json emits a raw newline — a newline inside a string is written
// as the two characters \ and n. sseMarshal closes the remaining case, a
// pre-encoded json.RawMessage carrying indentation, by compacting it.
func sseFrameBytes(id, eventType string, payload any) ([]byte, error) {
	data, err := sseMarshal(payload)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Grow(len(id) + len(eventType) + len(data) + 24)
	b.WriteString("id: ")
	b.WriteString(id)
	b.WriteString("\nevent: ")
	b.WriteString(eventType)
	b.WriteString("\ndata: ")
	b.Write(data)
	b.WriteString("\n\n")
	return b.Bytes(), nil
}

// sseMarshal encodes the frame payload the way JSON.stringify does.
//
// SetEscapeHTML(false) is the whole point: encoding/json escapes <, > and & as
// <, > and & by default and JSON.stringify does not, so leaving
// the default on would put different bytes on the wire for any event whose
// payload contains one of the three — a user agent string, a URL with a query, an
// HTML fragment in a notification. The escaping exists to make JSON safe to
// embed in an HTML document, and an event stream is not one: there is no
// <script> here for a `</script>` to break out of, which is exactly why the
// opposite call was made for the SSR config block (see the deviation
// ui-ssr-config-json-is-html-escaped). Here the reference's bytes win.
func sseMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a newline that JSON.stringify does not produce.
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if bytes.ContainsAny(out, "\n\r") {
		// Only reachable through a json.RawMessage that was indented before it
		// was handed over. Compacting it keeps the frame to one data line
		// without changing the value a client parses.
		var compact bytes.Buffer
		if err := json.Compact(&compact, out); err != nil {
			return nil, err
		}
		out = compact.Bytes()
	}
	return out, nil
}

// sseTimestamp is Date.prototype.toISOString at this instant: UTC, three
// fractional digits, a literal Z (sse-manager.ts:143, :185).
func sseTimestamp() string {
	return time.Now().UTC().Format(webhookTimestampLayout)
}
