package auth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

// trace records which sink was reached, in the order they were reached. The
// four steps of the fan-out are each synchronous on the calling goroutine —
// the telemetry write, the bus dispatch, the broadcast and the webhook store
// lookup — so the order they append in is the order Track ran them in. Only the
// webhook *delivery* is off the goroutine, and nothing here asserts on its
// position.
type trace struct {
	mu    sync.Mutex
	steps []string
}

func (t *trace) add(step string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.steps = append(t.steps, step)
}

func (t *trace) seen() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.steps...)
}

type recordingTelemetry struct {
	mu      sync.Mutex
	records []TelemetryEvent
	err     error
	onCall  func()
}

func (s *recordingTelemetry) Record(_ context.Context, e TelemetryEvent) error {
	if s.onCall != nil {
		s.onCall()
	}
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, e)
	return nil
}

func (s *recordingTelemetry) Query(context.Context, TelemetryFilter) ([]TelemetryEvent, error) {
	return nil, nil
}

func (s *recordingTelemetry) all() []TelemetryEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TelemetryEvent(nil), s.records...)
}

// capturingDistributor stands in for the open connections. With one configured,
// Broadcast publishes here and does not deliver locally, which makes every
// broadcast observable without opening a stream.
type capturingDistributor struct {
	mu     sync.Mutex
	topics []string
	events []StreamEvent
	onCall func()
}

func (d *capturingDistributor) Publish(_ context.Context, topic string, ev StreamEvent) error {
	if d.onCall != nil {
		d.onCall()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.topics = append(d.topics, topic)
	d.events = append(d.events, ev)
	return nil
}

func (d *capturingDistributor) Subscribe(context.Context, func(string, StreamEvent)) error {
	return nil
}

func (d *capturingDistributor) seen() ([]string, []StreamEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.topics...), append([]StreamEvent(nil), d.events...)
}

// tracingWebhookStore is a MemoryWebhookStore that says when it was consulted,
// and can fail the lookup on demand.
type tracingWebhookStore struct {
	*MemoryWebhookStore
	err    error
	onCall func()
}

func (s *tracingWebhookStore) FindByEvent(ctx context.Context, event, tenantID string) ([]WebhookConfig, error) {
	if s.onCall != nil {
		s.onCall()
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.MemoryWebhookStore.FindByEvent(ctx, event, tenantID)
}

type stubUserStore struct {
	user User
	err  error
}

func (s stubUserStore) CreateUser(context.Context, User) (User, error) { return User{}, nil }
func (s stubUserStore) GetUserByEmail(context.Context, string, string) (User, error) {
	return User{}, nil
}
func (s stubUserStore) GetUserByID(context.Context, string, string) (User, error) {
	return s.user, s.err
}

type capturingMailer struct{ sent chan MailMessage }

func (m capturingMailer) Send(_ context.Context, msg MailMessage) error {
	m.sent <- msg
	return nil
}

type capturingSMS struct {
	sent chan [2]string
}

func (s capturingSMS) Send(_ context.Context, phone, message string) error {
	s.sent <- [2]string{phone, message}
	return nil
}

// ---------------------------------------------------------------------------
// The fan-out
// ---------------------------------------------------------------------------

// TestTrackFansOutInTheSourceOrder pins the order the whole milestone turns on:
// telemetry, bus, SSE, webhooks (auth-tools.ts:216, :221, :233, :249). It is
// observable — a bus subscriber that reads the telemetry store sees the record
// for the event it is handling only because the save already happened — so it
// is pinned rather than left to the reading order of fanOut.
func TestTrackFansOutInTheSourceOrder(t *testing.T) {
	var got trace
	bus := NewEventBus()
	bus.Subscribe(EventBusWildcard, func(Event) { got.add("bus") })

	dist := &capturingDistributor{onCall: func() { got.add("sse") }}
	store := &tracingWebhookStore{MemoryWebhookStore: NewMemoryWebhookStore(), onCall: func() { got.add("webhooks") }}
	telemetry := &recordingTelemetry{onCall: func() { got.add("telemetry") }}

	tools, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{
		Telemetry:  telemetry,
		Webhooks:   store,
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	// No identifiers, so EventTopics resolves to `global` alone and the SSE step
	// appears once. How many topics one event reaches is
	// TestTrackSharesOneIDAcrossEveryTopicAndTheRecord's business, not this
	// test's.
	tools.Track(t.Context(), "identity.auth.login.success", map[string]any{"k": "v"}, TrackOptions{})

	want := []string{"telemetry", "bus", "sse", "webhooks"}
	if steps := got.seen(); !reflect.DeepEqual(steps, want) {
		t.Fatalf("fan-out order = %v, want %v", steps, want)
	}
}

// TestTrackSharesOneIDAcrossEveryTopicAndTheRecord pins the constraint U20 set:
// the id is generated once per event and reused, or the per-connection
// deduplication does nothing and a connection holding two of the topics
// receives the event twice (auth-tools.ts:200, :236-247).
func TestTrackSharesOneIDAcrossEveryTopicAndTheRecord(t *testing.T) {
	dist := &capturingDistributor{}
	telemetry := &recordingTelemetry{}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
		Telemetry:  telemetry,
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Track(t.Context(), "identity.auth.login.success", nil, TrackOptions{
		UserID: "u1", TenantID: "acme", SessionID: "s1",
	})

	topics, events := dist.seen()
	want := []string{"global", "tenant:acme", "user:u1", "session:s1"}
	if !reflect.DeepEqual(topics, want) {
		t.Fatalf("topics = %v, want %v", topics, want)
	}
	if len(events) != 4 {
		t.Fatalf("broadcasts = %d, want 4", len(events))
	}
	id := events[0].ID
	if id == "" {
		t.Fatal("event id is empty")
	}
	for i, ev := range events {
		if ev.ID != id {
			t.Fatalf("broadcast %d has id %q, want the shared %q", i, ev.ID, id)
		}
	}
	records := telemetry.all()
	if len(records) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(records))
	}
	if records[0].ID != id {
		t.Fatalf("telemetry record id = %q, want the broadcast id %q", records[0].ID, id)
	}
}

// TestTrackFrameCarriesTheWholeTelemetryRecord settles what U20 deliberately
// left open: the frame's data is the telemetry record, not the caller's payload
// (auth-tools.ts:240), spelled with the reference's key names. A client reads
// the payload at rawData.data and the provenance beside it.
func TestTrackFrameCarriesTheWholeTelemetryRecord(t *testing.T) {
	dist := &capturingDistributor{}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Track(t.Context(), "identity.auth.login.success", map[string]any{"method": "password"}, TrackOptions{
		UserID: "u1", SessionID: "s1", CorrelationID: "c1", IP: "203.0.113.7", UserAgent: "curl/8",
	})

	_, events := dist.seen()
	if len(events) == 0 {
		t.Fatal("no broadcast")
	}
	raw, err := json.Marshal(events[0].Data)
	if err != nil {
		t.Fatalf("marshal frame data: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal frame data: %v", err)
	}

	for _, key := range []string{"id", "event", "timestamp", "data", "userId", "sessionId", "correlationId", "ip", "userAgent"} {
		if _, ok := got[key]; !ok {
			t.Errorf("frame data is missing %q; got %v", key, got)
		}
	}
	// The tenant was not set, so the key is absent rather than empty — the
	// reference's JSON.stringify drops the undefined member.
	if _, ok := got["tenantId"]; ok {
		t.Errorf("frame data carries tenantId for an event that had none: %v", got)
	}
	if got["event"] != "identity.auth.login.success" {
		t.Errorf("frame data event = %v, want the event name", got["event"])
	}
	payload, ok := got["data"].(map[string]any)
	if !ok || payload["method"] != "password" {
		t.Errorf("frame data.data = %v, want the tracked payload", got["data"])
	}
	// Go field names must not reach the wire.
	for _, key := range []string{"EventName", "Meta", "success", "Success"} {
		if _, ok := got[key]; ok {
			t.Errorf("frame data carries %q, which the reference never sends: %v", key, got)
		}
	}
}

// TestTrackFillsProvenanceFromTheContext covers the one place Track reaches
// past its options. The reference's route reads the two headers and passes them
// (tools.router.ts:144-145); a caller here that passes nothing gets what the
// adapter captured, and one that passes a value keeps it.
func TestTrackFillsProvenanceFromTheContext(t *testing.T) {
	telemetry := &recordingTelemetry{}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{Telemetry: telemetry})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	ctx := ContextWithEventContext(t.Context(), EventContext{
		CorrelationID: "from-ctx", IP: "198.51.100.4", UserAgent: "ctx-agent",
	})

	tools.Track(ctx, "identity.auth.login.success", nil, TrackOptions{IP: "explicit"})

	records := telemetry.all()
	if len(records) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(records))
	}
	if records[0].CorrelationID != "from-ctx" {
		t.Errorf("correlation id = %q, want the context's", records[0].CorrelationID)
	}
	if records[0].UserAgent != "ctx-agent" {
		t.Errorf("user agent = %q, want the context's", records[0].UserAgent)
	}
	if records[0].IP != "explicit" {
		t.Errorf("ip = %q, want the caller's explicit value to win", records[0].IP)
	}
}

// TestTrackSurvivesEverySinkFailing is the failure-isolation contract: a
// telemetry write that fails and a webhook store that fails leave the other
// sinks running and never reach the caller (auth-tools.ts:218, :251).
func TestTrackSurvivesEverySinkFailing(t *testing.T) {
	var got trace
	var mu sync.Mutex
	var reported []error

	bus := NewEventBus()
	bus.Subscribe(EventBusWildcard, func(Event) { got.add("bus") })
	dist := &capturingDistributor{onCall: func() { got.add("sse") }}

	tools, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{
		Telemetry:  &recordingTelemetry{err: errors.New("store down")},
		Webhooks:   &tracingWebhookStore{MemoryWebhookStore: NewMemoryWebhookStore(), err: errors.New("lookup down")},
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
		OnError: func(err error) {
			mu.Lock()
			defer mu.Unlock()
			reported = append(reported, err)
		},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Track(t.Context(), "identity.auth.login.success", nil, TrackOptions{})

	if steps := got.seen(); !reflect.DeepEqual(steps, []string{"bus", "sse"}) {
		t.Fatalf("a failing telemetry store stopped the later sinks: %v", steps)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 2 {
		t.Fatalf("OnError calls = %d, want one per failing sink: %v", len(reported), reported)
	}
}

// TestTrackWithNoSinksConfigured is the zero-overhead case the reference
// documents (auth-tools.ts:140-141): everything optional is off, the event
// still reaches the bus, and nothing panics.
func TestTrackWithNoSinksConfigured(t *testing.T) {
	bus := NewEventBus()
	var seen []Event
	bus.Subscribe(EventBusWildcard, func(ev Event) { seen = append(seen, ev) })

	tools, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	if tools.SSE != nil {
		t.Error("SSE manager was built for an AuthTools that did not ask for one")
	}

	tools.Track(t.Context(), "identity.auth.login.success", map[string]any{"k": "v"}, TrackOptions{UserID: "u1"})

	if len(seen) != 1 {
		t.Fatalf("bus events = %d, want 1", len(seen))
	}
	if seen[0].Name != "identity.auth.login.success" || seen[0].UserID != "u1" {
		t.Fatalf("bus event = %+v, want the tracked one", seen[0])
	}
}

func TestNewAuthToolsRefusesANilBus(t *testing.T) {
	if _, err := NewAuthTools(t.Context(), nil, AuthToolsOptions{}); err == nil {
		t.Fatal("NewAuthTools accepted a nil bus; every sink fails silently when it is misconfigured")
	}
}

// ---------------------------------------------------------------------------
// Topics
// ---------------------------------------------------------------------------

func TestEventTopics(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   Event
		want []string
	}{
		{"bare", Event{}, []string{"global"}},
		{"user", Event{UserID: "u1"}, []string{"global", "user:u1"}},
		{"tenant", Event{TenantID: "acme"}, []string{"global", "tenant:acme"}},
		{"all four", Event{TenantID: "acme", UserID: "u1", SessionID: "s1"},
			[]string{"global", "tenant:acme", "user:u1", "session:s1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EventTopics(tc.ev); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("EventTopics = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStreamTopics(t *testing.T) {
	for _, tc := range []struct {
		name             string
		userID, tenantID string
		requested        []string
		want             []string
	}{
		{"anonymous", "", "", nil, []string{"global"}},
		{"principal", "u1", "acme", nil, []string{"global", "tenant:acme", "user:u1"}},
		{"a subset is honoured", "u1", "acme", []string{"user:u1"}, []string{"user:u1"}},
		{"an unauthorised topic is dropped", "u1", "", []string{"user:u1", "user:u2", "tenant:acme"}, []string{"user:u1"}},
		{"only unauthorised topics leave nothing", "u1", "", []string{"user:u2"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StreamTopics(tc.userID, tc.tenantID, tc.requested); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("StreamTopics = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSessionTopicIsPublishedButNeverAuthorised pins the asymmetry between the
// two halves of the topic rule as a fact about the source rather than a bug
// here: resolveTopics produces session:<id> (auth-tools.ts:357) and the stream
// route's authorised list does not contain it (tools.router.ts:207-210), so the
// topic is broadcast to and cannot be subscribed to through that route. If a
// later change makes the two agree, this test is the one that should be argued
// with first.
func TestSessionTopicIsPublishedButNeverAuthorised(t *testing.T) {
	published := EventTopics(Event{UserID: "u1", SessionID: "s1"})
	var hasSession bool
	for _, topic := range published {
		if topic == "session:s1" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatalf("EventTopics dropped the session topic: %v", published)
	}
	if got := StreamTopics("u1", "", []string{"session:s1"}); len(got) != 0 {
		t.Fatalf("StreamTopics authorised a session topic: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Notify
// ---------------------------------------------------------------------------

// TestNotifyDefaultsToTheSseChannelAlone covers the reference's `?? ['sse']`
// (auth-tools.ts:293) and the single named target: notify does not fan out
// across EventTopics.
func TestNotifyDefaultsToTheSseChannelAlone(t *testing.T) {
	dist := &capturingDistributor{}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
		Users:      stubUserStore{user: User{ID: "u1", Email: "a@example.com"}},
		Mail:       capturingMailer{sent: make(chan MailMessage, 1)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Notify(t.Context(), "user:u1", map[string]any{"message": "Welcome!"}, NotifyOptions{UserID: "u1"})

	topics, events := dist.seen()
	if !reflect.DeepEqual(topics, []string{"user:u1"}) {
		t.Fatalf("topics = %v, want the single named target", topics)
	}
	if events[0].Type != "notification" {
		t.Errorf("type = %q, want the default %q", events[0].Type, "notification")
	}
	if events[0].ID == "" || events[0].Timestamp == "" {
		t.Errorf("Broadcast did not fill the id and timestamp notify leaves empty: %+v", events[0])
	}
}

// TestNotifyEmailAndSms covers the two channels together: the subject
// fallbacks, the HTML wrapper, and the indentation difference between the two
// default bodies (auth-tools.ts:322-327 against :334).
func TestNotifyEmailAndSms(t *testing.T) {
	mail := capturingMailer{sent: make(chan MailMessage, 1)}
	sms := capturingSMS{sent: make(chan [2]string, 1)}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
		Users: stubUserStore{user: User{ID: "u1", Email: "a@example.com", PhoneNumber: "+15550001"}},
		Mail:  mail,
		SMS:   sms,
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Notify(t.Context(), "user:u1", map[string]any{"n": 1}, NotifyOptions{
		UserID:   "u1",
		Type:     "billing.reminder",
		Channels: []NotifyChannel{NotifyChannelEmail, NotifyChannelSMS},
	})

	select {
	case msg := <-mail.sent:
		if msg.To != "a@example.com" {
			t.Errorf("to = %q", msg.To)
		}
		if msg.Subject != "billing.reminder" {
			t.Errorf("subject = %q, want the type as the fallback", msg.Subject)
		}
		if !msg.IsHTML {
			t.Error("the email was not marked HTML")
		}
		// JSON.stringify(data, null, 2) is indented, and the indentation's
		// newlines become <br> inside the single wrapping <p>.
		if want := "<p>{<br>  \"n\": 1<br>}</p>"; msg.Body != want {
			t.Errorf("body = %q, want %q", msg.Body, want)
		}
		if want := "{\n  \"n\": 1\n}"; msg.Text != want {
			t.Errorf("text = %q, want the un-wrapped indented body %q", msg.Text, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no email was sent")
	}

	select {
	case got := <-sms.sent:
		if got[0] != "+15550001" {
			t.Errorf("phone = %q", got[0])
		}
		// Not indented, where the email body is: the reference passes `null, 2`
		// to one JSON.stringify and not to the other.
		if want := `{"n":1}`; got[1] != want {
			t.Errorf("message = %q, want the compact encoding %q", got[1], want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SMS was sent")
	}
}

// TestNotifyPassesAStringPayloadThrough is the reference's
// `typeof data === 'string' ? data : JSON.stringify(…)` (auth-tools.ts:323).
func TestNotifyPassesAStringPayloadThrough(t *testing.T) {
	sms := capturingSMS{sent: make(chan [2]string, 1)}
	tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
		Users: stubUserStore{user: User{ID: "u1", PhoneNumber: "+15550001"}},
		SMS:   sms,
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	tools.Notify(t.Context(), "user:u1", "your code is 123456", NotifyOptions{
		UserID: "u1", Channels: []NotifyChannel{NotifyChannelSMS},
	})

	select {
	case got := <-sms.sent:
		if got[1] != "your code is 123456" {
			t.Errorf("message = %q, want the string unquoted and unencoded", got[1])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SMS was sent")
	}
}

// TestNotifySkipsTheContactChannelsWithoutAUser covers the reference's guard
// (auth-tools.ts:307): no user id, no user store, or a store that fails, and
// the two contact channels do not apply — while the SSE broadcast that already
// happened stands.
func TestNotifySkipsTheContactChannelsWithoutAUser(t *testing.T) {
	for _, tc := range []struct {
		name   string
		users  UserStore
		userID string
	}{
		{"no user id", stubUserStore{user: User{Email: "a@example.com"}}, ""},
		{"no user store", nil, "u1"},
		{"the lookup failed", stubUserStore{err: errors.New("gone")}, "u1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mail := capturingMailer{sent: make(chan MailMessage, 1)}
			dist := &capturingDistributor{}
			tools, err := NewAuthTools(t.Context(), NewEventBus(), AuthToolsOptions{
				SSE:        true,
				SSEOptions: []SseOption{WithSseDistributor(dist)},
				Users:      tc.users,
				Mail:       mail,
			})
			if err != nil {
				t.Fatalf("NewAuthTools: %v", err)
			}

			tools.Notify(t.Context(), "user:u1", "hi", NotifyOptions{
				UserID:   tc.userID,
				Channels: []NotifyChannel{NotifyChannelSSE, NotifyChannelEmail},
			})

			if topics, _ := dist.seen(); len(topics) != 1 {
				t.Errorf("the SSE channel was skipped too: %v", topics)
			}
			select {
			case msg := <-mail.sent:
				t.Fatalf("an email was sent without a resolvable user: %+v", msg)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The bridge
// ---------------------------------------------------------------------------

// TestBridgeIsNotWiredByDefault is the default this PR argues for, stated as a
// test so that a later change to it is a deliberate one: an AuthTools built
// over a bus delivers nothing from that bus until a host calls Bridge.
func TestBridgeIsNotWiredByDefault(t *testing.T) {
	dist := &capturingDistributor{}
	telemetry := &recordingTelemetry{}
	bus := NewEventBus()
	if _, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{
		Telemetry:  telemetry,
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
	}); err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}

	bus.Publish(Event{Name: "identity.auth.login.success", UserID: "u1"})

	if topics, _ := dist.seen(); len(topics) != 0 {
		t.Errorf("constructing AuthTools subscribed the bus: %v", topics)
	}
	if got := telemetry.all(); len(got) != 0 {
		t.Errorf("constructing AuthTools began persisting bus events: %v", got)
	}
}

// TestBridgeRunsTheFanOutWithoutRepublishing covers the one step Bridge skips.
// The event arrived from the bus, so republishing it would feed the
// subscription its own output; the other three sinks run exactly as Track runs
// them.
func TestBridgeRunsTheFanOutWithoutRepublishing(t *testing.T) {
	dist := &capturingDistributor{}
	telemetry := &recordingTelemetry{}
	bus := NewEventBus()
	var busCalls int
	bus.Subscribe(EventBusWildcard, func(Event) { busCalls++ })

	tools, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{
		Telemetry:  telemetry,
		SSE:        true,
		SSEOptions: []SseOption{WithSseDistributor(dist)},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	cancel := tools.Bridge(t.Context())

	bus.Publish(Event{Name: "identity.auth.login.success", UserID: "u1"})

	if busCalls != 1 {
		t.Fatalf("bus handler ran %d times; the bridge republished what it was handed", busCalls)
	}
	topics, _ := dist.seen()
	if !reflect.DeepEqual(topics, []string{"global", "user:u1"}) {
		t.Fatalf("bridged topics = %v, want the EventTopics of the event", topics)
	}
	if got := telemetry.all(); len(got) != 1 {
		t.Fatalf("telemetry records = %d, want 1", len(got))
	}

	cancel()
	bus.Publish(Event{Name: "identity.auth.login.success", UserID: "u2"})
	if topics, _ := dist.seen(); len(topics) != 2 {
		t.Fatalf("the bridge kept broadcasting after cancel: %v", topics)
	}
}

// TestBridgeDeliversToWebhooks closes the loop the default leaves open: the
// nineteen events the library raises reach a webhook subscription once a host
// has called Bridge, and not before.
func TestBridgeDeliversToWebhooks(t *testing.T) {
	delivered := make(chan WebhookAttempt, 4)
	store := NewMemoryWebhookStore()
	if _, err := store.AddWebhook(t.Context(), WebhookConfig{
		URL:    "https://example.invalid/hook",
		Events: []string{WebhookEventWildcard},
	}); err != nil {
		t.Fatalf("AddWebhook: %v", err)
	}

	bus := NewEventBus()
	tools, err := NewAuthTools(t.Context(), bus, AuthToolsOptions{
		Webhooks: store,
		WebhookSender: &WebhookSender{Deliverer: WebhookDelivererFunc(func(_ context.Context, a WebhookAttempt) error {
			delivered <- a
			return nil
		})},
	})
	if err != nil {
		t.Fatalf("NewAuthTools: %v", err)
	}
	defer tools.Bridge(t.Context())()

	bus.Publish(Event{Name: "identity.auth.login.success", UserID: "u1", Data: map[string]any{"k": "v"}})

	select {
	case attempt := <-delivered:
		if attempt.Event != "identity.auth.login.success" {
			t.Errorf("delivered event = %q", attempt.Event)
		}
		var envelope map[string]any
		if err := json.Unmarshal(attempt.Body, &envelope); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if envelope["version"] != OutgoingWebhookVersion {
			t.Errorf("version = %v, want the default %q", envelope["version"], OutgoingWebhookVersion)
		}
		meta, _ := envelope["metadata"].(map[string]any)
		if meta["userId"] != "u1" {
			t.Errorf("metadata = %v, want the event's user id", envelope["metadata"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge delivered no webhook")
	}
}
