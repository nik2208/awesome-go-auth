package auth

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestEventBus_Subscribe_Publish(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	received := make([]Event, 0)
	bus.Subscribe("user.registered", func(e Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})
	bus.Publish(Event{Name: "user.registered", UserID: "u1", TenantID: "t1"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0].UserID != "u1" {
		t.Fatalf("unexpected user ID: %s", received[0].UserID)
	}
}

func TestEventBus_NoHandlers(t *testing.T) {
	bus := NewEventBus()
	// Should not panic
	bus.Publish(Event{Name: "no.handlers", UserID: "u1"})
}

func TestEventBus_Wildcard(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	count := 0
	bus.Subscribe("*", func(e Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	bus.Publish(Event{Name: "event.one"})
	bus.Publish(Event{Name: "event.two"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatalf("wildcard should receive all events, got %d", count)
	}
}

func TestEventBus_MultipleSubscribers(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	count := 0
	for i := 0; i < 3; i++ {
		bus.Subscribe("test.event", func(e Event) {
			mu.Lock()
			count++
			mu.Unlock()
		})
	}
	bus.Publish(Event{Name: "test.event"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 3 {
		t.Fatalf("expected 3 handlers called, got %d", count)
	}
}

func TestEventBus_TimestampSetIfZero(t *testing.T) {
	bus := NewEventBus()
	var received Event
	bus.Subscribe("ts.test", func(e Event) {
		received = e
	})
	before := time.Now()
	bus.Publish(Event{Name: "ts.test"})
	time.Sleep(20 * time.Millisecond)
	if received.Timestamp.IsZero() {
		t.Fatal("timestamp should be set if zero")
	}
	if received.Timestamp.Before(before) {
		t.Fatal("timestamp should be set to approximately current time")
	}
}

func TestEventBus_ExplicitTimestampPreserved(t *testing.T) {
	bus := NewEventBus()
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var received Event
	bus.Subscribe("ts.explicit", func(e Event) {
		received = e
	})
	bus.Publish(Event{Name: "ts.explicit", Timestamp: fixed})
	time.Sleep(20 * time.Millisecond)
	if !received.Timestamp.Equal(fixed) {
		t.Fatalf("explicit timestamp should be preserved: got %v", received.Timestamp)
	}
}

func TestEventBus_PanicRecovery(t *testing.T) {
	bus := NewEventBus()
	bus.Subscribe("panic.event", func(e Event) {
		panic("intentional panic in handler")
	})
	// Should not panic in the test goroutine
	bus.Publish(Event{Name: "panic.event"})
	time.Sleep(20 * time.Millisecond)
}

func TestEventBus_SpecificEventNotFiredForOther(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	count := 0
	bus.Subscribe("specific.event", func(e Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	bus.Publish(Event{Name: "other.event"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 0 {
		t.Fatalf("specific handler should not fire for other events, got %d calls", count)
	}
}

func TestEventBus_WildcardAndSpecific(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	specific := 0
	wildcard := 0
	bus.Subscribe("my.event", func(e Event) {
		mu.Lock()
		specific++
		mu.Unlock()
	})
	bus.Subscribe("*", func(e Event) {
		mu.Lock()
		wildcard++
		mu.Unlock()
	})
	bus.Publish(Event{Name: "my.event"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if specific != 1 {
		t.Fatalf("specific handler called %d times", specific)
	}
	if wildcard != 1 {
		t.Fatalf("wildcard handler called %d times", wildcard)
	}
}

func TestEventBus_EventData(t *testing.T) {
	bus := NewEventBus()
	var received Event
	bus.Subscribe("data.event", func(e Event) {
		received = e
	})
	bus.Publish(Event{
		Name:     "data.event",
		UserID:   "u42",
		TenantID: "t99",
		Data:     map[string]any{"key": "value"},
	})
	time.Sleep(20 * time.Millisecond)
	if received.UserID != "u42" {
		t.Fatalf("unexpected user ID: %s", received.UserID)
	}
	if received.TenantID != "t99" {
		t.Fatalf("unexpected tenant ID: %s", received.TenantID)
	}
	if received.Data["key"] != "value" {
		t.Fatalf("unexpected data: %v", received.Data)
	}
}

func TestEventBus_ConcurrentPublish(t *testing.T) {
	bus := NewEventBus()
	var mu sync.Mutex
	count := 0
	bus.Subscribe("concurrent", func(e Event) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Publish(Event{Name: "concurrent"})
		}()
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 10 {
		t.Fatalf("expected 10 events, got %d", count)
	}
}

// ── the payload, the carrier and the bus semantics ───────────────────────────
//
// The cases above predate the vocabulary and pin the bus as it was. These pin
// what U17 added: the four fields Event gained, the two projections that keep
// it from being reassembled by hand downstream, and the delivery semantics that
// were compared against the reference's EventEmitter rather than assumed.

func TestEventWithRequestContextFillsTheThreeFields(t *testing.T) {
	ctx := ContextWithEventContext(context.Background(), EventContext{
		CorrelationID: "corr-1", IP: "192.0.2.5", UserAgent: "ua",
	})
	got := Event{Name: EventAuthLoginSuccess, UserID: "u1"}.WithRequestContext(ctx)

	if got.CorrelationID != "corr-1" || got.IP != "192.0.2.5" || got.UserAgent != "ua" {
		t.Errorf("provenance = %q/%q/%q, want the carrier's values",
			got.CorrelationID, got.IP, got.UserAgent)
	}
	if got.Name != EventAuthLoginSuccess || got.UserID != "u1" {
		t.Error("WithRequestContext changed a field that is not request provenance")
	}
}

// The reference spreads the request context first and the payload over it
// (node-auth auth.router.ts:430-433), so the caller wins a collision. Its
// payload type has no key that can collide, so the observable rule is "fill
// what the caller left empty" — which is also the rule that survives a caller
// who sets one of the three on purpose.
func TestEventWithRequestContextDoesNotOverwriteAnExplicitValue(t *testing.T) {
	ctx := ContextWithEventContext(context.Background(), EventContext{
		CorrelationID: "from-header", IP: "192.0.2.5", UserAgent: "from-header",
	})
	got := Event{Name: EventAuthLogout, CorrelationID: "explicit", IP: "203.0.113.1"}.WithRequestContext(ctx)

	if got.CorrelationID != "explicit" {
		t.Errorf("CorrelationID = %q, want the caller's %q", got.CorrelationID, "explicit")
	}
	if got.IP != "203.0.113.1" {
		t.Errorf("IP = %q, want the caller's %q", got.IP, "203.0.113.1")
	}
	if got.UserAgent != "from-header" {
		t.Errorf("UserAgent = %q, want the carrier's value for the field the caller left empty", got.UserAgent)
	}
}

// A publish from outside any request — a background sweep, a host calling a
// Service method from a cron job — is not an error and leaves the three empty.
func TestEventWithRequestContextWithoutACarrier(t *testing.T) {
	ev := Event{Name: EventSessionExpired, UserID: "u1"}
	if got := ev.WithRequestContext(context.Background()); got.CorrelationID != "" || got.IP != "" || got.UserAgent != "" {
		t.Errorf("event = %+v, want the provenance left empty when the context carries no EventContext", got)
	}
}

// The webhook envelope's metadata is derived from the event rather than
// assembled beside it, in the reference's four keys and its camelCase spelling
// (auth-tools.ts:257-262). IP and UserAgent are deliberately absent: a webhook
// leaves the deployment.
func TestEventWebhookMetadata(t *testing.T) {
	full := Event{
		Name: EventRoleAssigned, UserID: "u1", TenantID: "t1",
		SessionID: "s1", CorrelationID: "c1",
		IP: "192.0.2.5", UserAgent: "ua",
	}.WebhookMetadata()

	want := map[string]any{"userId": "u1", "tenantId": "t1", "sessionId": "s1", "correlationId": "c1"}
	if len(full) != len(want) {
		t.Fatalf("metadata = %v, want exactly %v — extra keys are fields leaving the deployment", full, want)
	}
	for k, v := range want {
		if full[k] != v {
			t.Errorf("metadata[%q] = %v, want %v", k, full[k], v)
		}
	}
	for _, absent := range []string{"ip", "userAgent", "IP", "UserAgent"} {
		if _, ok := full[absent]; ok {
			t.Errorf("metadata carries %q: the reference's metadata is four identifiers and not "+
				"the client address or the browser string", absent)
		}
	}

	// An absent identifier is omitted rather than written empty, because the
	// reference lets JSON.stringify drop its undefined members.
	partial := Event{Name: EventAuthLoginFailed, CorrelationID: "c1"}.WebhookMetadata()
	if len(partial) != 1 || partial["correlationId"] != "c1" {
		t.Errorf("metadata = %v, want only the correlationId key", partial)
	}

	if none := (Event{Name: EventAuthOAuthConflict}).WebhookMetadata(); none != nil {
		t.Errorf("metadata = %v, want nil so OutgoingWebhookEvent.Metadata's omitempty drops the key", none)
	}
}

func TestEventBusPublishContextFillsFromTheCarrier(t *testing.T) {
	bus := NewEventBus()
	var got Event
	bus.Subscribe(EventUserCreated, func(e Event) { got = e })

	ctx := ContextWithEventContext(context.Background(), EventContext{
		CorrelationID: "corr-pub", IP: "192.0.2.5", UserAgent: "ua-pub",
	})
	bus.PublishContext(ctx, Event{Name: EventUserCreated, UserID: "u1", SessionID: "s1"})

	if got.CorrelationID != "corr-pub" || got.IP != "192.0.2.5" || got.UserAgent != "ua-pub" {
		t.Errorf("subscriber saw %q/%q/%q, want the carrier's values",
			got.CorrelationID, got.IP, got.UserAgent)
	}
	if got.SessionID != "s1" {
		t.Errorf("SessionID = %q, want the publisher's", got.SessionID)
	}
	if got.Timestamp.IsZero() {
		t.Error("PublishContext did not go through Publish: the timestamp was not filled")
	}
}

func TestEventBusPublishContextWithoutACarrier(t *testing.T) {
	bus := NewEventBus()
	var got Event
	bus.Subscribe(EventUserDeleted, func(e Event) { got = e })
	bus.PublishContext(context.Background(), Event{Name: EventUserDeleted, UserID: "u1"})

	if got.UserID != "u1" {
		t.Fatalf("the event was not delivered: %+v", got)
	}
	if got.CorrelationID != "" || got.IP != "" || got.UserAgent != "" {
		t.Errorf("provenance = %q/%q/%q, want empty: a publish outside any request invents nothing",
			got.CorrelationID, got.IP, got.UserAgent)
	}
}

// Publish is synchronous, as EventEmitter.emit is: every handler has run by the
// time it returns. The older cases in this file sleep before asserting, which
// would pass an asynchronous bus too; this one does not.
func TestEventBusPublishIsSynchronous(t *testing.T) {
	bus := NewEventBus()
	done := false
	bus.Subscribe(EventAuthLogout, func(Event) { done = true })
	bus.Publish(Event{Name: EventAuthLogout})
	if !done {
		t.Error("Publish returned before its handler ran: the reference's emit does not")
	}
}

// Named handlers run in registration order and before the wildcard ones, which
// is the order the reference's two emit calls produce (auth-event-bus.ts:61-63).
func TestEventBusDeliveryOrder(t *testing.T) {
	bus := NewEventBus()
	var order []string
	bus.Subscribe(EventUserCreated, func(Event) { order = append(order, "named-1") })
	bus.Subscribe(EventBusWildcard, func(Event) { order = append(order, "wildcard-1") })
	bus.Subscribe(EventUserCreated, func(Event) { order = append(order, "named-2") })
	bus.Subscribe(EventBusWildcard, func(Event) { order = append(order, "wildcard-2") })
	bus.Publish(Event{Name: EventUserCreated})

	want := []string{"named-1", "named-2", "wildcard-1", "wildcard-2"}
	if len(order) != len(want) {
		t.Fatalf("delivery = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("delivery = %v, want %v", order, want)
		}
	}
}

// Both buses dispatch against a snapshot: EventEmitter clones its listener
// array, Publish copies under the read lock. So a handler that subscribes
// during a dispatch is not called for the event being dispatched — and, here,
// cannot deadlock against the lock it is dispatching under.
func TestEventBusSubscribeDuringDispatch(t *testing.T) {
	bus := NewEventBus()
	late := 0
	bus.Subscribe(EventSessionRotated, func(Event) {
		bus.Subscribe(EventSessionRotated, func(Event) { late++ })
	})
	bus.Publish(Event{Name: EventSessionRotated})
	if late != 0 {
		t.Errorf("a handler subscribed during dispatch was called %d times for that same event", late)
	}
	bus.Publish(Event{Name: EventSessionRotated})
	if late != 1 {
		t.Errorf("the late handler was called %d times on the next publish, want 1", late)
	}
}

// The registered deviation event-handler-panic-does-not-fail-the-publisher, in
// both of its halves: the later handlers still run, and the publisher returns
// normally. The reference does neither — a listener that throws propagates out
// of emit, skipping the rest and failing the request that published.
func TestEventBusPanicIsContainedToOneHandler(t *testing.T) {
	bus := NewEventBus()
	var ran []string
	bus.Subscribe(EventUserPasswordChanged, func(Event) { ran = append(ran, "before") })
	bus.Subscribe(EventUserPasswordChanged, func(Event) { panic("subscriber bug") })
	bus.Subscribe(EventUserPasswordChanged, func(Event) { ran = append(ran, "after") })
	bus.Subscribe(EventBusWildcard, func(Event) { ran = append(ran, "wildcard") })

	bus.Publish(Event{Name: EventUserPasswordChanged, UserID: "u1"})

	want := []string{"before", "after", "wildcard"}
	if len(ran) != len(want) {
		t.Fatalf("handlers run = %v, want %v: a panicking subscriber must not silence the others", ran, want)
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Fatalf("handlers run = %v, want %v", ran, want)
		}
	}
}

// Subscribe's cancel function is the port of the reference's offEvent
// (auth-event-bus.ts:79-81). Go funcs are not comparable, so there is no
// Unsubscribe(name, handler) to write; the cancel is what the caller already
// holds.
func TestEventBusSubscribeCancels(t *testing.T) {
	bus := NewEventBus()
	var ran []string
	bus.Subscribe(EventUserCreated, func(Event) { ran = append(ran, "kept") })
	cancel := bus.Subscribe(EventUserCreated, func(Event) { ran = append(ran, "cancelled") })
	stopWildcard := bus.Subscribe(EventBusWildcard, func(Event) { ran = append(ran, "wildcard") })

	bus.Publish(Event{Name: EventUserCreated})
	if len(ran) != 3 {
		t.Fatalf("before cancelling, handlers run = %v, want all three", ran)
	}

	ran = nil
	cancel()
	cancel() // idempotent: the second call has nothing to remove
	bus.Publish(Event{Name: EventUserCreated})
	want := []string{"kept", "wildcard"}
	if len(ran) != len(want) || ran[0] != want[0] || ran[1] != want[1] {
		t.Fatalf("after cancelling, handlers run = %v, want %v: cancelling one subscription must not touch its neighbours", ran, want)
	}

	ran = nil
	stopWildcard()
	bus.Publish(Event{Name: EventUserCreated})
	if len(ran) != 1 || ran[0] != "kept" {
		t.Fatalf("after cancelling the wildcard, handlers run = %v, want [kept]", ran)
	}
}

// Two subscriptions of the same func value are two subscriptions, which is the
// case a listener-identity offEvent gets wrong and an id-keyed cancel does not.
func TestEventBusCancelRemovesOneOfTwoIdenticalHandlers(t *testing.T) {
	bus := NewEventBus()
	calls := 0
	handler := func(Event) { calls++ }
	cancel := bus.Subscribe(EventUserCreated, handler)
	bus.Subscribe(EventUserCreated, handler)

	cancel()
	bus.Publish(Event{Name: EventUserCreated})
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1: cancelling one registration must leave the other", calls)
	}
}

// Publish dispatches against a snapshot taken under the read lock, so a cancel
// from inside a handler does not reach the event being delivered — the same
// rule EventEmitter has, since it clones its listener array before emitting.
func TestEventBusCancelDuringDispatchAppliesToTheNextEvent(t *testing.T) {
	bus := NewEventBus()
	var ran []string
	var cancelLater func()
	bus.Subscribe(EventUserCreated, func(Event) {
		ran = append(ran, "first")
		cancelLater()
	})
	cancelLater = bus.Subscribe(EventUserCreated, func(Event) { ran = append(ran, "second") })

	bus.Publish(Event{Name: EventUserCreated})
	if len(ran) != 2 {
		t.Fatalf("handlers run = %v, want both: a cancel cannot reach a dispatch already in flight", ran)
	}
	ran = nil
	bus.Publish(Event{Name: EventUserCreated})
	if len(ran) != 1 || ran[0] != "first" {
		t.Fatalf("handlers run = %v, want [first] on the next event", ran)
	}
}
