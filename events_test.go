package auth

import (
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
