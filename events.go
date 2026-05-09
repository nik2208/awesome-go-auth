package auth

import (
	"log"
	"sync"
	"time"
)

// Event is a generic auth domain event payload.
type Event struct {
	Name      string
	UserID    string
	TenantID  string
	Timestamp time.Time
	Data      map[string]any
}

// EventBus is a tiny in-process pub/sub for auth events.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]func(Event)
}

func NewEventBus() *EventBus {
	return &EventBus{subscribers: make(map[string][]func(Event))}
}

func (b *EventBus) Subscribe(event string, handler func(Event)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[event] = append(b.subscribers[event], handler)
}

func (b *EventBus) Publish(ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	b.mu.RLock()
	handlers := append([]func(Event){}, b.subscribers[ev.Name]...)
	wildcard := append([]func(Event){}, b.subscribers["*"]...)
	b.mu.RUnlock()
	for _, h := range handlers {
		safeCall(h, ev)
	}
	for _, h := range wildcard {
		safeCall(h, ev)
	}
}

func safeCall(handler func(Event), ev Event) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("auth: recovered panic in event handler for %q: %v", ev.Name, r)
		}
	}()
	handler(ev)
}
