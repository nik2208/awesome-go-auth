package auth

import (
	"context"
	"sync"
	"time"
)

// TelemetryEvent represents a single persisted auth event for analytics: the
// reference's TelemetryEvent (telemetry-store.interface.ts:4-25).
//
// SessionID and CorrelationID were missing and are the reference's
// (telemetry-store.interface.ts:18, :20). They arrived with the event
// vocabulary because the Event that will feed this record now carries both, and
// a store that could not hold them would drop, on the way to the one consumer
// that is allowed to see everything, the two identifiers that make a record
// joinable — to the other events of the same session, and to the request that
// caused it. Success and Error have no counterpart in the reference and are
// this port's own; they are left alone here.
type TelemetryEvent struct {
	ID        string
	EventName string
	UserID    string
	TenantID  string
	SessionID string
	// CorrelationID is the caller's trace handle, never generated here. See
	// EventContext.CorrelationID.
	CorrelationID string
	IP            string
	UserAgent     string
	Success       bool
	Error         string
	Timestamp     time.Time
	Meta          map[string]any
}

// TelemetryStore persists auth telemetry events.
type TelemetryStore interface {
	Record(ctx context.Context, event TelemetryEvent) error
	Query(ctx context.Context, filter TelemetryFilter) ([]TelemetryEvent, error)
}

// TelemetryFilter restricts query results: the reference's TelemetryFilter
// (telemetry-store.interface.ts:30-39).
//
// SessionID is the reference's `sessionId` (:34), added with the field it
// filters on.
//
// Offset is the reference's `offset` (:38), and it arrived with the route that
// sends it: GET <tools>/telemetry reads `limit` and `offset` from the query
// string and passes both to the store (tools.router.ts:240-241), so a filter
// that could not carry the second would answer page one to every request.
// Implementing it is part of the TelemetryStore contract rather than an
// optimisation — a store that ignores it does not paginate, and its caller has
// no way to find out.
type TelemetryFilter struct {
	UserID    string
	TenantID  string
	SessionID string
	EventName string
	Since     time.Time
	Until     time.Time
	Limit     int
	// Offset is the number of matching events to skip before the page begins.
	// Zero is the first page. It is applied after every other member has
	// filtered and before Limit counts, which is the order the reference's own
	// example query implies and the only order under which the two compose into
	// pages.
	Offset int
}

// MemoryTelemetryStore is an in-memory implementation of TelemetryStore.
type MemoryTelemetryStore struct {
	mu     sync.RWMutex
	events []TelemetryEvent
}

// NewMemoryTelemetryStore creates an in-memory telemetry store.
func NewMemoryTelemetryStore() *MemoryTelemetryStore {
	return &MemoryTelemetryStore{}
}

func (m *MemoryTelemetryStore) Record(_ context.Context, event TelemetryEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *MemoryTelemetryStore) Query(_ context.Context, f TelemetryFilter) ([]TelemetryEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []TelemetryEvent
	// skipped counts the matches Offset drops. A negative offset skips nothing,
	// which is what an out-of-range offset does to a SQL OFFSET and what the
	// route's unclamped parseInt can produce.
	skipped := 0
	for _, e := range m.events {
		if f.UserID != "" && e.UserID != f.UserID {
			continue
		}
		if f.TenantID != "" && e.TenantID != f.TenantID {
			continue
		}
		if f.SessionID != "" && e.SessionID != f.SessionID {
			continue
		}
		if f.EventName != "" && e.EventName != f.EventName {
			continue
		}
		if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
			continue
		}
		if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
			continue
		}
		if skipped < f.Offset {
			skipped++
			continue
		}
		out = append(out, e)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}
