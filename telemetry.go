package auth

import (
	"context"
	"sync"
	"time"
)

// TelemetryEvent represents a single persisted auth event for analytics.
type TelemetryEvent struct {
	ID        string
	EventName string
	UserID    string
	TenantID  string
	IP        string
	UserAgent string
	Success   bool
	Error     string
	Timestamp time.Time
	Meta      map[string]any
}

// TelemetryStore persists auth telemetry events.
type TelemetryStore interface {
	Record(ctx context.Context, event TelemetryEvent) error
	Query(ctx context.Context, filter TelemetryFilter) ([]TelemetryEvent, error)
}

// TelemetryFilter restricts query results.
type TelemetryFilter struct {
	UserID    string
	TenantID  string
	EventName string
	Since     time.Time
	Until     time.Time
	Limit     int
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
	for _, e := range m.events {
		if f.UserID != "" && e.UserID != f.UserID {
			continue
		}
		if f.TenantID != "" && e.TenantID != f.TenantID {
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
		out = append(out, e)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}
