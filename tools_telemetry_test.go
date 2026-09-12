package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The parts of GET <tools>/telemetry that are a conversion rather than a wire:
// what the query string becomes. The route itself — the mount condition, the
// guard, the body — is pinned for all four adapters in
// adapter/internal/wiretest/tools_telemetry.go.

func TestToolsTelemetryTime(t *testing.T) {
	// `from ? new Date(from) : undefined` (tools.router.ts:237). The two zone
	// rules are ISO 8601's and they differ: a date-only string is UTC midnight, a
	// date-time with no offset is local.
	local := func(y int, m time.Month, d, hh, mm, ss int) time.Time {
		return time.Date(y, m, d, hh, mm, ss, 0, time.Local)
	}
	for _, c := range []struct {
		raw  string
		want time.Time
	}{
		{"", time.Time{}},
		{"nonsense", time.Time{}},
		{"2026-09-12T10:30:00Z", time.Date(2026, 9, 12, 10, 30, 0, 0, time.UTC)},
		{"2026-09-12T10:30:00+02:00", time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)},
		{"2026-09-12T10:30:00", local(2026, 9, 12, 10, 30, 0)},
		{"2026-09-12T10:30", local(2026, 9, 12, 10, 30, 0)},
		{"2026-09-12", time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)},
		// A spelling the Date constructor accepts and this does not. It is the
		// engine-defined half of that constructor, and the answer for anything
		// unparseable is "absent" — one rule for the whole query string.
		{"Sat, 12 Sep 2026 10:30:00 GMT", time.Time{}},
	} {
		t.Run(c.raw, func(t *testing.T) {
			got := toolsTelemetryTime(c.raw)
			if !got.Equal(c.want) {
				t.Errorf("toolsTelemetryTime(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

func TestToolsTelemetryFilterIgnoresRepeatedParameters(t *testing.T) {
	// Express parses a repeated parameter into an array, whose parseInt is NaN
	// and whose Date is invalid; here the first value is read and, for the two
	// numbers, an unparseable one is the default. What matters is that neither
	// spelling produces a filter nobody asked for.
	query := httptest.NewRequest(http.MethodGet,
		"/tools/telemetry?userId=a&userId=b&limit=5&limit=9", nil).URL.Query()
	filter := toolsTelemetryFilter(query)
	if filter.UserID != "a" || filter.Limit != 5 {
		t.Errorf("filter = %#v, want the first of each repeated parameter", filter)
	}
}

func TestToolsTelemetryFilterLeavesTheRestZero(t *testing.T) {
	// Every absent parameter is TelemetryFilter's zero, which the store contract
	// reads as "do not filter on this" — the reference's undefined.
	filter := toolsTelemetryFilter(map[string][]string{})
	if filter != (TelemetryFilter{}) {
		t.Errorf("filter = %#v, want the zero filter", filter)
	}
}
