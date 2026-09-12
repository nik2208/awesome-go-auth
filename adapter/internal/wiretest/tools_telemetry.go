package wiretest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// GET <tools>/telemetry for all four adapters: when it is mounted, what guards
// it, what the query string becomes, and what the body looks like.
//
// The route is three lines of work over a store, so most of what is worth
// pinning is either side of it — the two-part mount condition, the guard it
// shares with track, and the filter the query string turns into. That last one
// is asserted against a recording store rather than against returned rows,
// because a filter is what this route actually produces: the rows are the
// store's answer, and a store that ignored the filter entirely would still
// return rows a looser assertion would accept.

// toolsTelemetryRecorder is a TelemetryStore that keeps what it was asked and
// answers what the case told it to.
type toolsTelemetryRecorder struct {
	events []auth.TelemetryEvent
	filter auth.TelemetryFilter
	calls  int
	err    error
}

func (s *toolsTelemetryRecorder) Record(_ context.Context, event auth.TelemetryEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *toolsTelemetryRecorder) Query(_ context.Context, filter auth.TelemetryFilter) ([]auth.TelemetryEvent, error) {
	s.calls++
	s.filter = filter
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

// toolsTelemetryEnv mounts the tools router with store as its telemetry store.
func toolsTelemetryEnv(t *testing.T, mount Mounter, store auth.TelemetryStore, opts ...func(*auth.ToolsOptions)) *Env {
	t.Helper()
	return NewEnv(t, mount, toolsConfig(t, append([]func(*auth.ToolsOptions){
		func(o *auth.ToolsOptions) { o.TelemetryStore = store },
	}, opts...)...))
}

// toolsTelemetryRows is the `data` array of a successful query.
func toolsTelemetryRows(t *testing.T, env *Env, query string) []any {
	t.Helper()
	rec := env.Do(toolsRequest(env, http.MethodGet, auth.ToolsTelemetryPath+query))
	AssertStatus(t, rec, http.StatusOK)
	body := Body(t, rec)
	AssertKeys(t, body, "data")
	rows, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("data = %#v, want an array", body["data"])
	}
	return rows
}

func testToolsTelemetry(t *testing.T, mount Mounter) {
	t.Run("a telemetry store is half the mount condition", func(t *testing.T) {
		// `if (telemetry && options.telemetryStore?.query)` (tools.router.ts:226).
		// The flag is on by default and the store is not configured, so the route
		// does not exist — 404 rather than an empty list, which would tell a
		// caller the store is there and happens to hold nothing.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.TelemetryStore = nil }))
		assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodGet, auth.ToolsTelemetryPath)))
	})

	t.Run("the telemetry flag is the other half", func(t *testing.T) {
		// One flag gates both routes of the group there (:121, read at :140 and
		// :226), so turning telemetry off takes the query with track.
		env := toolsTelemetryEnv(t, mount, auth.NewMemoryTelemetryStore(),
			func(o *auth.ToolsOptions) { o.DisableTelemetry = true })
		assertToolsUnrouted(t, env.Do(toolsRequest(env, http.MethodGet, auth.ToolsTelemetryPath)))
	})

	t.Run("it is behind the guard", func(t *testing.T) {
		// The reference spreads the same ...protect onto this route as onto track
		// (:227). A guard that refuses everything must therefore be reached before
		// the store is.
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store, func(o *auth.ToolsOptions) {
			o.Access = auth.ToolsProtected(func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				})
			})
		})
		AssertStatus(t, env.Do(toolsRequest(env, http.MethodGet, auth.ToolsTelemetryPath)), http.StatusForbidden)
		if store.calls != 0 {
			t.Errorf("the store was queried %d times behind a refusing guard, want 0", store.calls)
		}
	})

	t.Run("an empty store answers an empty array", func(t *testing.T) {
		// `res.json({ data: results })` (:244). [] and not null: an empty JS array
		// encodes as [], and every client here iterates.
		env := toolsTelemetryEnv(t, mount, auth.NewMemoryTelemetryStore())
		if rows := toolsTelemetryRows(t, env, ""); len(rows) != 0 {
			t.Errorf("data = %#v, want an empty array", rows)
		}
	})

	t.Run("a record is the reference's TelemetryEvent on the wire", func(t *testing.T) {
		// The wire shape is the reference's ten members (openapi.ts:1607-1619),
		// which is this package's trackedRecord and not its TelemetryEvent: the
		// event name is `event`, the payload is `data`, the timestamp is an ISO
		// string, and the fields this port added for itself — Success, Error —
		// are not on the wire at all.
		store := &toolsTelemetryRecorder{events: []auth.TelemetryEvent{{
			ID:            "tel_1",
			EventName:     "identity.probe",
			UserID:        "user-1",
			TenantID:      "tenant-1",
			SessionID:     "sess-1",
			CorrelationID: "corr-1",
			IP:            "203.0.113.7",
			UserAgent:     "probe/1.0",
			Success:       true,
			Error:         "ignored",
			Timestamp:     time.Date(2026, 9, 12, 10, 30, 0, 0, time.UTC),
			Meta:          map[string]any{"k": "v"},
		}}}
		env := toolsTelemetryEnv(t, mount, store)
		rows := toolsTelemetryRows(t, env, "")
		if len(rows) != 1 {
			t.Fatalf("data = %#v, want one row", rows)
		}
		row, ok := rows[0].(map[string]any)
		if !ok {
			t.Fatalf("row = %#v, want an object", rows[0])
		}
		for key, want := range map[string]any{
			"id":            "tel_1",
			"event":         "identity.probe",
			"userId":        "user-1",
			"tenantId":      "tenant-1",
			"sessionId":     "sess-1",
			"correlationId": "corr-1",
			"ip":            "203.0.113.7",
			"userAgent":     "probe/1.0",
			"timestamp":     "2026-09-12T10:30:00.000Z",
		} {
			if row[key] != want {
				t.Errorf("row[%q] = %#v, want %#v", key, row[key], want)
			}
		}
		if data, _ := row["data"].(map[string]any); data["k"] != "v" {
			t.Errorf("row[\"data\"] = %#v, want the meta map", row["data"])
		}
		for _, absent := range []string{"eventName", "success", "error", "meta"} {
			if _, ok := row[absent]; ok {
				t.Errorf("row carries %q, which is this port's field name and not the wire's", absent)
			}
		}
	})

	t.Run("the query string becomes the filter", func(t *testing.T) {
		// The seven parameters of :233-242, each in the field TelemetryFilter
		// holds it in.
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store)
		toolsTelemetryRows(t, env, "?event=identity.probe&userId=u1&tenantId=t1"+
			"&from=2026-09-01T00:00:00Z&to=2026-09-30T00:00:00Z&limit=25&offset=50")
		want := auth.TelemetryFilter{
			EventName: "identity.probe",
			UserID:    "u1",
			TenantID:  "t1",
			Since:     time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			Until:     time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
			Limit:     25,
			Offset:    50,
		}
		got := store.filter
		if got.EventName != want.EventName || got.UserID != want.UserID || got.TenantID != want.TenantID ||
			!got.Since.Equal(want.Since) || !got.Until.Equal(want.Until) ||
			got.Limit != want.Limit || got.Offset != want.Offset {
			t.Errorf("filter = %#v, want %#v", got, want)
		}
	})

	t.Run("nothing is clamped and nothing is scoped", func(t *testing.T) {
		// Two facts in one case because they are the same fact twice: this route
		// passes the query string on. The admin listings clamp limit to 100
		// (admin.router.ts:1366) and this one does not; and `userId` is read from
		// the query rather than from the principal (:233), so it reaches the store
		// as asked even though the request carries no credential naming anyone.
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store)
		toolsTelemetryRows(t, env, "?limit=1000000&userId=somebody-else")
		if store.filter.Limit != 1000000 {
			t.Errorf("Limit = %d, want 1000000 — this route clamps nothing", store.filter.Limit)
		}
		if store.filter.UserID != "somebody-else" {
			t.Errorf("UserID = %q, want the query's value", store.filter.UserID)
		}
	})

	t.Run("sessionId is not a parameter", func(t *testing.T) {
		// TelemetryFilter declares it (telemetry-store.interface.ts:34) and the
		// route does not destructure it (:233), so a client cannot filter on the
		// identifier that makes a record joinable. Reproduced: an unknown
		// parameter is ignored rather than refused.
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store)
		toolsTelemetryRows(t, env, "?sessionId=sess-1")
		if store.filter.SessionID != "" {
			t.Errorf("SessionID = %q, want it unread", store.filter.SessionID)
		}
	})

	t.Run("an unparseable value is treated as absent", func(t *testing.T) {
		// parseInt('abc', 10) is NaN and new Date('nonsense') is an Invalid Date,
		// and neither an int nor a time.Time can carry either. The answer is
		// adminQueryInt's: the default, which for both of these is "no bound".
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store)
		toolsTelemetryRows(t, env, "?limit=abc&offset=&from=nonsense&to=")
		if store.filter.Limit != 0 || store.filter.Offset != 0 {
			t.Errorf("limit/offset = %d/%d, want 0/0", store.filter.Limit, store.filter.Offset)
		}
		if !store.filter.Since.IsZero() || !store.filter.Until.IsZero() {
			t.Errorf("since/until = %v/%v, want both zero", store.filter.Since, store.filter.Until)
		}
	})

	t.Run("a leading integer is that integer", func(t *testing.T) {
		// parseInt('12abc', 10) is 12, on this route as on the admin listings.
		store := &toolsTelemetryRecorder{}
		env := toolsTelemetryEnv(t, mount, store)
		toolsTelemetryRows(t, env, "?limit=12abc")
		if store.filter.Limit != 12 {
			t.Errorf("Limit = %d, want 12", store.filter.Limit)
		}
	})

	t.Run("a failing store is a 500 with no detail", func(t *testing.T) {
		// The reference has no catch here at all, so there is no shape to copy;
		// what must not happen is the store's own message reaching a caller this
		// route may not have authenticated.
		store := &toolsTelemetryRecorder{err: errors.New("telemetry database is on fire")}
		env := toolsTelemetryEnv(t, mount, store)
		rec := env.Do(toolsRequest(env, http.MethodGet, auth.ToolsTelemetryPath))
		AssertStatus(t, rec, http.StatusInternalServerError)
		if body := rec.Body.String(); strings.Contains(body, "fire") {
			t.Errorf("the 500 describes the store failure: %s", body)
		}
	})

	t.Run("HEAD is served from the GET route", func(t *testing.T) {
		// router.get serves HEAD when no HEAD layer is registered (:227).
		env := toolsTelemetryEnv(t, mount, auth.NewMemoryTelemetryStore())
		AssertStatus(t, env.Do(toolsRequest(env, http.MethodHead, auth.ToolsTelemetryPath)), http.StatusOK)
	})

	t.Run("it is read-only", func(t *testing.T) {
		env := toolsTelemetryEnv(t, mount, auth.NewMemoryTelemetryStore())
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			assertToolsUnrouted(t, env.Do(toolsRequest(env, method, auth.ToolsTelemetryPath)))
		}
	})

	t.Run("the document describes it only when it is mounted", func(t *testing.T) {
		// hasTelemetryQuery (openapi.ts:1378) is the same two-part condition as
		// the mount, which is what keeps this one route out of the "documented and
		// answers 404" class the inbound webhook is deliberately in.
		env := NewEnv(t, mount, toolsConfig(t, func(o *auth.ToolsOptions) { o.TelemetryStore = nil }))
		paths := toolsDocumentPaths(t, toolsDocument(t, env))
		if _, ok := paths[env.Config.ToolsPath()+auth.ToolsTelemetryPath]; ok {
			t.Errorf("the document describes the telemetry query with no store configured")
		}
	})
}
