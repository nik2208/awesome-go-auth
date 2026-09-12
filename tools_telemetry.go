package auth

import (
	"net/http"
	"time"
)

// GET <tools>/telemetry, the tools router's query endpoint
// (tools.router.ts:226-245).
//
// It is the read side of the group POST <tools>/track writes, it shares that
// route's guard — the reference spreads the same ...protect onto both (:227) —
// and it is the only route of this router that answers with stored data.
//
// # It is mounted on two conditions, not one
//
//	if (telemetry && options.telemetryStore?.query)
//
// (:226). The Telemetry feature flag and a configured store, which here is
// ToolsOptions.TelemetryStore. With no store the route is not registered at
// all, so a client cannot tell "no telemetry store" from "no tools router":
// both answer 404. That is the reference's condition reproduced, and the
// alternative — an empty list — would tell a caller the store exists and
// happens to be empty.
//
// The reference then re-checks inside the handler and answers 501 (:229-232),
// which is unreachable: the registration already required store.query. The
// check is kept below because TelemetryStore here is one interface with a
// mandatory Query, so the state it describes — a store that cannot be queried
// — is not expressible in Go at all, and a nil store reaching the handler
// would be a routing bug rather than a configuration. It answers the
// reference's literal, so that if it ever fires a client sees what the
// reference would have sent.
//
// # What it does not do, and this is the part to read
//
// It does not scope the result to the caller. Every filter is read from the
// query string and nothing at all is read from the authenticated principal
// (:232-243) — there is no req.user anywhere on this route — so
// ?userId=someone-else is honoured, and a request with no filter returns
// whatever the store returns for an empty filter: everyone's events, up to
// whatever limit was asked for. The record is the whole telemetry row, IP and
// user agent included.
//
// So this route is a store-wide read behind whatever ToolsAccess happens to be,
// and with ToolsPublic it is a store-wide read behind nothing. That is the
// reference's shape and it is reproduced; it is also the strongest single
// argument in the tools-router-requires-an-explicit-guard-decision entry. A
// deployment that wants per-principal scoping puts it in the guard, or does not
// mount the route — ToolsOptions.DisableTelemetry, which takes POST /track with
// it, because the reference has one flag for both.
//
// # The query string
//
// Seven parameters, destructured in one statement (:233). sessionId is not
// among them although TelemetryFilter declares it (:34) and the record carries
// it — so a client cannot filter on the identifier U17 added for exactly that
// join. Reproduced: an unknown parameter is ignored rather than refused, which
// is what Express's query parser and a destructure do together.
//
// Nothing is clamped. The admin listings clamp limit to 100 in the route
// (admin.router.ts:1366) and this one does not, so ?limit=1000000 is what the
// store is asked for and the size of the answer is the store's business. A
// deployment that needs a ceiling puts it in its TelemetryStore, where it also
// applies to every other caller of Query.
func (a *Auth) toolsTelemetryHandler(cfg HTTPConfig) http.Handler {
	store := cfg.Tools.TelemetryStore
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The reference's unreachable 501 (:229-232). See the head of this file.
		if store == nil {
			WriteHTTPError(w, HTTPErrTelemetryQueryUnsupported)
			return
		}
		events, err := store.Query(r.Context(), toolsTelemetryFilter(r.URL.Query()))
		if err != nil {
			// The reference has no catch on this route: it is an async handler
			// whose rejection Express 4 forwards nowhere, so the request never
			// completes at all. A Go handler that returns has answered, so there
			// is no equivalent to reproduce and the answer is the generic one. It
			// carries no detail, as HTTPErrInternal never does — a failing store
			// must not describe itself to a caller this route may not have
			// authenticated.
			if a.service != nil {
				a.service.logf("auth: tools telemetry query failed: %v", err)
			}
			WriteHTTPError(w, HTTPErrInternal)
			return
		}
		// res.json({ data: results }) (:244). The record is trackedRecord's
		// spelling and not this package's TelemetryEvent: `event`, `data` and the
		// absence of `success` are what the reference's TelemetryEvent is on the
		// wire, what an SSE frame carries, and what this document's
		// TelemetryEvent schema declares (openapi.ts:1607-1619).
		//
		// The slice is made non-nil so an empty result is [] and not null. An
		// empty JS array encodes as [], and every client here iterates.
		records := make([]trackedRecord, 0, len(events))
		for _, event := range events {
			records = append(records, newTrackedRecord(event))
		}
		WriteJSON(w, http.StatusOK, map[string]any{"data": records})
	})
}

// HTTPErrTelemetryQueryUnsupported is the reference's 501 (:230):
// {"error": "Telemetry query not supported by the configured store"}. No code
// field, because the reference's literal has one key.
var HTTPErrTelemetryQueryUnsupported = HTTPError{
	Status:  http.StatusNotImplemented,
	Message: "Telemetry query not supported by the configured store",
}

// The seven query parameters of GET <tools>/telemetry (tools.router.ts:233),
// named because two files read them: this one and the document that describes
// them.
const (
	ToolsTelemetryEventParam    = "event"
	ToolsTelemetryUserIDParam   = "userId"
	ToolsTelemetryTenantIDParam = "tenantId"
	ToolsTelemetryFromParam     = "from"
	ToolsTelemetryToParam       = "to"
	ToolsTelemetryLimitParam    = "limit"
	ToolsTelemetryOffsetParam   = "offset"
)

// toolsTelemetryFilter is the reference's filter object built from the query
// string (tools.router.ts:234-242).
//
// Every parameter is optional and every absent one is the zero value, which
// TelemetryFilter already defines as "do not filter on this" — the reference's
// undefined, which its own store contract reads the same way.
//
// The two conversions are new Date(x) and parseInt(x, 10), and both have a
// spelling with no Go answer. A value JavaScript cannot convert yields NaN or
// an Invalid Date and both flow onward into the store: a filter carrying NaN is
// whatever the store makes of it — the interface's own example hands it to a SQL
// LIMIT (telemetry-store.interface.ts:52-57) — and a comparison against an
// Invalid Date is false for every row, so an unparseable `from` silently
// returns nothing at all. There is no single behaviour to reproduce even in
// principle, and neither an int nor a time.Time can carry either value.
//
// So an unparseable value is treated as absent, which is adminQueryInt's own
// answer to the same problem and is therefore one rule for the whole query
// string rather than two. It is also the answer for the only spelling a client
// actually sends, which is none.
func toolsTelemetryFilter(query map[string][]string) TelemetryFilter {
	get := func(name string) string {
		values := query[name]
		if len(values) == 0 {
			return ""
		}
		// The first of a repeated parameter. Express would parse ?limit=1&limit=2
		// into an array, whose parseInt is NaN and whose Date is invalid — both
		// of which are the "treated as absent" case above, one step later.
		return values[0]
	}
	return TelemetryFilter{
		EventName: get(ToolsTelemetryEventParam),
		UserID:    get(ToolsTelemetryUserIDParam),
		TenantID:  get(ToolsTelemetryTenantIDParam),
		Since:     toolsTelemetryTime(get(ToolsTelemetryFromParam)),
		Until:     toolsTelemetryTime(get(ToolsTelemetryToParam)),
		// adminQueryInt is parseInt(x, 10) with a default, written once in
		// admin_read.go; the default here is 0, which is TelemetryFilter's
		// "unset" for both fields. It is shared rather than copied because the
		// two routes convert the same two parameters with the same JavaScript
		// function, including its leading-digits rule — ?limit=12abc is 12 on
		// both.
		Limit:  adminQueryInt(get(ToolsTelemetryLimitParam), 0),
		Offset: adminQueryInt(get(ToolsTelemetryOffsetParam), 0),
	}
}

// toolsTelemetryLayouts are the spellings of new Date(s) this route accepts, in
// the order they are tried.
//
// The reference hands the raw string to the Date constructor, which parses far
// more than ISO 8601 and does so differently per engine. What is reproduced is
// the part that is specified rather than implementation-defined, which is ISO
// 8601 — including its two zone rules, because they differ and both are
// observable: a date-only string is UTC midnight, and a date-time with no
// offset is local time.
var toolsTelemetryLayouts = []struct {
	layout string
	local  bool
}{
	{layout: time.RFC3339, local: false},
	{layout: "2006-01-02T15:04:05", local: true},
	{layout: "2006-01-02T15:04", local: true},
	{layout: "2006-01-02", local: false},
}

// toolsTelemetryTime is `x ? new Date(x) : undefined` (tools.router.ts:237-238)
// over the layouts above. Anything else — including an empty parameter, which is
// the falsy half of the ternary — is the zero Time, which TelemetryFilter reads
// as no bound.
func toolsTelemetryTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, candidate := range toolsTelemetryLayouts {
		if candidate.local {
			if parsed, err := time.ParseInLocation(candidate.layout, raw, time.Local); err == nil {
				return parsed
			}
			continue
		}
		if parsed, err := time.Parse(candidate.layout, raw); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
