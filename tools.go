package auth

import (
	"net/http"
	"strings"
)

// The tools router's skeleton: where it mounts, which of its four feature
// groups are switched on, and — the substance of this file — who is allowed
// through it.
//
// This is the port of createToolsRouter's front half (tools.router.ts:117-135)
// together with its two documentation routes (:332-352). The four feature
// groups the router exists to carry are the PRs after this one: track and
// notify (:140-179), the SSE stream (:184-221), the telemetry query (:226-245)
// and the inbound webhook (:250-326). Each of them is one case in the switch in
// ToolsHandler and, where the reference guards it, one call to
// ToolsProtectMiddleware.
//
// # The posture
//
// The reference builds its guard slot like this:
//
//	const protect: RequestHandler[] = authMiddleware ? [authMiddleware] : [];
//
// (tools.router.ts:135). There is no built-in guard behind that ternary, and —
// unlike the admin router, which at least writes a warning to stderr
// (admin.router.ts:531-536) — nothing at all is said when the slot is left
// empty. All four feature flags default to true (:121-124). So a host that
// mounts the tools router and forgets authMiddleware does not get a stub: it
// publishes track, notify and the stream, and with a telemetry store the
// telemetry query too, to anyone who can reach the port.
//
// This port declines that default and mounts nothing until the host has said
// which posture it wants. That is the
// tools-router-requires-an-explicit-guard-decision deviation, and the
// reference's own default is one named call away — Access: auth.ToolsPublic().
//
// # Why, given that U12 already declined the same shape on the admin console
//
// The admin entry rested on two grounds, and both hold here with more force.
// HTTPConfig.Tools is new in this release, so there is no Go deployment whose
// configuration a refusal can break — no host has ever set these fields, and
// the first one to set them reads this doc while doing it. And the reference's
// signal cannot be ported: there the admin router at least prints a line, and
// this package writes diagnostics through Config.Logger, which defaults to nil
// and discards them; here there is no line to port in the first place.
//
// What is different is the surface, and it is worth pricing rather than
// assuming. The admin console reads the user table; the tools router writes
// telemetry and sends messages. That is not a smaller door:
//
//   - POST <tools>/track/:eventName takes userId, tenantId and sessionId from
//     the request body and only falls back to the authenticated principal
//     (tools.router.ts:143-147). An unauthenticated caller therefore forges
//     telemetry attributed to any user, and Track fans that forgery out to all
//     four sinks (auth_tools.go): it is persisted, it is published on the bus
//     where the host's own subscribers act on it, it is broadcast to the SSE
//     connections holding user:<id> — so an anonymous POST injects arbitrary
//     JSON into a named user's live stream — and it fires every matching
//     outgoing webhook, which is the deployment POSTing attacker-chosen content
//     to third parties in its own name, under its own signature, with retries.
//   - POST <tools>/notify/:target sends on the sse, email and sms channels. With
//     Mail and SMS configured, an anonymous caller names a user and the
//     deployment sends that user mail and text messages. That one costs money
//     and sender reputation, and neither is refundable.
//   - GET <tools>/stream with no principal resolves to the single topic
//     `global` (StreamTopics), which is not a small leak: global carries every
//     tracked event, and the frame is the whole telemetry record — user id,
//     session id, IP, user agent (auth-tools.ts:240). A deployment that has
//     called Bridge is then streaming its identity.* events to whoever
//     connects.
//
// So the cost of an open door here is not lower than on the admin surface, it
// is merely different in kind: it spends the deployment's money, speaks in the
// deployment's voice to third parties, and injects into other users' streams.
// Requiring the host to name the posture is the same statement U12 made, made
// where it cannot be missed, and ToolsMounted is exported so a host can turn
// the refusal into its own startup error in one line:
//
//	if cfg.Tools.Enabled && !cfg.ToolsMounted() { log.Fatal("tools: no access decision") }
//
// # Where it mounts, and why not under the API prefix
//
// Beside HTTPConfig.APIPrefix, at ToolsOptions.Path — "/tools" by default —
// exactly as the admin console mounts beside it. createToolsRouter returns an
// Express router the host mounts where it likes (tools.router.ts:114), and its
// own swaggerBasePath defaults to '/tools' (:127), which is the reference
// naming the place it expects to be mounted at.
//
// Mounting it under the API prefix instead would put it inside the auth
// router's middleware chain, which the reference's separate router is outside
// of, and that chain is wrong for this surface in a way that shows up
// immediately: CSRFMiddleware enforces the double-submit on a mutating request
// below the mount prefix (csrfEnforced), and POST <tools>/track is a
// server-to-server call carrying no cookie, no header pair and no browser
// origin. It would also make an operator's reverse-proxy rule for /auth
// silently expose the tools surface with it.
//
// # What is not wrapped around it
//
// As for the admin console, the four adapters mount this handler bare: no
// CSRFMiddleware, no RateLimitMiddleware, no EventContextMiddleware. All three
// belong to the auth router, applied because the reference registers its auth
// routes after a router-level CSRF auto-init (auth.router.ts:529-538); this is
// a different router and carries none of them. The consequence to state rather
// than hide is that once U23 lands, POST <tools>/track and POST <tools>/notify
// accept a cross-site form post from a browser that holds a session — which is
// the reference's own shape, and which is the first thing a host's
// authMiddleware is there to stop.

// The tools router's own paths, relative to its mount. The two documentation
// routes reuse DocsSpecPath and DocsUIPath: the reference registers them at the
// same two literals on both routers (tools.router.ts:333, :348 against
// auth.router.ts:1658, :1674), and spelling them once is what keeps that true.
const (
	// DefaultToolsPath is ToolsOptions.Path's default and the reference's
	// swaggerBasePath default (tools.router.ts:127).
	DefaultToolsPath = "/tools"

	// The five feature routes, each the parent path of a group U23 through U25
	// mounts. The three that take a path parameter are spelled without it —
	// the reference's are '/track/:eventName', '/notify/:target' and
	// '/webhook/:provider' — because what the switch in ToolsHandler matches on
	// is the segment above the parameter.
	ToolsTrackPath     = "/track"     // tools.router.ts:141, U23
	ToolsNotifyPath    = "/notify"    // tools.router.ts:166, U23
	ToolsStreamPath    = "/stream"    // tools.router.ts:192, U24
	ToolsTelemetryPath = "/telemetry" // tools.router.ts:227, U25
	ToolsWebhookPath   = "/webhook"   // tools.router.ts:251, U25
)

// ToolsAccess is the reference's authMiddleware slot (tools.router.ts:43,
// read at :135), with the third state the reference does not distinguish.
//
// It is a struct behind a pointer for the reason AdminAccessPolicy is: there
// are three configurations and not two — a guard, a deliberate absence of one,
// and nothing said at all — and only the first two are configurations this port
// will serve. A nil *ToolsAccess is "not set", and HTTPConfig.ToolsMounted is
// false for it.
//
// Build one with ToolsProtected or ToolsPublic rather than by hand, so that the
// decision reads as one call in a host's configuration.
type ToolsAccess struct {
	// Middleware is the guard every route the reference spreads ...protect onto
	// goes behind: track, notify, stream and the telemetry query
	// (tools.router.ts:141, :166, :192, :227). Nil is the reference's empty
	// slot — no guard — and is only reachable through ToolsPublic.
	//
	// Two of the six route groups never see it, there or here. The inbound
	// webhook is registered with no protect at all (:251), because the caller
	// is a third-party provider that has no session to present; and the two
	// documentation routes carry none either (:333, :348). U25 owns the first
	// of those and should verify the sender some other way.
	Middleware func(http.Handler) http.Handler
}

// ToolsProtected is the ordinary configuration: every guarded route goes behind
// mw, which is the reference's authMiddleware. A host usually passes its
// adapter's Middleware() — the same value it protects its own routes with — so
// that a tools call is authenticated exactly as an API call is.
//
// A nil mw returns nil rather than an unguarded router. Passing one is a host
// whose middleware variable was never assigned, and a configuration that
// silently degrades from "guarded" to "open" is the failure this whole file
// exists to prevent; nil is "not set", so nothing mounts and every tools path
// answers 404 until the host looks.
func ToolsProtected(mw func(http.Handler) http.Handler) *ToolsAccess {
	if mw == nil {
		return nil
	}
	return &ToolsAccess{Middleware: mw}
}

// ToolsPublic is the reference's own default, asked for by name: no guard on
// any route, so track, notify and the stream answer to any caller that can
// reach the mount.
//
// It exists because the reference's default has to stay reachable — a port that
// removed the configuration would be removing a capability rather than making
// it explicit — and because a decision spelled in the host's own source is a
// decision a reviewer can find. Read ToolsAccess and the head of this file
// before choosing it.
func ToolsPublic() *ToolsAccess { return &ToolsAccess{} }

// ToolsOptions is HTTPConfig.Tools: whether the adapters mount the tools
// router, where, with which feature groups, and behind what.
//
// It is the reference's ToolsRouterOptions (tools.router.ts:13-102) less the
// store and callback slots that belong to the routes that read them —
// telemetryStore, webhookStore, settingsStore and onWebhook arrive with U25,
// which owns the two routes that consult them.
type ToolsOptions struct {
	// Enabled mounts the tools router, the way Docs.Enabled mounts the
	// documentation routes and Admin.Enabled mounts the console. Unset — the
	// default — nothing under Path is registered and every tools path answers
	// 404.
	//
	// Enabled on its own is not sufficient: AuthTools and Access must both be
	// set too, which is what HTTPConfig.ToolsMounted reports. See the head of
	// this file for the second of those.
	Enabled bool
	// Path is where the tools router mounts, on the same router the adapter was
	// given and beside HTTPConfig.APIPrefix rather than under it. Empty means
	// DefaultToolsPath, which is the reference's own default (:127).
	Path string
	// AuthTools is the facade every route of this router calls: the reference's
	// first argument to createToolsRouter (:117). Nil mounts nothing, because a
	// router whose every handler needs it would answer 500 on each of them.
	//
	// It is here, and not on the Auth, because U21 left the question open in
	// exactly these terms: how the facade reaches the adapters is route
	// mounting, and route mounting is what HTTPConfig describes. Nothing in the
	// service layer calls it — Track and Notify are a host's fan-out, not the
	// library's — so an Option that put it on the Auth would be storing a value
	// only the adapters read. NewAuthTools takes a context and returns an
	// error, so the host builds it and hands it over, the way it hands over a
	// RateLimiter.
	AuthTools *AuthTools
	// Access decides who reaches the guarded routes. Nil is "not configured"
	// and mounts nothing at all; ToolsProtected(mw) is the ordinary
	// configuration and ToolsPublic() is the reference's default.
	//
	// This is the field the head of this file is about.
	Access *ToolsAccess
	// The four feature flags, spelled in the negative because the reference's
	// default is on and Go's zero value is off (tools.router.ts:121-124). A
	// zero ToolsOptions therefore selects what `createToolsRouter(tools, {})`
	// selects: all four groups. Naming them for what a host has to set to
	// change that is the stdlib's own answer to this (http.Transport's
	// DisableKeepAlives, DisableCompression), and it beats a *bool whose three
	// states are two.
	//
	// Each of them gates the routes of one group and nothing else. Read them
	// through Features, which resolves the negation once.
	DisableTelemetry bool // the reference's `telemetry: false` — POST /track/:eventName and GET /telemetry
	DisableNotify    bool // `notify: false` — POST /notify/:target
	DisableStream    bool // `stream: false` — GET /stream
	DisableWebhook   bool // `webhook: false` — POST /webhook/:provider
	// Docs mounts this router's own two documentation routes, GET
	// <tools>/openapi.json and GET <tools>/docs (tools.router.ts:332-352).
	//
	// It is DocsOptions, the same type HTTPConfig.Docs is, because the
	// reference's two options are the same pair: `swagger` and
	// `swaggerBasePath` (:93, :101) against the auth router's (auth.router.ts:
	// 123-139). Everything that type's doc comment says applies here — in
	// particular that Enabled is a plain bool where the reference's option is
	// also the string "auto", and that the page it serves loads swagger-ui-dist
	// from a CDN.
	//
	// BasePath is this router's swaggerBasePath: empty means ToolsPath(). It
	// moves the description and the page's spec URL, never the mount.
	Docs DocsOptions
}

// ToolsFeatures is the four feature flags resolved: which groups of routes the
// router mounts, in the reference's own spelling and polarity.
type ToolsFeatures struct {
	// Telemetry is the reference's `telemetry`, and it gates two routes rather
	// than one: POST /track/:eventName (tools.router.ts:140) and, when a
	// telemetry store with a query is configured, GET /telemetry (:226).
	Telemetry bool
	Notify    bool
	Stream    bool
	Webhook   bool
}

// Features resolves the four flags. It is the one place the negation is
// undone, so the switch in ToolsHandler, the OpenAPI document and any later
// route read the same answer.
func (o ToolsOptions) Features() ToolsFeatures {
	return ToolsFeatures{
		Telemetry: !o.DisableTelemetry,
		Notify:    !o.DisableNotify,
		Stream:    !o.DisableStream,
		Webhook:   !o.DisableWebhook,
	}
}

// ToolsPath is ToolsOptions.Path resolved: the configured value normalised the
// way Prefix normalises the API prefix, or DefaultToolsPath when none is set.
func (c HTTPConfig) ToolsPath() string {
	path := strings.TrimSpace(c.Tools.Path)
	if path == "" {
		return DefaultToolsPath
	}
	return "/" + strings.Trim(path, "/")
}

// ToolsMounted reports whether the adapters register the tools router: the
// block is enabled, a facade was supplied, and an access decision has been
// made for it.
//
// The third condition is the tools-router-requires-an-explicit-guard-decision
// deviation. It is a method rather than a field so that the four adapters
// cannot come to disagree about the condition, and so that a host can assert on
// it at startup — see the head of this file.
func (c HTTPConfig) ToolsMounted() bool {
	return c.Tools.Enabled && c.Tools.AuthTools != nil && c.Tools.Access != nil
}

// ToolsDocsBasePath is ToolsOptions.Docs.BasePath resolved: the configured
// value, or the tools mount when none is configured. It is the counterpart of
// DocsBasePath, and the reference's swaggerBasePath (tools.router.ts:127, read
// at :342 and :350).
func (c HTTPConfig) ToolsDocsBasePath() string {
	if strings.TrimSpace(c.Tools.Docs.BasePath) == "" {
		return c.ToolsPath()
	}
	return HTTPConfig{APIPrefix: c.Tools.Docs.BasePath}.Prefix()
}

// ToolsOpenAPIInfo is the document this mount describes, read off the
// configuration it was mounted with. It is exported for the same reason
// (*Adapter).OpenAPIInfo is: a host that serves the document from its own route
// or writes it to a file at build time needs exactly this value.
func (c HTTPConfig) ToolsOpenAPIInfo() ToolsOpenAPIInfo {
	features := c.Tools.Features()
	return ToolsOpenAPIInfo{
		BasePath:  c.ToolsDocsBasePath(),
		Telemetry: features.Telemetry,
		Notify:    features.Notify,
		Stream:    features.Stream,
		Webhook:   features.Webhook,
		Docs:      c.Tools.Docs.Enabled,
	}
}

// ToolsProtectMiddleware is the reference's `...protect` spread
// (tools.router.ts:135) as one wrapper: the configured guard, or a
// pass-through when the host asked for ToolsPublic.
//
// It is the counterpart of RateLimitMiddleware and CSRFMiddleware and is
// written the same way, so that every route U23 through U25 adds behind a guard
// is one call — ToolsProtectMiddleware(cfg)(handler) — and none of them has to
// re-derive which configurations mean "no guard". A configuration with no
// Access at all never reaches here: ToolsMounted is false for it and the
// adapters register no route to wrap.
func ToolsProtectMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	access := cfg.Tools.Access
	if access == nil || access.Middleware == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return access.Middleware
}

// ToolsHandler serves the whole tools router, dispatched on the path below the
// mount.
//
// It is one handler rather than a mount per route for the reason AdminHandler
// and UIHandler are: the reference mounts one router, three of its six route
// groups carry a path parameter, and a catch-all beside fixed siblings is not a
// shape every Go router will register — gin's tree refuses it outright. The
// four adapters mount this at <ToolsPath> and <ToolsPath>/, and U23 through U25
// add their routes to the switch below rather than to four mount functions.
//
// The shape a later route takes is the one GET <tools>/stream took below: the
// handler built once outside the closure — the guard chain and anything it
// captures must not be rebuilt per request — behind ToolsProtectMiddleware
// where the reference spreads ...protect, left nil when its feature flag is
// off, and matched on the nil in the case itself, so that the flag is read once
// and the switch carries no second copy of it. Anything the switch does not
// recognise is a 404, which is what an Express router with no matching layer
// ends at.
//
// The receiver is unused today and is not decoration: U25's inbound webhook
// resolves the enabled action set through Config.Settings, which this Auth
// already holds — the reason ToolsOptions carries no settingsStore of its own.
func (a *Auth) ToolsHandler(cfg HTTPConfig) http.Handler {
	// The two documentation routes (tools.router.ts:332-352), built once. Both
	// are nil when this router's own swagger option is off, which is how the
	// reference registers neither (:332).
	//
	// Neither goes behind ToolsProtectMiddleware: the reference gives them no
	// protect (:333, :348), so the document and the page are readable by anyone
	// who can reach the mount even when every other route is guarded. That is
	// the same posture the auth router's pair has (docs.go), and the same
	// warning applies — the document describes the surface, and the page loads
	// a CDN bundle onto this origin.
	var spec, page http.Handler
	if cfg.Tools.Docs.Enabled {
		spec = ToolsOpenAPIHandler(cfg.ToolsOpenAPIInfo())
		// The page is SwaggerUIHandler unchanged, which is the reference's one
		// buildSwaggerUiHtml serving all three of its routers (openapi.ts:1646,
		// read at tools.router.ts:350). Its title says "Tools API" — a quirk
		// this port already reproduces on the auth router, where it is wrong;
		// here it is simply correct, and the two pages differ only in the spec
		// URL they are given.
		page = SwaggerUIHandler(cfg.ToolsDocsBasePath() + DocsSpecPath)
	}

	// GET <tools>/stream (tools.router.ts:192-220), built once and wrapped in
	// the reference's two middlewares in the reference's order: extractSseToken
	// (:185-190), which is the posture and is documented in tools_stream.go,
	// then the guard it spreads ...protect onto. Nil when the stream flag is
	// off, which is the `if (stream)` at :184 — the nil-handler shape the two
	// documentation routes above already use for their own flag, so the switch
	// reads one flag per route in one place.
	var stream http.Handler
	if cfg.Tools.Features().Stream {
		stream = ToolsSseTokenMiddleware(ToolsProtectMiddleware(cfg)(a.toolsStreamHandler(cfg)))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rel := toolsRouterPath(r, cfg); {
		// U23 adds POST <tools>/track/:eventName and POST <tools>/notify/:target
		// here, U25 GET <tools>/telemetry and POST <tools>/webhook/:provider.
		// The documentation routes stay last, as the reference registers them
		// last.
		case stream != nil && rel == ToolsStreamPath && isToolsRead(r):
			stream.ServeHTTP(w, r)
		case spec != nil && rel == DocsSpecPath && isToolsRead(r):
			spec.ServeHTTP(w, r)
		case page != nil && rel == DocsUIPath && isToolsRead(r):
			page.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// isToolsRead is Express's fallback from HEAD to a GET layer, which every
// router.get in the reference's tools router inherits.
func isToolsRead(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

// toolsRouterPath is the path below the tools mount, the way adminRouterPath is
// the path below the admin mount.
func toolsRouterPath(r *http.Request, cfg HTTPConfig) string {
	mount := cfg.ToolsPath()
	switch p := r.URL.Path; {
	case p == mount:
		return "/"
	case strings.HasPrefix(p, mount+"/"):
		return p[len(mount):]
	default:
		return p
	}
}
