package auth

import "net/http"

// The tools router's OpenAPI document: the port of buildOpenApiSpec
// (openapi.ts:1366-1637), which is the reference's second generator and has
// nothing to do with the auth router's.
//
// Two generators because the reference has two, and because they describe two
// routers mounted at two unrelated paths. GenerateOpenAPISpec writes paths
// below HTTPConfig.Prefix(); this one writes them below
// HTTPConfig.ToolsDocsBasePath(), which defaults to the tools mount. Merging
// them would mean one document claiming to describe a surface the adapter
// serves somewhere else entirely.
//
// The document grows with the routes. The four feature groups arrive in U23
// through U25, and each of those PRs adds its path item here beside the switch
// case that mounts it — the pairing the conformance suite then holds in both
// directions (adapter/internal/wiretest/tools.go), which is exactly how the
// auth document and the auth mount are kept honest. A path item written ahead
// of its route would document an endpoint that answers 404, which is the one
// failure that suite exists to catch.

// ToolsOpenAPIInfo is what the tools document is generated from: the feature
// flags that select its path items, and the base path they are written under.
//
// It is the reference's Pick<ToolsRouterOptions, 'telemetry' | 'notify' |
// 'stream' | 'webhook' | 'telemetryStore'> plus basePath (openapi.ts:1366-1369).
// HTTPConfig.ToolsOpenAPIInfo fills one in from a mounted configuration, which
// is how the adapters get it; a caller building one by hand is describing a
// mount it is responsible for matching.
type ToolsOpenAPIInfo struct {
	// Title, Description and Version default to the reference's literals with
	// the package name changed (openapi.ts:1628-1632). They name the host's
	// tools surface, so a caller that wants its own fills them in.
	Title       string
	Description string
	Version     string
	// BasePath is where the tools router is mounted, and the prefix every
	// documented path carries: the reference's basePath parameter, whose
	// default is '/tools' (openapi.ts:1368). Empty means DefaultToolsPath.
	BasePath string
	// The four feature flags, in the reference's polarity: each one includes
	// the path items of its group. They must match the ToolsOptions the adapter
	// was mounted with, or the document describes routes the server does not
	// serve — HTTPConfig.ToolsOpenAPIInfo is the way not to have to remember
	// that.
	//
	// They select no path items yet, because U22 mounts none of the four
	// groups; what they select today is the tags block, which is the
	// reference's own flag-driven vocabulary declaration (openapi.ts:1621-1625).
	Telemetry bool
	Notify    bool
	Stream    bool
	Webhook   bool
	// Docs mirrors ToolsOptions.Docs.Enabled: the two documentation routes the
	// adapters then mount, GET <tools>/openapi.json and GET <tools>/docs, are
	// described by the document too. Set the two together, or the document
	// omits two routes the server serves — or describes two it does not.
	//
	// The reference's generator describes neither, under any option: it emits
	// the four feature groups and stops. That is the same half-deviation
	// OpenAPIInfo.Docs carries on the auth document, registered as
	// docs-routes-are-opt-in, and it is here for the same reason — the wire
	// conformance suite compares the document to the mount in both directions,
	// and a document that hid the endpoint serving it would have to be exempted
	// from that comparison.
	Docs bool
}

// GenerateToolsOpenAPISpec builds the tools router's OpenAPI 3.0 document:
// the reference's buildOpenApiSpec (openapi.ts:1366-1637).
func GenerateToolsOpenAPISpec(info ToolsOpenAPIInfo) map[string]any {
	if info.Title == "" {
		info.Title = "awesome-go-auth Tools API"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}
	if info.Description == "" {
		info.Description = "Optional event-driven tools: telemetry, SSE notifications, and webhooks."
	}
	base := info.BasePath
	if base == "" {
		base = DefaultToolsPath
	}

	paths := map[string]any{}
	// U23: base + "/track/{eventName}" and base + "/notify/{target}".
	// U25: base + "/telemetry" and base + "/webhook/{provider}", the first of
	// them under the reference's hasTelemetryQuery rather than the telemetry
	// flag alone (openapi.ts:1378).
	if info.Stream {
		paths[base+ToolsStreamPath] = toolsOpenAPIStreamPath()
	}
	if info.Docs {
		paths[base+DocsSpecPath] = toolsOpenAPIDocsSpecPath()
		paths[base+DocsUIPath] = toolsOpenAPIDocsUIPath()
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"tags":  toolsOpenAPITags(info),
		"paths": paths,
		"components": map[string]any{
			// One scheme, as there (openapi.ts:1590-1596): the tools router's
			// guard is whatever the host put in ToolsAccess, and the reference
			// documents the bearer token its own authMiddleware reads. A
			// deployment whose guard is cookie-based should say so on its own
			// copy of this document.
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
			// All four schemas, unconditionally, as the reference emits them
			// (openapi.ts:1597-1619) — it builds the components block whole and
			// lets the flags decide only which paths reference it. They are the
			// $refs the path items U23 through U25 add resolve against, so they
			// are written once, here, rather than one per PR.
			"schemas": toolsOpenAPISchemas(),
		},
	}
}

// ToolsOpenAPIHandler serves GenerateToolsOpenAPISpec(info) as
// application/json, which is what the reference's route does
// (tools.router.ts:333-346).
//
// The document is built once, here, and not per request: it is a pure function
// of info. The handler carries no guard, as the reference's route carries none;
// ToolsHandler is where that is decided and says why.
func ToolsOpenAPIHandler(info ToolsOpenAPIInfo) http.Handler {
	document := GenerateToolsOpenAPISpec(info)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, document)
	})
}

// toolsOpenAPITags is the reference's tags block (openapi.ts:1621-1625): one
// entry per feature group that is switched on, with Notifications covering
// notify and stream together.
//
// It follows the flags and not the path items, which is the reference's own
// rule — there the two cannot disagree, because a flag that is on is a group
// that is mounted. Here they can, until U25 lands: a tag is a vocabulary
// declaration and not a claim that a path exists, so the faithful version is
// the one that tracks the configuration.
func toolsOpenAPITags(info ToolsOpenAPIInfo) []map[string]any {
	tags := make([]map[string]any, 0, 3)
	if info.Telemetry {
		tags = append(tags, map[string]any{"name": "Telemetry", "description": "Event tracking and query"})
	}
	if info.Notify || info.Stream {
		tags = append(tags, map[string]any{"name": "Notifications", "description": "Real-time SSE notifications"})
	}
	if info.Webhook {
		tags = append(tags, map[string]any{"name": "Webhooks", "description": "Inbound webhook processing"})
	}
	return tags
}

// toolsOpenAPISchemas is the reference's components.schemas for this document
// (openapi.ts:1597-1619), transcribed.
//
// TelemetryEvent's members are the reference's ten and deliberately not this
// package's TelemetryEvent fields: what a client reads off GET <tools>/telemetry
// and off an SSE frame is the record as trackedRecord spells it on the wire
// (auth_tools.go), which is where `event`, `data` and the absence of `success`
// come from.
func toolsOpenAPISchemas() map[string]any {
	return map[string]any{
		"OkResponse": map[string]any{
			"type":       "object",
			"properties": map[string]any{"ok": map[string]any{"type": "boolean", "example": true}},
			"required":   []string{"ok"},
		},
		"TrackPayload": map[string]any{
			"type":        "object",
			"description": "Telemetry event payload",
			"properties": map[string]any{
				// `data` is documented with no type at all there — the value is
				// arbitrary JSON — so the description stands alone.
				"data":          map[string]any{"description": "Arbitrary event data"},
				"userId":        map[string]any{"type": "string"},
				"tenantId":      map[string]any{"type": "string"},
				"sessionId":     map[string]any{"type": "string"},
				"correlationId": map[string]any{"type": "string"},
			},
		},
		"NotifyPayload": map[string]any{
			"type":        "object",
			"description": "SSE notification payload",
			"required":    []string{"data"},
			"properties": map[string]any{
				"data":     map[string]any{"description": "Payload to deliver"},
				"type":     map[string]any{"type": "string", "description": "Event type label", "example": "notification"},
				"tenantId": map[string]any{"type": "string"},
				"userId":   map[string]any{"type": "string"},
				"metadata": map[string]any{"type": "object", "additionalProperties": true},
			},
		},
		"TelemetryEvent": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":            map[string]any{"type": "string", "format": "uuid"},
				"event":         map[string]any{"type": "string"},
				"timestamp":     map[string]any{"type": "string", "format": "date-time"},
				"data":          map[string]any{},
				"userId":        map[string]any{"type": "string"},
				"tenantId":      map[string]any{"type": "string"},
				"sessionId":     map[string]any{"type": "string"},
				"correlationId": map[string]any{"type": "string"},
				"ip":            map[string]any{"type": "string"},
				"userAgent":     map[string]any{"type": "string"},
			},
		},
	}
}

// toolsOpenAPIStreamPath describes GET <tools>/stream, transcribed from
// openapi.ts:1492-1522.
//
// The reference documents one parameter, `topics`, and says nothing at all
// about `token` — the parameter its own extractSseToken reads
// (tools.router.ts:186) and the one that decides whether the request is
// authenticated. That silence is reproduced in the parameter list, because a
// generated document that grew a parameter the reference's does not is a
// document two clients disagree about. It is not reproduced in the prose: the
// description below says what the query token is and what it costs, which
// changes no machine-readable field and is the one place a reader of the
// document would otherwise have no way to learn it. tools_stream.go argues the
// trade in full.
//
// The three responses are the reference's three, including the 401 it can only
// answer when a guard is configured — with ToolsPublic there is nothing to
// refuse a request, so the document is describing the guarded posture, which is
// also the posture its single `security: [bearer]` entry describes.
func toolsOpenAPIStreamPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary":     "Subscribe to real-time events via Server-Sent Events",
			"operationId": "sseStream",
			"tags":        []string{"Notifications"},
			"security":    []map[string]any{{"BearerAuth": []string{}}},
			"description": "Opens a `text/event-stream` that stays open until the client " +
				"disconnects. The first frame is `connected` and carries the connection id and " +
				"the topics the server authorised. " +
				"**The credential may also be given as `?token=<access token>`**, which is " +
				"copied into an `Authorization: Bearer` header before the guard runs, because a " +
				"browser `EventSource` cannot set headers. It overwrites any Authorization " +
				"header and takes precedence over the access-token cookie, so when both are " +
				"present the query token is the credential that is verified. A token in a URL " +
				"is recorded in access logs, `Referer` headers and browser history: prefer the " +
				"cookie or header where the client can set one. " +
				"There is no resume: `Last-Event-ID` is not read and nothing is retained, so a " +
				"reconnecting client resumes from now and whatever was raised while it was away " +
				"is gone.",
			"parameters": []map[string]any{
				{
					"name":        ToolsStreamTopicsParam,
					"in":          "query",
					"required":    false,
					"description": "Comma-separated list of topics to subscribe to. The server enforces authorization.",
					"schema":      map[string]any{"type": "string", "example": "global,user:123"},
				},
			},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "SSE stream (text/event-stream)",
					"content": map[string]any{
						"text/event-stream": map[string]any{
							"schema": map[string]any{"type": "string", "description": "Newline-delimited SSE frames"},
						},
					},
				},
				"401": map[string]any{"description": "Unauthorized"},
				"503": map[string]any{"description": "SSE not enabled on this server"},
			},
		},
	}
}

// toolsOpenAPIDocsSpecPath describes GET <tools>/openapi.json: this document,
// serving itself. It is the tools router's counterpart of openAPIDocsSpecPath,
// and it is here for the reason ToolsOpenAPIInfo.Docs gives.
func toolsOpenAPIDocsSpecPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "This OpenAPI document",
			"description": "Public: no credential of any kind. The tools router's guard — " +
				"`ToolsOptions.Access` — is never applied to this route, as the reference " +
				"spreads no `protect` onto it. Mounted only when `ToolsOptions.Docs.Enabled` " +
				"is set, and described here only when `ToolsOpenAPIInfo.Docs` is.",
			"operationId": "toolsOpenapiDocument",
			"tags":        []string{"Docs"},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The generated OpenAPI 3.0.3 document",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": map[string]any{"type": "object", "additionalProperties": true},
						},
					},
				},
			},
		},
	}
}

// toolsOpenAPIDocsUIPath describes GET <tools>/docs, the Swagger UI page that
// reads the document next door.
func toolsOpenAPIDocsUIPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "Swagger UI for this document",
			"description": "Public: no credential of any kind, as above. Serves the reference's " +
				"Swagger UI page, which loads `swagger-ui-dist@5` from the unpkg CDN and " +
				"fetches the document from `" + DocsSpecPath + "` below " +
				"`ToolsOptions.Docs.BasePath`. Mounted only when `ToolsOptions.Docs.Enabled` " +
				"is set.",
			"operationId": "toolsSwaggerUI",
			"tags":        []string{"Docs"},
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The Swagger UI page",
					"content": map[string]any{
						"text/html": map[string]any{
							"schema": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	}
}
