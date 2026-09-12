package auth

import "net/http"

// The admin console's OpenAPI document: the port of buildAdminOpenApiSpec
// (openapi.ts:672-1362), which is the reference's *third* generator and has
// nothing to do with either of the other two.
//
// Three generators because the reference has three, for three routers mounted at
// three unrelated paths. GenerateOpenAPISpec writes paths below
// HTTPConfig.Prefix(), GenerateToolsOpenAPISpec below
// HTTPConfig.ToolsDocsBasePath(), and this one below
// HTTPConfig.AdminDocsBasePath() — which defaults to the admin mount, beside the
// API prefix rather than under it. Merging any two would mean one document
// claiming to describe a surface the adapter serves somewhere else entirely.
//
// # What it does not describe, and why that is not a bug
//
// The reference's admin document is deliberately smaller than the reference's
// admin router, and reproducing it means reproducing the gaps:
//
//   - The console's own shell, its two static assets, and POST <admin>/login and
//     POST <admin>/logout are absent. The document describes the REST API, not
//     the page.
//   - GET /api/actions, the two template routes and — the one a reader of this
//     PR will look for — all four upload routes are absent. There is no flag for
//     any of them.
//   - hasUi describes two paths this router has never served: /api/ui-settings
//     and /api/ui/logo, where the real routes are PATCH /api/settings/ui and
//     POST /api/upload/logo. Nothing sets that flag — createAdminRouter passes
//     the other eight and not this one (admin.router.ts:1501-1510) — so those
//     two path items are unreachable there, and AdminOpenAPIInfo.UI is likewise
//     never set from a configuration here. It is kept because removing it would
//     be a silent edit to a transcription, and because a caller building the
//     info by hand should get the reference's document.
//
// So this document is held to the mount in one direction only — every path it
// describes is served — and the reverse direction is asserted for the routes the
// reference does document. The tools document, whose generator matches its
// router, is held in both (adapter/internal/wiretest/tools.go).
//
// The one thing added to it is the documentation pair itself, under
// AdminOpenAPIInfo.Docs, for the reason OpenAPIInfo.Docs gives on the auth
// document: an endpoint that serves a document the document hides is an endpoint
// no conformance check can hold. Here it does a second job, because those two
// routes are the only ones on this surface with no security requirement — so the
// document says so, in the one place a reader of the API will look.

// AdminOpenAPIInfo is what the admin document is generated from: the feature
// flags that select its optional path items, and the base path they are written
// under.
//
// It is the reference's AdminOpenApiOptions plus basePath
// (openapi.ts:645-664, :672-675). (*Auth).AdminOpenAPIInfo fills one in from a
// mounted configuration, which is how the adapters get it; a caller building one
// by hand is describing a mount it is responsible for matching.
type AdminOpenAPIInfo struct {
	// Title, Description and Version default to the reference's literals with
	// the package name changed (openapi.ts:1344-1348).
	Title       string
	Description string
	Version     string
	// BasePath is where the admin router is mounted as a reader can reach it,
	// and the prefix every documented path carries: the reference's basePath
	// parameter, whose default is '/admin' (openapi.ts:674). Empty means
	// DefaultAdminPath.
	BasePath string
	// The eight flags createAdminRouter passes (admin.router.ts:1501-1510), in
	// the reference's polarity: each includes the path items of its group. They
	// must match the stores the Auth was built with, or the document describes
	// routes the console answers 404 for — (*Auth).AdminOpenAPIInfo is the way
	// not to have to remember that.
	Sessions       bool
	Roles          bool
	Tenants        bool
	Metadata       bool
	Settings       bool
	LinkedAccounts bool
	APIKeys        bool
	Webhooks       bool
	// UI is the reference's hasUi, and it describes two paths the admin router
	// has never served. Nothing sets it. See this file's header.
	UI bool
	// Docs mirrors AdminOptions.Docs.Enabled: the two documentation routes the
	// console then mounts are described by the document too. Set the two
	// together, or the document omits two routes the server serves — or
	// describes two it does not.
	//
	// The reference's generator describes neither, under any option. That half
	// of the docs-routes-are-opt-in deviation is registered in compatibility.go
	// and now covers all three documents.
	Docs bool
}

// AdminOpenAPIInfo is the document this mount describes, read off the
// HTTPConfig the adapter was mounted with and the stores this Auth holds.
//
// The eight flags come from adminFeatures rather than from the stores directly,
// so the document and the console's own tabs cannot come to disagree: a
// deployment whose SPA hides the Tenants tab does not publish tenant endpoints,
// and a PR that turns a feature on turns it on in both places at once.
//
// The one place the mapping is not one word for one: hasSettings is the
// reference's `!!options.settingsStore` and this port's adminFeatures calls that
// flag Control, which is the SPA's name for the same tab.
func (a *Auth) AdminOpenAPIInfo(cfg HTTPConfig) AdminOpenAPIInfo {
	features := a.adminFeatures(cfg)
	return AdminOpenAPIInfo{
		BasePath:       cfg.AdminDocsBasePath(),
		Sessions:       features.Sessions,
		Roles:          features.Roles,
		Tenants:        features.Tenants,
		Metadata:       features.Metadata,
		Settings:       features.Control,
		LinkedAccounts: features.LinkedAccounts,
		APIKeys:        features.APIKeys,
		Webhooks:       features.Webhooks,
		Docs:           cfg.Admin.Docs.Enabled,
	}
}

// AdminOpenAPIHandler serves GenerateAdminOpenAPISpec(info) as
// application/json, which is what the reference's route does with the document
// its own generator returns (admin.router.ts:1499-1515).
//
// The document is built once, here, and not per request: it is a pure function
// of info. The handler carries no guard, as the reference's route carries none;
// AdminOptions.Docs is where that is decided and says what it costs.
func AdminOpenAPIHandler(info AdminOpenAPIInfo) http.Handler {
	document := GenerateAdminOpenAPISpec(info)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, document)
	})
}

// GenerateAdminOpenAPISpec builds the admin console's OpenAPI 3.0 document: the
// reference's buildAdminOpenApiSpec (openapi.ts:672-1362).
func GenerateAdminOpenAPISpec(info AdminOpenAPIInfo) map[string]any {
	if info.Title == "" {
		info.Title = "awesome-go-auth Admin API"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}
	if info.Description == "" {
		info.Description = "Admin REST API for user, session, role, tenant, settings, " +
			"API key, and webhook management."
	}
	base := info.BasePath
	if base == "" {
		base = DefaultAdminPath
	}

	// The shorthands. security is one entry on every operation the reference
	// declares one on, and the scheme is declared once in components below.
	str := map[string]any{"type": "string"}
	security := []map[string]any{{"AdminAuth": []string{}}}
	ref := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	jsonContent := func(schema map[string]any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	object := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props}
	}
	array := func(items map[string]any) map[string]any {
		return map[string]any{"type": "array", "items": items}
	}
	// ok wraps a 200 with a JSON body; text is a status with a description and
	// no content, which is how the reference writes every 401 and its one 404.
	ok := func(description string, schema map[string]any) map[string]any {
		return map[string]any{"description": description, "content": jsonContent(schema)}
	}
	text := func(description string) map[string]any {
		return map[string]any{"description": description}
	}
	success := func(description string) map[string]any {
		return ok(description, ref("SuccessResponse"))
	}
	unauthorized := text("Unauthorized")
	pathParam := func(name string) map[string]any {
		return map[string]any{"name": name, "in": "path", "required": true, "schema": str}
	}
	intQuery := func(name string, def int) map[string]any {
		return map[string]any{
			"name": name, "in": "query",
			"schema": map[string]any{"type": "integer", "default": def},
		}
	}
	body := func(schema map[string]any) map[string]any {
		return map[string]any{"required": true, "content": jsonContent(schema)}
	}

	paths := map[string]any{}

	// ── GET /api/ping (openapi.ts:691-700) ───────────────────────────────────
	//
	// The documented body is {ok} alone, where the route answers {ok, features}
	// (admin.router.ts:742). That is the reference's document and not a mistake
	// to correct: a client reading this one is told less than the route sends,
	// which is the direction that breaks nobody.
	paths[base+AdminPingPath] = map[string]any{
		"get": map[string]any{
			"summary":     "Health check",
			"operationId": "adminPing",
			"tags":        []string{"Admin"},
			"security":    security,
			"responses": map[string]any{
				"200": ok("pong", object(map[string]any{"ok": map[string]any{"type": "boolean"}})),
			},
		},
	}

	// ── Users (openapi.ts:703-745) ───────────────────────────────────────────
	paths[base+AdminUsersPath] = map[string]any{
		"get": map[string]any{
			"summary":     "List users (paginated)",
			"operationId": "adminListUsers",
			"tags":        []string{"Admin — Users"},
			"security":    security,
			"parameters": []map[string]any{
				intQuery("limit", 20),
				intQuery("offset", 0),
				{
					"name": "filter", "in": "query", "schema": str,
					"description": "Filter by email or ID (case-insensitive substring)",
				},
			},
			"responses": map[string]any{
				"200": ok("User list", object(map[string]any{
					"users": array(ref("AdminUser")),
					"total": map[string]any{"type": "integer"},
				})),
				"401": unauthorized,
			},
		},
	}
	paths[base+AdminUsersPath+"/{id}"] = map[string]any{
		"get": map[string]any{
			"summary":     "Get a specific user by ID",
			"operationId": "adminGetUser",
			"tags":        []string{"Admin — Users"},
			"security":    security,
			"parameters":  []map[string]any{pathParam("id")},
			"responses": map[string]any{
				"200": ok("User detail", object(map[string]any{"user": ref("AdminUser")})),
				"401": unauthorized,
				"404": text("User not found"),
			},
		},
		"delete": map[string]any{
			"summary":     "Delete a user",
			"operationId": "adminDeleteUser",
			"tags":        []string{"Admin — Users"},
			"security":    security,
			"parameters":  []map[string]any{pathParam("id")},
			"responses": map[string]any{
				"200": success("User deleted"),
				"401": unauthorized,
			},
		},
	}

	// ── 2FA policy (openapi.ts:748-761) ──────────────────────────────────────
	paths[base+AdminTwoFAPolicyPath] = map[string]any{
		"post": map[string]any{
			"summary":     "Enforce or revoke TOTP 2FA for a user",
			"operationId": "admin2faPolicy",
			"tags":        []string{"Admin — Users"},
			"security":    security,
			"requestBody": body(map[string]any{
				"type":     "object",
				"required": []string{"userId", "require2FA"},
				"properties": map[string]any{
					"userId":     str,
					"require2FA": map[string]any{"type": "boolean"},
				},
			}),
			"responses": map[string]any{
				"200": success("2FA policy applied"),
				"401": unauthorized,
			},
		},
	}

	// ── User metadata (openapi.ts:764-790) ───────────────────────────────────
	if info.Metadata {
		paths[base+AdminUsersPath+"/{id}/metadata"] = map[string]any{
			"get": map[string]any{
				"summary":     "Get user metadata",
				"operationId": "adminGetUserMetadata",
				"tags":        []string{"Admin — Users"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": ok("Metadata key/value pairs", object(map[string]any{
						"metadata": map[string]any{"type": "object", "additionalProperties": true},
					})),
					"401": unauthorized,
				},
			},
			"put": map[string]any{
				"summary":     "Update user metadata",
				"operationId": "adminUpdateUserMetadata",
				"tags":        []string{"Admin — Users"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"requestBody": body(map[string]any{"type": "object", "additionalProperties": true}),
				"responses": map[string]any{
					"200": success("Metadata updated"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── User linked accounts (openapi.ts:793-808) ────────────────────────────
	if info.LinkedAccounts {
		paths[base+AdminUsersPath+"/{id}/linked-accounts"] = map[string]any{
			"get": map[string]any{
				"summary":     "Get linked OAuth accounts for a user",
				"operationId": "adminGetUserLinkedAccounts",
				"tags":        []string{"Admin — Users"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": ok("Linked accounts", object(map[string]any{
						"linkedAccounts": array(map[string]any{"type": "object"}),
					})),
					"401": unauthorized,
				},
			},
		}
	}

	// ── User roles (openapi.ts:811-853) ──────────────────────────────────────
	if info.Roles {
		paths[base+AdminUsersPath+"/{id}/roles"] = map[string]any{
			"get": map[string]any{
				"summary":     "Get roles assigned to a user",
				"operationId": "adminGetUserRoles",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": ok("User roles", object(map[string]any{"roles": array(str)})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Assign a role to a user",
				"operationId": "adminAssignUserRole",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"requestBody": body(map[string]any{
					"type":       "object",
					"required":   []string{"role"},
					"properties": map[string]any{"role": str},
				}),
				"responses": map[string]any{
					"200": success("Role assigned"),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminUsersPath+"/{id}/roles/{role}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Remove a role from a user",
				"operationId": "adminRemoveUserRole",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id"), pathParam("role")},
				"responses": map[string]any{
					"200": success("Role removed"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── User tenants (openapi.ts:856-871) ────────────────────────────────────
	if info.Tenants {
		paths[base+AdminUsersPath+"/{id}/tenants"] = map[string]any{
			"get": map[string]any{
				"summary":     "Get tenants the user belongs to",
				"operationId": "adminGetUserTenants",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": ok("Tenant list", object(map[string]any{
						"tenants": array(ref("AdminTenant")),
					})),
					"401": unauthorized,
				},
			},
		}
	}

	// ── Settings (openapi.ts:874-898) ────────────────────────────────────────
	//
	// PATCH /api/settings/ui is not here. The reference documents this path with
	// a get and a put and nothing else, and the branding patch lives under
	// hasUi as a path that does not exist; see this file's header.
	if info.Settings {
		paths[base+AdminSettingsPath] = map[string]any{
			"get": map[string]any{
				"summary":     "Get global auth settings",
				"operationId": "adminGetSettings",
				"tags":        []string{"Admin — Settings"},
				"security":    security,
				"responses": map[string]any{
					"200": ok("Settings", object(map[string]any{"settings": ref("AdminSettings")})),
					"401": unauthorized,
				},
			},
			"put": map[string]any{
				"summary":     "Update global auth settings",
				"operationId": "adminUpdateSettings",
				"tags":        []string{"Admin — Settings"},
				"security":    security,
				"requestBody": body(ref("AdminSettings")),
				"responses": map[string]any{
					"200": success("Settings updated"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── Sessions (openapi.ts:901-932) ────────────────────────────────────────
	if info.Sessions {
		paths[base+AdminSessionsPath] = map[string]any{
			"get": map[string]any{
				"summary":     "List active sessions",
				"operationId": "adminListSessions",
				"tags":        []string{"Admin — Sessions"},
				"security":    security,
				"parameters": []map[string]any{
					{"name": "userId", "in": "query", "schema": str},
					intQuery("limit", 20),
					intQuery("offset", 0),
					{"name": "filter", "in": "query", "schema": str},
				},
				"responses": map[string]any{
					"200": ok("Session list", object(map[string]any{
						"sessions": array(ref("AdminSession")),
						"total":    map[string]any{"type": "integer"},
					})),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminSessionsPath+"/{handle}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Revoke a session by handle",
				"operationId": "adminRevokeSession",
				"tags":        []string{"Admin — Sessions"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("handle")},
				"responses": map[string]any{
					"200": success("Session revoked"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── Roles (openapi.ts:935-974) ───────────────────────────────────────────
	if info.Roles {
		paths[base+AdminRolesPath] = map[string]any{
			"get": map[string]any{
				"summary":     "List all roles",
				"operationId": "adminListRoles",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"responses": map[string]any{
					"200": ok("Role list", object(map[string]any{
						"roles": array(map[string]any{"type": "object"}),
					})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Create a role",
				"operationId": "adminCreateRole",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"requestBody": body(map[string]any{
					"type":     "object",
					"required": []string{"name"},
					"properties": map[string]any{
						"name":        str,
						"permissions": array(str),
					},
				}),
				"responses": map[string]any{
					"200": success("Role created"),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminRolesPath+"/{name}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Delete a role",
				"operationId": "adminDeleteRole",
				"tags":        []string{"Admin — Roles"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("name")},
				"responses": map[string]any{
					"200": success("Role deleted"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── Tenants (openapi.ts:977-1051) ────────────────────────────────────────
	if info.Tenants {
		paths[base+AdminTenantsPath] = map[string]any{
			"get": map[string]any{
				"summary":     "List all tenants",
				"operationId": "adminListTenants",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"responses": map[string]any{
					"200": ok("Tenant list", object(map[string]any{
						"tenants": array(ref("AdminTenant")),
					})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Create a tenant",
				"operationId": "adminCreateTenant",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"requestBody": body(map[string]any{
					"type":     "object",
					"required": []string{"name"},
					"properties": map[string]any{
						"name":     str,
						"isActive": map[string]any{"type": "boolean"},
					},
				}),
				"responses": map[string]any{
					"200": ok("Tenant created", object(map[string]any{"tenant": ref("AdminTenant")})),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminTenantsPath+"/{id}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Delete a tenant",
				"operationId": "adminDeleteTenant",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": success("Tenant deleted"),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminTenantsPath+"/{id}/users"] = map[string]any{
			"get": map[string]any{
				"summary":     "List users in a tenant",
				"operationId": "adminGetTenantUsers",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": ok("User IDs", object(map[string]any{"userIds": array(str)})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Add a user to a tenant",
				"operationId": "adminAddTenantUser",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"requestBody": body(map[string]any{
					"type":       "object",
					"required":   []string{"userId"},
					"properties": map[string]any{"userId": str},
				}),
				"responses": map[string]any{
					"200": success("User added"),
					"401": unauthorized,
				},
			},
		}
		paths[base+AdminTenantsPath+"/{id}/users/{userId}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Remove a user from a tenant",
				"operationId": "adminRemoveTenantUser",
				"tags":        []string{"Admin — Tenants"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id"), pathParam("userId")},
				"responses": map[string]any{
					"200": success("User removed"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── API keys (openapi.ts:1054-1113) ──────────────────────────────────────
	//
	// The routes are U14b's; the flag is off until adminFeatures reports the
	// store, so this block describes nothing until they land.
	if info.APIKeys {
		paths[base+"/api/api-keys"] = map[string]any{
			"get": map[string]any{
				"summary":     "List API keys (paginated)",
				"operationId": "adminListApiKeys",
				"tags":        []string{"Admin — API Keys"},
				"security":    security,
				"parameters": []map[string]any{
					intQuery("limit", 20),
					intQuery("offset", 0),
					{
						"name": "filter", "in": "query", "schema": str,
						"description": "Filter by name, service ID, or prefix",
					},
				},
				"responses": map[string]any{
					"200": ok("API key list", object(map[string]any{
						"keys":  array(ref("AdminApiKey")),
						"total": map[string]any{"type": "integer"},
					})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Create a new API key (returns rawKey once)",
				"operationId": "adminCreateApiKey",
				"tags":        []string{"Admin — API Keys"},
				"security":    security,
				"requestBody": body(map[string]any{
					"type":     "object",
					"required": []string{"name"},
					"properties": map[string]any{
						"name":       str,
						"serviceId":  str,
						"scopes":     array(str),
						"allowedIps": array(str),
						"expiresAt":  map[string]any{"type": "string", "format": "date-time"},
					},
				}),
				"responses": map[string]any{
					"200": ok("API key created. rawKey is shown once only.", object(map[string]any{
						"rawKey": str,
						"record": ref("AdminApiKey"),
					})),
					"400": text("Validation error"),
					"401": unauthorized,
				},
			},
		}
		paths[base+"/api/api-keys/{id}/revoke"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Revoke an API key (sets isActive: false)",
				"operationId": "adminRevokeApiKey",
				"tags":        []string{"Admin — API Keys"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": success("API key revoked"),
					"401": unauthorized,
				},
			},
		}
		paths[base+"/api/api-keys/{id}"] = map[string]any{
			"delete": map[string]any{
				"summary":     "Hard-delete an API key record",
				"operationId": "adminDeleteApiKey",
				"tags":        []string{"Admin — API Keys"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": success("API key deleted"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── Webhooks (openapi.ts:1116-1174) ──────────────────────────────────────
	if info.Webhooks {
		paths[base+"/api/webhooks"] = map[string]any{
			"get": map[string]any{
				"summary":     "List registered webhooks (paginated)",
				"operationId": "adminListWebhooks",
				"tags":        []string{"Admin — Webhooks"},
				"security":    security,
				"parameters":  []map[string]any{intQuery("limit", 20), intQuery("offset", 0)},
				"responses": map[string]any{
					"200": ok("Webhook list", object(map[string]any{
						"webhooks": array(ref("AdminWebhook")),
						"total":    map[string]any{"type": "integer"},
					})),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Register a new outgoing webhook",
				"operationId": "adminCreateWebhook",
				"tags":        []string{"Admin — Webhooks"},
				"security":    security,
				"requestBody": body(map[string]any{
					"type":     "object",
					"required": []string{"url"},
					"properties": map[string]any{
						"url":        map[string]any{"type": "string", "format": "uri"},
						"events":     array(str),
						"secret":     str,
						"tenantId":   str,
						"isActive":   map[string]any{"type": "boolean", "default": true},
						"maxRetries": map[string]any{"type": "integer", "default": 3},
					},
				}),
				"responses": map[string]any{
					"200": ok("Webhook created", object(map[string]any{"webhook": ref("AdminWebhook")})),
					"400": text("Validation error"),
					"401": unauthorized,
				},
			},
		}
		paths[base+"/api/webhooks/{id}"] = map[string]any{
			"patch": map[string]any{
				"summary":     "Partially update a webhook (e.g. toggle isActive)",
				"operationId": "adminUpdateWebhook",
				"tags":        []string{"Admin — Webhooks"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"requestBody": body(object(map[string]any{
					"isActive": map[string]any{"type": "boolean"},
					"url":      str,
					"events":   array(str),
				})),
				"responses": map[string]any{
					"200": success("Webhook updated"),
					"401": unauthorized,
				},
			},
			"delete": map[string]any{
				"summary":     "Delete a webhook registration",
				"operationId": "adminDeleteWebhook",
				"tags":        []string{"Admin — Webhooks"},
				"security":    security,
				"parameters":  []map[string]any{pathParam("id")},
				"responses": map[string]any{
					"200": success("Webhook deleted"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── UI customisation (openapi.ts:1177-1233) ──────────────────────────────
	//
	// Two paths this router has never served, under a flag nothing sets. See
	// this file's header before reaching for either.
	if info.UI {
		paths[base+"/api/ui-settings"] = map[string]any{
			"get": map[string]any{
				"summary":     "Get UI customization settings",
				"operationId": "adminGetUiSettings",
				"tags":        []string{"Admin — UI"},
				"security":    security,
				"responses": map[string]any{
					"200": ok("UI settings", ref("UiSettings")),
					"401": unauthorized,
				},
			},
			"post": map[string]any{
				"summary":     "Update UI customization settings",
				"operationId": "adminUpdateUiSettings",
				"tags":        []string{"Admin — UI"},
				"security":    security,
				"requestBody": body(ref("UiSettings")),
				"responses": map[string]any{
					"200": success("Settings updated"),
					"401": unauthorized,
				},
			},
		}
		paths[base+"/api/ui/logo"] = map[string]any{
			"post": map[string]any{
				"summary":     "Upload a custom logo image",
				"operationId": "adminUploadLogo",
				"tags":        []string{"Admin — UI"},
				"security":    security,
				"requestBody": map[string]any{
					"content": map[string]any{
						"multipart/form-data": map[string]any{
							"schema": object(map[string]any{
								"logo": map[string]any{"type": "string", "format": "binary"},
							}),
						},
					},
				},
				"responses": map[string]any{
					"200": ok("Logo uploaded", object(map[string]any{
						"success": map[string]any{"type": "boolean"},
						"logoUrl": str,
					})),
					"401": unauthorized,
				},
			},
			"delete": map[string]any{
				"summary":     "Remove custom logo",
				"operationId": "adminDeleteLogo",
				"tags":        []string{"Admin — UI"},
				"security":    security,
				"responses": map[string]any{
					"200": success("Logo removed"),
					"401": unauthorized,
				},
			},
		}
	}

	// ── The documentation pair ───────────────────────────────────────────────
	//
	// This port's addition, for the reason AdminOpenAPIInfo.Docs gives. Neither
	// operation carries `security`, and that absence is the point: it is the
	// only place on this surface where the document states that a route needs no
	// credential, and it is true.
	if info.Docs {
		paths[base+AdminOpenAPIPath] = adminOpenAPIDocsSpecPath()
		paths[base+AdminDocsPath] = adminOpenAPIDocsUIPath()
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"tags":  adminOpenAPITags(info),
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				// One scheme, named for the legacy bearer secret it was written
				// for (openapi.ts:1353-1357). It is still the truth for a
				// deployment under AdminOptions.Secret; under an access policy
				// the same header carries a session token instead, and the
				// cookie the console actually uses is documented nowhere there.
				// Transcribed rather than corrected: a document that described
				// two schemes would not be the reference's.
				"AdminAuth": map[string]any{
					"type":        "http",
					"scheme":      "bearer",
					"description": "Admin secret token — pass as `Authorization: Bearer <adminSecret>`",
				},
			},
			// All eight schemas, unconditionally, as the reference emits them
			// (openapi.ts:1236-1332) — it builds the components block whole and
			// lets the flags decide only which paths reference it.
			"schemas": adminOpenAPISchemas(),
		},
	}
}

// adminOpenAPITags is the reference's tags block (openapi.ts:1334-1344): two
// unconditional entries and seven that follow the flags.
//
// Order matters here and nowhere else in the document — a tags array is a list —
// so it is the reference's order and not the flag struct's.
func adminOpenAPITags(info AdminOpenAPIInfo) []map[string]any {
	tags := []map[string]any{
		{"name": "Admin", "description": "Admin health check"},
		{"name": "Admin — Users", "description": "User management"},
	}
	add := func(on bool, name, description string) {
		if on {
			tags = append(tags, map[string]any{"name": name, "description": description})
		}
	}
	add(info.Sessions, "Admin — Sessions", "Session management")
	add(info.Roles, "Admin — Roles", "Role and permission management")
	add(info.Tenants, "Admin — Tenants", "Tenant management")
	add(info.Settings, "Admin — Settings", "Global auth settings")
	add(info.APIKeys, "Admin — API Keys", "API key / service token management")
	add(info.Webhooks, "Admin — Webhooks", "Outgoing webhook management")
	add(info.UI, "Admin — UI", "UI customization and preview")
	// The reference declares no tag for the documentation pair, because it
	// describes no such routes. This port does, so the pair gets one.
	add(info.Docs, "Docs", "This document and the page that reads it")
	return tags
}

// adminOpenAPISchemas is the reference's components.schemas for this document
// (openapi.ts:1236-1332), transcribed.
//
// AdminUser is worth a warning because it is the one schema a client will code
// against: it is not the projection GET <admin>/api/users answers with. It
// declares loginProvider and lastLogin, which that route sends on neither store,
// and omits require2FA and phoneNumber, which it does send (admin.router.ts:764-773,
// ported as adminUserRow). That mismatch is the reference's; correcting it here
// would mean this document described a body the reference's document does not.
func adminOpenAPISchemas() map[string]any {
	str := map[string]any{"type": "string"}
	boolean := map[string]any{"type": "boolean"}
	dateTime := map[string]any{"type": "string", "format": "date-time"}
	nullableDateTime := map[string]any{"type": "string", "format": "date-time", "nullable": true}
	strArray := map[string]any{"type": "array", "items": str}

	return map[string]any{
		"SuccessResponse": map[string]any{
			"type":       "object",
			"properties": map[string]any{"success": map[string]any{"type": "boolean", "example": true}},
			"required":   []string{"success"},
		},
		"AdminUser": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":              str,
				"email":           map[string]any{"type": "string", "format": "email"},
				"role":            str,
				"isEmailVerified": boolean,
				"isTotpEnabled":   boolean,
				"loginProvider":   str,
				"lastLogin":       dateTime,
				"createdAt":       dateTime,
			},
		},
		"AdminSession": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"handle":     str,
				"userId":     str,
				"deviceInfo": str,
				"ip":         str,
				"createdAt":  dateTime,
				"expiresAt":  dateTime,
			},
		},
		"AdminTenant": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":       str,
				"name":     str,
				"isActive": boolean,
			},
		},
		"AdminSettings": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"require2FA": boolean,
				"emailVerificationMode": map[string]any{
					"type": "string",
					"enum": []string{"none", "lazy", "strict"},
				},
				"emailVerificationGracePeriodDays": map[string]any{"type": "integer"},
			},
		},
		"AdminApiKey": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":   str,
				"name": str,
				"keyPrefix": map[string]any{
					"type":        "string",
					"description": "First ~11 chars of the key (safe to display)",
				},
				"serviceId":  map[string]any{"type": "string", "nullable": true},
				"scopes":     strArray,
				"allowedIps": map[string]any{"type": "array", "items": str, "nullable": true},
				"isActive":   boolean,
				"expiresAt":  nullableDateTime,
				"createdAt":  dateTime,
				"lastUsedAt": nullableDateTime,
			},
		},
		"AdminWebhook": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":           map[string]any{"type": "string"},
				"url":          map[string]any{"type": "string", "format": "uri"},
				"events":       strArray,
				"isActive":     boolean,
				"tenantId":     map[string]any{"type": "string", "nullable": true},
				"maxRetries":   map[string]any{"type": "integer"},
				"retryDelayMs": map[string]any{"type": "integer"},
				"secret": map[string]any{
					"type": "string", "description": "Masked as *** if set", "nullable": true,
				},
			},
		},
		"UiSettings": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"primaryColor":   map[string]any{"type": "string", "example": "#1a1a2e"},
				"secondaryColor": map[string]any{"type": "string", "example": "#ffffff"},
				"logoUrl": map[string]any{
					"type": "string", "example": "/auth/ui/assets/logo/logo.png", "nullable": true,
				},
				"siteName": map[string]any{"type": "string", "example": "My Auth Service"},
			},
		},
	}
}

// adminOpenAPIDocsSpecPath describes GET <admin>/api/openapi.json: this
// document, serving itself.
func adminOpenAPIDocsSpecPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "This OpenAPI document",
			"description": "Public: no credential of any kind. The admin router's guard is " +
				"spread onto every other route under `/api/*` and onto neither of these two, " +
				"as the reference registers them without it. Mounted only when " +
				"`AdminOptions.Docs.Enabled` is set, and described here only when " +
				"`AdminOpenAPIInfo.Docs` is.",
			"operationId": "adminOpenapiDocument",
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

// adminOpenAPIDocsUIPath describes GET <admin>/api/docs, the Swagger UI page
// that reads the document next door.
func adminOpenAPIDocsUIPath() map[string]any {
	return map[string]any{
		"get": map[string]any{
			"summary": "Swagger UI for this document",
			"description": "Public: no credential of any kind, as above. Serves the reference's " +
				"Swagger UI page, which loads `swagger-ui-dist@5` from the unpkg CDN and " +
				"fetches the document from `" + AdminOpenAPIPath + "` below " +
				"`AdminOptions.Docs.BasePath`. Its title says \"Tools API\", which is the " +
				"reference's one page builder serving all three of its routers. Mounted only " +
				"when `AdminOptions.Docs.Enabled` is set.",
			"operationId": "adminSwaggerUI",
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
