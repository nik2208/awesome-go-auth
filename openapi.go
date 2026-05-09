package auth

// OpenAPIInfo holds metadata for the generated OpenAPI spec.
type OpenAPIInfo struct {
	Title       string
	Description string
	Version     string
	ServerURL   string
}

// GenerateOpenAPISpec returns an OpenAPI 3.0 spec for awesome-go-auth endpoints.
func GenerateOpenAPISpec(info OpenAPIInfo) map[string]any {
	if info.Title == "" {
		info.Title = "awesome-go-auth"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}
	if info.Description == "" {
		info.Description = "Authentication & Authorization API"
	}

	servers := []map[string]any{}
	if info.ServerURL != "" {
		servers = append(servers, map[string]any{"url": info.ServerURL})
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"servers": servers,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
				"ApiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-Api-Key",
				},
			},
			"schemas": openAPISchemas(),
		},
		"paths": openAPIPaths(),
	}
}

func openAPISchemas() map[string]any {
	return map[string]any{
		"RegisterInput": map[string]any{
			"type": "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":     map[string]any{"type": "string", "format": "email"},
				"password":  map[string]any{"type": "string", "minLength": 8},
				"tenant_id": map[string]any{"type": "string"},
			},
		},
		"LoginInput": map[string]any{
			"type": "object",
			"required": []string{"email", "password"},
			"properties": map[string]any{
				"email":     map[string]any{"type": "string", "format": "email"},
				"password":  map[string]any{"type": "string"},
				"tenant_id": map[string]any{"type": "string"},
			},
		},
		"AuthTokens": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"access_token":  map[string]any{"type": "string"},
				"refresh_token": map[string]any{"type": "string"},
				"expires_in":    map[string]any{"type": "integer", "description": "TTL in nanoseconds"},
			},
		},
		"User": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"id":                map[string]any{"type": "string"},
				"email":             map[string]any{"type": "string"},
				"tenant_id":         map[string]any{"type": "string"},
				"first_name":        map[string]any{"type": "string"},
				"last_name":         map[string]any{"type": "string"},
				"is_email_verified": map[string]any{"type": "boolean"},
				"roles":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"created_at":        map[string]any{"type": "string", "format": "date-time"},
			},
		},
		"Error": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"error": map[string]any{"type": "string"},
			},
		},
	}
}

func openAPIPaths() map[string]any {
	ref := func(name string) map[string]any {
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	jsonContent := func(schema map[string]any) map[string]any {
		return map[string]any{
			"application/json": map[string]any{"schema": schema},
		}
	}
	okResponse := func(schema map[string]any) map[string]any {
		return map[string]any{
			"200": map[string]any{
				"description": "Success",
				"content":     jsonContent(schema),
			},
			"400": map[string]any{"description": "Bad request", "content": jsonContent(ref("Error"))},
			"401": map[string]any{"description": "Unauthorized", "content": jsonContent(ref("Error"))},
		}
	}

	authResponse := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"user":   ref("User"),
			"tokens": ref("AuthTokens"),
		},
	}

	return map[string]any{
		"/auth/register": map[string]any{
			"post": map[string]any{
				"summary":     "Register a new user",
				"operationId": "register",
				"tags":        []string{"Auth"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(ref("RegisterInput")),
				},
				"responses": okResponse(authResponse),
			},
		},
		"/auth/login": map[string]any{
			"post": map[string]any{
				"summary":     "Login with email and password",
				"operationId": "login",
				"tags":        []string{"Auth"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(ref("LoginInput")),
				},
				"responses": okResponse(authResponse),
			},
		},
		"/auth/refresh": map[string]any{
			"post": map[string]any{
				"summary":     "Refresh access token",
				"operationId": "refresh",
				"tags":        []string{"Auth"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"refresh_token": map[string]any{"type": "string"}}}),
				},
				"responses": okResponse(ref("AuthTokens")),
			},
		},
		"/auth/logout": map[string]any{
			"post": map[string]any{
				"summary":     "Logout and revoke session",
				"operationId": "logout",
				"tags":        []string{"Auth"},
				"security":    []map[string]any{{"BearerAuth": []string{}}},
				"responses":   map[string]any{"204": map[string]any{"description": "Logged out"}},
			},
		},
		"/auth/me": map[string]any{
			"get": map[string]any{
				"summary":     "Get current user profile",
				"operationId": "me",
				"tags":        []string{"Auth"},
				"security":    []map[string]any{{"BearerAuth": []string{}}},
				"responses":   okResponse(ref("User")),
			},
		},
		"/auth/forgot-password": map[string]any{
			"post": map[string]any{
				"summary":     "Request password reset",
				"operationId": "forgotPassword",
				"tags":        []string{"Password"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"email": map[string]any{"type": "string"}, "tenant_id": map[string]any{"type": "string"}}}),
				},
				"responses": map[string]any{"204": map[string]any{"description": "Reset email sent (if user exists)"}},
			},
		},
		"/auth/reset-password": map[string]any{
			"post": map[string]any{
				"summary":     "Reset password with token",
				"operationId": "resetPassword",
				"tags":        []string{"Password"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"token": map[string]any{"type": "string"}, "new_password": map[string]any{"type": "string"}}}),
				},
				"responses": map[string]any{"204": map[string]any{"description": "Password reset successfully"}},
			},
		},
		"/auth/magic-link/send": map[string]any{
			"post": map[string]any{
				"summary":     "Send magic link email",
				"operationId": "sendMagicLink",
				"tags":        []string{"MagicLink"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"email": map[string]any{"type": "string"}, "tenant_id": map[string]any{"type": "string"}}}),
				},
				"responses": map[string]any{"204": map[string]any{"description": "Magic link sent"}},
			},
		},
		"/auth/magic-link/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Verify magic link token",
				"operationId": "verifyMagicLink",
				"tags":        []string{"MagicLink"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"token": map[string]any{"type": "string"}}}),
				},
				"responses": okResponse(authResponse),
			},
		},
		"/auth/totp/setup": map[string]any{
			"post": map[string]any{
				"summary":     "Initialize TOTP setup",
				"operationId": "setupTOTP",
				"tags":        []string{"TOTP"},
				"security":    []map[string]any{{"BearerAuth": []string{}}},
				"responses":   okResponse(map[string]any{"type": "object", "properties": map[string]any{"secret": map[string]any{"type": "string"}}}),
			},
		},
		"/auth/totp/verify": map[string]any{
			"post": map[string]any{
				"summary":     "Verify TOTP code",
				"operationId": "verifyTOTP",
				"tags":        []string{"TOTP"},
				"requestBody": map[string]any{
					"required": true,
					"content":  jsonContent(map[string]any{"type": "object", "properties": map[string]any{"code": map[string]any{"type": "string"}, "user_id": map[string]any{"type": "string"}, "tenant_id": map[string]any{"type": "string"}}}),
				},
				"responses": okResponse(authResponse),
			},
		},
		"/auth/sessions": map[string]any{
			"get": map[string]any{
				"summary":     "List active sessions",
				"operationId": "listSessions",
				"tags":        []string{"Sessions"},
				"security":    []map[string]any{{"BearerAuth": []string{}}},
				"responses":   okResponse(map[string]any{"type": "array", "items": map[string]any{"type": "object"}}),
			},
		},
	}
}
