package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The two documentation routes of the reference's auth router: the generated
// OpenAPI document at GET <prefix>/openapi.json and the Swagger UI page that
// reads it at GET <prefix>/docs (auth.router.ts:1651-1677).
//
// Neither carries a guard of its own there — no auth middleware, no session —
// so a reader fetches both with no credential of any kind, and that is how they
// answer here. They are not, however, outside the router-level CSRF auto-init:
// that is a router.use at auth.router.ts:529-538, eleven hundred lines earlier,
// and Express runs every earlier use-layer for a route registered after it. So
// with csrf enabled the reference answers a bare GET of either with a fresh
// csrf-token cookie, and the adapters mount both behind CSRFMiddleware to do
// the same. Nothing is rejected by it: a GET or a HEAD never reaches the
// double-submit check (csrfEnforced).
//
// The document they publish is the one GenerateOpenAPISpec builds in
// openapi.go; the page is the reference's HTML, reproduced byte for byte
// including the CDN it loads from (see swaggerUIHTML).
//
// What the adapters do with these is in adapter/nethttp/docs.go: the handlers
// are written once there, as for every other group, and chi, gin and echo
// re-register them.

const (
	// DocsSpecPath and DocsUIPath are where the two routes sit below the mount
	// prefix (auth.router.ts:1658, :1674). They are constants and not
	// configuration: the reference has no option for either, and the family's
	// clients that read a spec read it from the first.
	DocsSpecPath = "/openapi.json"
	DocsUIPath   = "/docs"
)

// DocsOptions is HTTPConfig.Docs: whether the adapters mount the two
// documentation routes, and under which base path the document describes
// itself.
type DocsOptions struct {
	// Enabled mounts GET <prefix>/openapi.json and GET <prefix>/docs, neither
	// of them guarded, as the reference registers them
	// (auth.router.ts:1656-1677). Unset — the default — neither route is
	// registered at all, and both answer 404.
	//
	// Enabling the second of the two puts a remote script on the auth origin:
	// the page is the reference's, and it loads swagger-ui-dist@5 from the
	// unpkg CDN with no subresource integrity (see swaggerUIHTML). Whatever
	// unpkg serves then runs same-origin with the auth cookies, where the CSRF
	// cookie is readable from JavaScript by design. Keep the routes off in
	// production, or serve them behind a Content-Security-Policy that pins that
	// CDN — the deviation register's docs-routes-are-opt-in note says the same.
	//
	// It is a plain bool. The reference's option is boolean or the string
	// "auto", "auto" is the default, and it means enabled unless the process
	// environment says NODE_ENV=production (auth.router.ts:123-131, :1652-1654).
	// This port resolves nothing against an environment: a library whose routes
	// appear and disappear with a variable it never sees configured is a
	// library nobody can reason about from its own configuration, and Go has no
	// NODE_ENV to read anyway. Deciding what the ambient environment means is
	// the host's call, and it is one line where the HTTPConfig is built:
	//
	//	cfg.Docs.Enabled = os.Getenv("APP_ENV") != "production"
	//
	// The consequence — off by default where the reference is on by default
	// outside production — is the docs-routes-are-opt-in deviation.
	Enabled bool
	// BasePath is the prefix the served document writes its paths under, and
	// the base of the spec URL the Swagger UI page fetches. Empty means the
	// mount prefix, HTTPConfig.Prefix(), and is normalised the way that is, so
	// a base path and a mount built from the same string agree.
	//
	// It is the reference's swaggerBasePath (auth.router.ts:133-139, read at
	// :1657), which defaults to the configured apiPrefix there too. The
	// reference needs it more than this port does: an Express router cannot
	// know where app.use mounted it, while an adapter here is mounted at the
	// prefix it was configured with. Set it when the routes are reachable from
	// outside under some other path — behind a reverse proxy that adds or
	// strips a segment — so that the document and the page point at the URL a
	// reader can actually fetch.
	//
	// It moves the description, never the mount: the two routes are always
	// served at HTTPConfig.Prefix(), because that is where the adapter is.
	BasePath string
}

// DocsBasePath is DocsOptions.BasePath resolved: the configured value, or the
// mount prefix when none is configured.
func (c HTTPConfig) DocsBasePath() string {
	if strings.TrimSpace(c.Docs.BasePath) == "" {
		return c.Prefix()
	}
	return HTTPConfig{APIPrefix: c.Docs.BasePath}.Prefix()
}

// OpenAPIHandler serves GenerateOpenAPISpec(info) as application/json, which is
// what the reference's route does with the document its own generator returns
// (auth.router.ts:1658-1671).
//
// The document is built once, here, and not per request: it is a pure function
// of info, and nothing the handler sees can change it. The bytes are stable
// too — encoding/json writes map keys in sorted order — so a caching client
// sees one body per configuration.
//
// The handler carries no middleware of its own, as the reference's route
// carries no guard: no auth, no session, nothing to present a credential to.
// The adapters put CSRFMiddleware in front of it, which on a GET only
// distributes the cookie the reference's router-level auto-init distributes
// (auth.router.ts:529-538) and rejects nothing. A host mounting it by hand
// should leave it as public as that, or keep it off: it describes routes, not
// data, but it is still a description of the surface an attacker would
// otherwise have to guess.
func OpenAPIHandler(info OpenAPIInfo) http.Handler {
	document := GenerateOpenAPISpec(info)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, http.StatusOK, document)
	})
}

// SwaggerUIHandler serves the reference's Swagger UI page for the document at
// specURL, as text/html (auth.router.ts:1674-1677). An empty specURL means the
// reference's own default, "./openapi.json" (openapi.ts:1646).
//
// The page is rendered once, here: it is a pure function of specURL.
func SwaggerUIHandler(specURL string) http.Handler {
	page := []byte(swaggerUIHTML(specURL))
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(page)
	})
}

// swaggerUIHTML is the reference's buildSwaggerUiHtml (openapi.ts:1646-1669),
// reproduced verbatim: the same markup, the same swagger-ui-dist@5 bundles from
// unpkg, the same SwaggerUIBundle options, and the same title — which says
// "Tools API" on the auth router too, because the reference's one builder
// serves its auth, admin and tools routers alike (auth.router.ts:1676,
// admin.router.ts:1519, tools.router.ts:350). None of that is ours to improve:
// a page that differs from the reference's is a page whose behaviour a
// deployment has to re-verify.
//
// The one thing that is not a transcription is how specURL is quoted. The
// reference interpolates JSON.stringify(specUrl); encoding/json produces the
// same bytes for it, except that it escapes <, > and & as <, > and
// &. A URL carrying any of them decodes to exactly the same JavaScript
// string, so the page behaves identically — and a specURL containing the
// characters that would end the script element cannot end it here.
func swaggerUIHTML(specURL string) string {
	if specURL == "" {
		specURL = "./openapi.json"
	}
	quoted, err := json.Marshal(specURL)
	if err != nil {
		// Unreachable: a string always marshals. The fallback is the
		// reference's default rather than an empty url, so a page built from an
		// impossible error is still a page that loads something.
		quoted = []byte(`"./openapi.json"`)
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>awesome-node-auth Tools API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: ` + string(quoted) + `,
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    });
  </script>
</body>
</html>`
}
