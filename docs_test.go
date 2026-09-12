package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The documentation routes, on their own: the handlers, the page, and the two
// path items the generator adds for them. The wiretest harness holds all three
// to what the four adapters actually mount; these are the pieces by themselves.

// wantSwaggerUIPage is the reference's page (openapi.ts:1646-1669) written out
// a second time, for the spec URL wantSwaggerUISpecURL. Spelling it again is
// the point: swaggerUIHTML is a transcription, and a transcription with no
// second copy to compare against is just a string somebody can edit.
const wantSwaggerUISpecURL = "/api/auth/openapi.json"

const wantSwaggerUIPage = `<!DOCTYPE html>
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
      url: "/api/auth/openapi.json",
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    });
  </script>
</body>
</html>`

// TestSwaggerUIHTMLIsTheReferencePage: the page is the reference's, byte for
// byte, including the unpkg CDN it loads swagger-ui-dist@5 from. The CDN is the
// reference's choice and not ours to improve: a deployment that has verified
// the reference's page against its own content policy must not find a different
// one here.
func TestSwaggerUIHTMLIsTheReferencePage(t *testing.T) {
	if got := swaggerUIHTML(wantSwaggerUISpecURL); got != wantSwaggerUIPage {
		t.Errorf("page =\n%s\n\nwant\n%s", got, wantSwaggerUIPage)
	}
}

// TestSwaggerUIHTMLSpecURL: the URL is interpolated the way the reference
// interpolates it, JSON.stringify(specUrl) (openapi.ts:1660), and an empty one
// falls back to the reference's default parameter value (:1646).
func TestSwaggerUIHTMLSpecURL(t *testing.T) {
	for _, tc := range []struct{ name, specURL, want string }{
		{"absolute", "https://api.example.com/auth/openapi.json", `url: "https://api.example.com/auth/openapi.json"`},
		{"relative", "/auth/openapi.json", `url: "/auth/openapi.json"`},
		{"empty falls back to the reference default", "", `url: "./openapi.json"`},
		// encoding/json escapes the three characters that could otherwise end
		// the script element. The decoded string is the same either way, so the
		// page fetches the same URL; see swaggerUIHTML.
		{"script-ending characters are escaped", "/a</script>", `url: "/a\u003c/script\u003e"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := swaggerUIHTML(tc.specURL); !strings.Contains(got, tc.want) {
				t.Errorf("page does not carry %q:\n%s", tc.want, got)
			}
		})
	}
}

// TestSwaggerUIHandler: 200, the reference's page, and the content type the
// reference's route sets (auth.router.ts:1675).
func TestSwaggerUIHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	SwaggerUIHandler(wantSwaggerUISpecURL).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/docs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html; charset=utf-8")
	}
	if got := rec.Body.String(); got != wantSwaggerUIPage {
		t.Errorf("body =\n%s\n\nwant\n%s", got, wantSwaggerUIPage)
	}
}

// TestOpenAPIHandler: 200 and the generated document as application/json, which
// is what the reference's route writes (auth.router.ts:1658-1671). The document
// is the one GenerateOpenAPISpec returns for the same info, not a rebuild of
// it — the handler is the route, not a second generator.
func TestOpenAPIHandler(t *testing.T) {
	info := OpenAPIInfo{APIPrefix: "/api/auth", Docs: true}

	rec := httptest.NewRecorder()
	OpenAPIHandler(info).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/openapi.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	paths, ok := got["paths"].(map[string]any)
	if !ok {
		t.Fatalf("paths = %#v, want an object", got["paths"])
	}
	for _, path := range []string{"/api/auth/login", "/api/auth" + DocsSpecPath, "/api/auth" + DocsUIPath} {
		if _, ok := paths[path]; !ok {
			t.Errorf("the served document does not describe %q", path)
		}
	}

	want, err := json.Marshal(GenerateOpenAPISpec(info))
	if err != nil {
		t.Fatalf("marshal the generated spec: %v", err)
	}
	if strings.TrimSpace(rec.Body.String()) != string(want) {
		t.Errorf("the served document is not GenerateOpenAPISpec(info):\n%s\n\nwant\n%s", rec.Body.String(), want)
	}
}

// TestGenerateOpenAPISpecDocs: the two documentation paths are in the document
// only when OpenAPIInfo.Docs says the adapter was mounted with
// HTTPConfig.Docs.Enabled, and they sit under the mount prefix like every other
// path. The wiretest harness's "docs" conditional set holds this to what the
// four adapters mount; this is the generator on its own.
func TestGenerateOpenAPISpecDocs(t *testing.T) {
	paths := func(info OpenAPIInfo) map[string]any {
		spec := GenerateOpenAPISpec(info)
		out, ok := spec["paths"].(map[string]any)
		if !ok {
			t.Fatalf("paths is %T", spec["paths"])
		}
		return out
	}

	for _, route := range []string{DocsSpecPath, DocsUIPath} {
		if _, ok := paths(OpenAPIInfo{})[DefaultAPIPrefix+route]; ok {
			t.Errorf("%q is documented without OpenAPIInfo.Docs", route)
		}
	}

	for _, tc := range []struct{ name, prefix, want string }{
		{"the default prefix", "", DefaultAPIPrefix},
		{"a configured prefix", "/api/auth", "/api/auth"},
		{"a prefix normalised like the mount", "api/auth/", "/api/auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			documented := paths(OpenAPIInfo{APIPrefix: tc.prefix, Docs: true})
			for _, route := range []string{DocsSpecPath, DocsUIPath} {
				item, ok := documented[tc.want+route].(map[string]any)
				if !ok {
					t.Fatalf("%q is not documented at %q", route, tc.want+route)
				}
				if _, ok := item["get"]; !ok {
					t.Errorf("%q is documented without a GET operation: %#v", route, item)
				}
			}
		})
	}

	// The flag adds these two and nothing else: a document that grew a third
	// path here would be describing a route no adapter mounts.
	base := len(paths(OpenAPIInfo{}))
	if got := len(paths(OpenAPIInfo{Docs: true})); got != base+2 {
		t.Errorf("OpenAPIInfo.Docs added %d paths, want 2", got-base)
	}
}

// TestDocsBasePath: DocsOptions.BasePath is where the document describes
// itself, and an empty one means the mount prefix — the reference's default for
// swaggerBasePath too (auth.router.ts:1657).
func TestDocsBasePath(t *testing.T) {
	for _, tc := range []struct{ name, prefix, basePath, want string }{
		{"unset follows the default mount prefix", "", "", DefaultAPIPrefix},
		{"unset follows a configured mount prefix", "/api/auth", "", "/api/auth"},
		{"set overrides the mount prefix", "/api/auth", "/public/auth", "/public/auth"},
		{"set is normalised like a prefix", "/api/auth", "public/auth/", "/public/auth"},
		{"blank counts as unset", "/api/auth", "   ", "/api/auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := HTTPConfig{APIPrefix: tc.prefix, Docs: DocsOptions{BasePath: tc.basePath}}
			if got := cfg.DocsBasePath(); got != tc.want {
				t.Errorf("DocsBasePath() = %q, want %q", got, tc.want)
			}
		})
	}
}
