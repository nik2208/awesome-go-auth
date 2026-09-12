package auth

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// The routing of <prefix>/ui is pinned by the wiretest suite, on all four
// adapters. What is pinned here is what the four adapters cannot see: the
// classification rules the catch-all applies, and every one of the string
// replacements uiInjectSSR makes — because each of those is a contract with a
// vendored file this repository is not allowed to edit, so the test is the only
// thing that notices when a re-vendor breaks one.

// uiPagesHTTPConfig is a mounted UI at the default prefix.
func uiPagesHTTPConfig() HTTPConfig {
	cfg := DefaultHTTPConfig()
	cfg.UI.Enabled = true
	return cfg
}

// uiPagesHandler builds the handler under test with a recognisable stand-in for
// the config route, so that a test can tell delegation from a page render
// without parsing JSON.
func uiPagesHandler(t *testing.T, cfg HTTPConfig) http.Handler {
	t.Helper()
	a := uiTestAuth(t, uiTestConfig())
	return a.UIHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Config-Route", "1")
		w.WriteHeader(http.StatusOK)
	}))
}

// uiPagesGet replays one request against the handler.
func uiPagesGet(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestUIHasExtension(t *testing.T) {
	// Node's path.extname read as a boolean. The dotfile rows are the ones Go's
	// path.Ext gets wrong, and they are why the function is hand-written.
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/", false},
		{"/login", false},
		{"/reset-password", false},
		{"/base.css", true},
		{"/auth.js", true},
		{"/assets/logo/company.png", true},
		{"/a.b/c", false},       // the extension is the last segment's, not the path's
		{"/.hidden", false},     // Node: '' — a leading dot is not an extension
		{"/.well-known", false}, // the same, and the case a real deployment hits
		{"/..", false},          // Node: ''
		{"/.", false},           // Node: ''
		{"/a.", true},           // Node: '.', which is truthy
		{"/.a.b", true},         // Node: '.b'
		{"", false},             //
		{"/dir/", false},        // trailing slash: the basename is empty
		{"/x/y.min.js", true},   //
		{"/2fa", false},         // a digit-led page name is still a page
	} {
		if got := uiHasExtension(tc.path); got != tc.want {
			t.Errorf("uiHasExtension(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestUIRouterPath(t *testing.T) {
	cfg := uiPagesHTTPConfig()
	for _, tc := range []struct{ path, want string }{
		// Express gives a router mounted at /ui a req.path of "/" for both of
		// these, and serves the login page at both.
		{"/auth/ui", "/"},
		{"/auth/ui/", "/"},
		{"/auth/ui/login", "/login"},
		{"/auth/ui/config", "/config"},
		{"/auth/ui/assets/logo/x.png", "/assets/logo/x.png"},
		// Not under the mount: passed through whole rather than mangled.
		{"/elsewhere/login", "/elsewhere/login"},
		// A path that merely starts with the same letters is not under it.
		{"/auth/uix", "/auth/uix"},
	} {
		got := uiRouterPath(httptest.NewRequest(http.MethodGet, tc.path, nil), cfg)
		if got != tc.want {
			t.Errorf("uiRouterPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestUIHandlerServesPagesAndAssets(t *testing.T) {
	h := uiPagesHandler(t, uiPagesHTTPConfig())

	t.Run("the mount root renders the login page", func(t *testing.T) {
		// page = '' || 'login' (ui.router.ts:306), at both spellings of the root.
		for _, target := range []string{"/auth/ui", "/auth/ui/"} {
			rec := uiPagesGet(t, h, http.MethodGet, target)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", target, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), `id="login-form"`) {
				t.Errorf("GET %s did not serve login.html", target)
			}
		}
	})

	t.Run("a named page renders its own file", func(t *testing.T) {
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/register")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `id="register-form"`) {
			t.Error("GET /auth/ui/register did not serve register.html")
		}
	})

	t.Run("an SSR page is uncacheable HTML", func(t *testing.T) {
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/login")
		if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != uiPageCacheControl {
			t.Errorf("Cache-Control = %q, want %q", got, uiPageCacheControl)
		}
	})

	t.Run("an unknown page falls back to login", func(t *testing.T) {
		// The reference tries login.html, index.html, index.csr.html in order
		// (ui.router.ts:316-325); only the first is vendored.
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/no-such-page")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `id="login-form"`) {
			t.Error("the fallback did not render login.html")
		}
	})

	t.Run("a path with an extension is a file, not a page", func(t *testing.T) {
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/base.css")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		want, err := ReadUpstreamUIAsset("base.css")
		if err != nil {
			t.Fatal(err)
		}
		if rec.Body.String() != string(want) {
			t.Error("base.css was not served verbatim")
		}
		if got := rec.Header().Get("Cache-Control"); got != uiStaticCacheControl {
			t.Errorf("Cache-Control = %q, want %q", got, uiStaticCacheControl)
		}
		if strings.Contains(rec.Body.String(), "__AUTH_CONFIG__") {
			t.Error("a static file was put through the SSR injection")
		}
	})

	t.Run("a missing file is a 404 rather than a page", func(t *testing.T) {
		// It has an extension, so it never reaches the catch-all and is never
		// answered with login.html — which is the whole reason the extension
		// test exists.
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/nothing.css")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("the config route is delegated", func(t *testing.T) {
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/config")
		if rec.Header().Get("X-Config-Route") != "1" {
			t.Fatalf("GET /auth/ui/config was answered by the catch-all (%d): %s",
				rec.Code, rec.Body.String())
		}
	})

	t.Run("a non-GET method falls through the catch-all", func(t *testing.T) {
		// req.method !== 'GET' → next() (ui.router.ts:296-298), and the static
		// layer behind it does not answer a POST either.
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec := uiPagesGet(t, h, method, "/auth/ui/login")
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s /auth/ui/login = %d, want 404", method, rec.Code)
			}
		}
		// And /config is a GET route there too, so a POST to it is not
		// delegated.
		if rec := uiPagesGet(t, h, http.MethodPost, "/auth/ui/config"); rec.Header().Get("X-Config-Route") != "" {
			t.Error("POST /auth/ui/config reached the config route")
		}
	})

	t.Run("HEAD reaches the static layer, not the catch-all", func(t *testing.T) {
		// The reference's catch-all next()s every non-GET including HEAD, so a
		// HEAD of an extensionless page falls to express.static, which has no
		// file called "login" and 404s — while a HEAD of a real asset is
		// answered. Reproduced rather than smoothed over: it is what a client
		// probing the two paths sees.
		if rec := uiPagesGet(t, h, http.MethodHead, "/auth/ui/login"); rec.Code != http.StatusNotFound {
			t.Errorf("HEAD /auth/ui/login = %d, want 404", rec.Code)
		}
		rec := uiPagesGet(t, h, http.MethodHead, "/auth/ui/base.css")
		if rec.Code != http.StatusOK {
			t.Errorf("HEAD /auth/ui/base.css = %d, want 200", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD returned a %d-byte body", rec.Body.Len())
		}
	})

	t.Run("a traversal attempt resolves to the login page", func(t *testing.T) {
		// fs.FS refuses a name containing "..", so the lookup misses and the
		// fallback chain answers. Nothing outside the asset set is reachable.
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/..%2f..%2fetc%2fpasswd")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="login-form"`) {
			t.Errorf("status = %d, body served was not the login page", rec.Code)
		}
	})
}

func TestUIHandlerHeadlessServesNoPages(t *testing.T) {
	// ui.router.ts:172-183: /config and the static assets, then return. A
	// headless deployment that still served login.html would be a different
	// product, so each half of this is asserted separately.
	cfg := uiPagesHTTPConfig()
	cfg.UI.Headless = true
	h := uiPagesHandler(t, cfg)

	for _, target := range []string{"/auth/ui", "/auth/ui/", "/auth/ui/login", "/auth/ui/register"} {
		if rec := uiPagesGet(t, h, http.MethodGet, target); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d in headless mode, want 404 (body %.80q)",
				target, rec.Code, rec.Body.String())
		}
	}

	// auth.js is the whole point of the mode: the hosting SPA loads it with a
	// <script> tag and uses the fetch interceptor.
	rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/auth.js")
	if rec.Code != http.StatusOK {
		t.Errorf("GET /auth/ui/auth.js = %d in headless mode, want 200", rec.Code)
	}

	if rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/config"); rec.Header().Get("X-Config-Route") != "1" {
		t.Error("the config route is not served in headless mode")
	}
}

func TestUIHandlerUploads(t *testing.T) {
	// The reference mounts the same directory under a legacy path and a unified
	// one (ui.router.ts:185-191).
	cfg := uiPagesHTTPConfig()
	cfg.UI.Uploads = fstest.MapFS{
		"company.png": &fstest.MapFile{Data: []byte("PNGDATA")},
	}
	h := uiPagesHandler(t, cfg)

	for _, target := range []string{"/auth/ui/assets/logo/company.png", "/auth/ui/assets/uploads/company.png"} {
		rec := uiPagesGet(t, h, http.MethodGet, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", target, rec.Code)
		}
		if rec.Body.String() != "PNGDATA" {
			t.Errorf("GET %s served %q", target, rec.Body.String())
		}
	}

	t.Run("a miss falls through rather than answering", func(t *testing.T) {
		// express.static next()s when it has no such file, so the request ends
		// at the same 404 an unconfigured deployment gives.
		rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/assets/logo/absent.png")
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("an unconfigured deployment serves neither path", func(t *testing.T) {
		// And does not fail: the reference's `if (uploadDir)` simply leaves the
		// two mounts unregistered.
		bare := uiPagesHandler(t, uiPagesHTTPConfig())
		for _, target := range []string{"/auth/ui/assets/logo/company.png", "/auth/ui/assets/uploads/company.png"} {
			if rec := uiPagesGet(t, bare, http.MethodGet, target); rec.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d with no Uploads configured, want 404", target, rec.Code)
			}
		}
	})
}

func TestUIHandlerHonoursConfiguredAssets(t *testing.T) {
	// UIOptions.Assets is the reference's uiAssetsDir: supplied, it replaces the
	// built-in set outright rather than layering over it.
	cfg := uiPagesHTTPConfig()
	cfg.UI.Assets = fstest.MapFS{
		"login.html": &fstest.MapFile{Data: []byte("<html><head></head><body>HOSTPAGE</body></html>")},
	}
	h := uiPagesHandler(t, cfg)

	rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/login")
	if !strings.Contains(rec.Body.String(), "HOSTPAGE") {
		t.Errorf("the configured asset set was not used: %.120q", rec.Body.String())
	}
	// The vendored set is not consulted as a fallback.
	if rec := uiPagesGet(t, h, http.MethodGet, "/auth/ui/base.css"); rec.Code != http.StatusNotFound {
		t.Errorf("GET base.css = %d against a host asset set that has no such file, want 404", rec.Code)
	}
}

// uiInjectTestConfig is a config with every branding member set to something
// recognisable, so an assertion cannot pass on a default.
func uiInjectTestConfig() UIConfig {
	return UIConfig{
		APIPrefix: "/auth",
		UI: UIConfigBranding{
			PrimaryColor:   "#112233",
			SecondaryColor: "#445566",
			LogoURL:        "https://cdn.example.com/logo.svg",
			SiteName:       "Acme Auth",
			CustomCSS:      ".card { border: 0 }",
			BgColor:        "#f0f4ff",
			BgImage:        "https://cdn.example.com/bg.jpg",
			CardBg:         "#ffffff",
		},
		Translations: map[string]string{},
		Lang:         "en",
	}
}

func TestUIInjectSSRWritesTheBrandingVariables(t *testing.T) {
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), uiInjectTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	// ui.router.ts:201-214, including the one value that becomes two variables.
	for _, want := range []string{
		"<style>:root {",
		"--primary-color: #112233;",
		"--input-focus: #112233;",
		"--secondary-color: #445566;",
		"--bg-color: #f0f4ff;",
		"--card-bg: #ffffff;",
		`--bg-image: url("https://cdn.example.com/bg.jpg");`,
		"}</style>",
		"<style>.card { border: 0 }</style>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the injected page does not contain %q", want)
		}
	}
}

func TestUIInjectSSROmitsUnsetBrandingVariables(t *testing.T) {
	// Each member is written only when it is set (ui.router.ts:203-213), so a
	// deployment that configures no background does not get an empty
	// --bg-color: ; declaration.
	config := uiInjectTestConfig()
	config.UI.BgColor = ""
	config.UI.BgImage = ""
	config.UI.CardBg = ""
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"--bg-color", "--card-bg", "--bg-image"} {
		// The splash CSS mentions --bg-color in a var() fallback, so the test
		// looks for the declaration rather than the name.
		if strings.Contains(out, unwanted+": ") {
			t.Errorf("the injected page declares %s for an unset value", unwanted)
		}
	}
}

func TestUIInjectSSREscapesTheBackgroundImageURL(t *testing.T) {
	// /['"\\]/g → encodeURIComponent (ui.router.ts:211). The value lands inside
	// url("..."), so these three are what could break out of it.
	config := uiInjectTestConfig()
	config.UI.BgImage = `https://x.example/a'b"c\d e.jpg`
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
	if err != nil {
		t.Fatal(err)
	}
	const want = `--bg-image: url("https://x.example/a%27b%22c%5Cd e.jpg");`
	if !strings.Contains(out, want) {
		t.Errorf("the escaped background URL is not %q", want)
	}
}

func TestUIInjectSSREscapesTheSiteName(t *testing.T) {
	// Five replacements in one order (ui.router.ts:218-223). The ampersand goes
	// first, which is what stops the other four's output being escaped again —
	// so the input below is chosen to fail loudly if the order is lost: a naive
	// order turns the < into &amp;lt;.
	config := uiInjectTestConfig()
	config.UI.SiteName = `A & B <script> "quoted" 'single'`
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
	if err != nil {
		t.Fatal(err)
	}
	const escaped = `A &amp; B &lt;script&gt; &quot;quoted&quot; &#39;single&#39;`
	if !strings.Contains(out, "<title>"+escaped+"</title>") {
		t.Errorf("the title does not carry the escaped site name")
	}
	if strings.Contains(out, "&amp;lt;") || strings.Contains(out, "&amp;quot;") {
		t.Error("the site name was double-escaped: the ampersand pass did not run first")
	}
	// &#34; is what html.EscapeString would have written; the family writes
	// &quot; and the two are different bytes on the wire.
	if strings.Contains(out, "&#34;") {
		t.Error("the double quote was escaped as &#34; rather than the reference's &quot;")
	}
}

func TestUIInjectSSRRewritesTheSiteHeading(t *testing.T) {
	// /(<h1[^>]*class="site-name"[^>]*>).*?(<\/h1>)/s — the tags are kept and
	// only the text between them is replaced. Both pages are asserted because
	// account-conflict.html writes an id attribute after the class, which is the
	// reason the second [^>]* is in the pattern at all.
	for _, page := range []string{"login.html", "account-conflict.html"} {
		t.Run(page, func(t *testing.T) {
			out, err := uiInjectSSR(mustUpstreamPage(t, page), uiInjectTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			m := uiSiteNamePattern.FindStringSubmatch(out)
			if m == nil {
				t.Fatal("the site-name heading has gone from the injected page")
			}
			if !strings.Contains(m[0], ">Acme Auth<") {
				t.Errorf("the heading is %q, want the configured site name in it", m[0])
			}
			if !strings.Contains(m[1], `class="site-name"`) {
				t.Errorf("the opening tag was not preserved: %q", m[1])
			}
			if strings.Contains(out, "Awesome Node Auth</h1>") {
				t.Error("the reference's own name is still in the heading")
			}
		})
	}
}

func TestUIInjectSSRDoesNotExpandDollarsInOperatorStrings(t *testing.T) {
	// The heading substitution rebuilds $1 and $2 by hand precisely so that an
	// operator-supplied string containing $1 is inserted rather than expanded.
	config := uiInjectTestConfig()
	config.UI.SiteName = `$1 costs $2`
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<title>$1 costs $2</title>") {
		t.Error("a site name containing $1 was expanded as a submatch reference")
	}
}

func TestUIInjectSSRRevealsTheLogo(t *testing.T) {
	// The pages ship the tag hidden and empty; substituting it drops the hidden
	// class, which is what makes the logo appear (ui.router.ts:227-229).
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), uiInjectTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `<img src="https://cdn.example.com/logo.svg" alt="Logo" class="logo">`) {
		t.Error("the logo tag was not substituted")
	}
	if strings.Contains(out, `class="logo hidden"`) {
		t.Error("the hidden logo tag is still in the page")
	}

	t.Run("no logo leaves the tag alone", func(t *testing.T) {
		config := uiInjectTestConfig()
		config.UI.LogoURL = ""
		out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, `class="logo hidden"`) {
			t.Error("the tag was rewritten for a deployment with no logo")
		}
	})

	t.Run("a page with no logo tag is unharmed", func(t *testing.T) {
		// account-conflict.html has none, and a replacement that does not match
		// leaves the document alone — there as here.
		out, err := uiInjectSSR(mustUpstreamPage(t, "account-conflict.html"), uiInjectTestConfig())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "__AUTH_CONFIG__") {
			t.Error("the rest of the injection did not run")
		}
	})
}

func TestUIInjectSSRInjectsTheSplashAndConfig(t *testing.T) {
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), uiInjectTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	// The three anchors, and where each insertion goes relative to them
	// (ui.router.ts:275-281).
	if !strings.Contains(out, uiSplashCSS+"\n") {
		t.Error("the splash CSS is not in the page")
	}
	if !strings.Contains(out, "<body>\n"+uiSplashHTML) {
		t.Error("the splash div does not follow <body>")
	}
	if !strings.Contains(out, uiSplashJS+"\n</body>") {
		t.Error("the splash script does not precede </body>")
	}
	if !strings.Contains(out, `<div id="global-splash">`) {
		t.Error("the splash element is missing")
	}

	head := strings.Index(out, "</head>")
	script := strings.Index(out, "window.__AUTH_CONFIG__")
	if script < 0 || head < 0 || script > head {
		t.Errorf("the config script is not before </head> (script %d, head %d)", script, head)
	}
}

func TestUIInjectSSRConfigJSONIsHTMLEscaped(t *testing.T) {
	// The registered deviation ui-ssr-config-json-is-html-escaped.
	//
	// The reference writes JSON.stringify(config) into a <script> unescaped, so
	// a </script> inside any operator-supplied string closes the block and what
	// follows is parsed as HTML. encoding/json escapes <, > and & by default and
	// that default is kept, which changes the bytes and closes the hole. Both
	// halves are asserted: the escape is present, and the raw sequence is not.
	config := uiInjectTestConfig()
	config.UI.SiteName = `x</script><img src=x onerror=alert(1)>`
	out, err := uiInjectSSR(mustUpstreamPage(t, "login.html"), config)
	if err != nil {
		t.Fatal(err)
	}

	script := out[strings.Index(out, "window.__AUTH_CONFIG__"):]
	script = script[:strings.Index(script, "</script>")]
	if strings.Contains(script, "<") || strings.Contains(script, ">") {
		t.Errorf("the config script carries a raw angle bracket: %.200q", script)
	}
	if !strings.Contains(script, `\u003c/script\u003e`) {
		t.Errorf("the </script> was not \\u-escaped: %.200q", script)
	}

	// And the escaping is not a substitute for the HTML escaping of the site
	// name, which happens separately and is what the <title> carries.
	if !strings.Contains(out, "<title>x&lt;/script&gt;") {
		t.Error("the site name was not HTML-escaped for the title")
	}
}

func TestUIInjectSSRReplacesOnlyTheFirstAnchor(t *testing.T) {
	// JavaScript's String.prototype.replace with a string pattern, and with a
	// regexp carrying no g flag, rewrites the first occurrence only. No vendored
	// page has a second one, so this is asserted on a page built for it.
	const page = `<html><head><title>one</title></head><body>` +
		`<title>two</title></body></html>`
	out, err := uiInjectSSR(page, uiInjectTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<title>Acme Auth</title>") {
		t.Fatal("the first title was not replaced")
	}
	if !strings.Contains(out, "<title>two</title>") {
		t.Error("the second title was replaced too: the port is using ReplaceAll")
	}
}

func TestUIInjectSSRLeavesAPageWithNoAnchorsAlone(t *testing.T) {
	// Every replacement here is conditional on finding its anchor, so a host
	// asset set that looks nothing like the reference's pages is passed through
	// rather than corrupted or refused.
	const page = "<p>not really a page</p>"
	out, err := uiInjectSSR(page, uiInjectTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if out != page {
		t.Errorf("a page with no anchors was rewritten to %q", out)
	}
}

func TestUIInjectSSRRendersEveryVendoredPage(t *testing.T) {
	// The injection is a set of contracts with the vendored files, which this
	// repository may not edit. This is the test that fails when a re-vendor
	// breaks one of them, naming the page and the anchor.
	assets := UpstreamUIAssetFS()
	names, err := fs.Glob(assets, "*.html")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 9 {
		t.Fatalf("found %d vendored pages, want the 9 in upstreamUIAssetTable", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			out, err := uiInjectSSR(mustUpstreamPage(t, name), uiInjectTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []struct{ what, substr string }{
				{"the config object", "window.__AUTH_CONFIG__"},
				{"the branding variables", "--primary-color: #112233;"},
				{"the splash element", `<div id="global-splash">`},
				{"the splash script", "window.onload = function()"},
				{"the site name in the title", "<title>Acme Auth</title>"},
				{"the site name in the heading", ">Acme Auth</h1>"},
			} {
				if !strings.Contains(out, want.substr) {
					t.Errorf("%s is missing from the rendered page (looked for %q)", want.what, want.substr)
				}
			}
			// account-conflict.html is the one page with no logo tag.
			if name != "account-conflict.html" && !strings.Contains(out, `alt="Logo" class="logo">`) {
				t.Error("the logo tag was not revealed")
			}
		})
	}
}

// mustUpstreamPage reads one vendored page.
func mustUpstreamPage(t *testing.T, name string) string {
	t.Helper()
	data, err := ReadUpstreamUIAsset(name)
	if err != nil {
		t.Fatalf("read vendored %s: %v", name, err)
	}
	return string(data)
}
