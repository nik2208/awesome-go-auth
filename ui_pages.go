package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
)

// This file is the rest of the reference's ui.router.ts: the HTML pages, the
// uploaded assets, the static files, and the server-side config injection that
// makes a page usable before auth.js has fetched anything.
//
// ui_config.go mounted the first of that router's four routes — GET /config —
// in v0.7.0. This mounts the other three and puts /config back where the
// reference has it, inside one handler, so that the whole of ui.router.ts is
// one thing an adapter mounts once rather than four things four adapters have
// to keep in the reference's order. The order is behaviour: /config answers
// before the headless short-circuit, the short-circuit returns before the
// uploaded assets are mounted, and the SSR catch-all runs before the static
// serve, which is the only reason an extensionless /login is a page and
// /base.css is a file.
//
// The pages it serves are the vendored ones (ui_upstream.go), which U10 copied
// from the reference byte for byte. They are not editable here, so everything
// they need in order to render — the branding variables, the site name, the
// logo, the config object — has to be injected on the way out. That is what
// uiInjectSSR is, and every replacement it makes is a contract with a specific
// string in those files rather than a generic templating pass.

// UIRoute is where the reference mounts its whole ui router below the API
// prefix (auth.router.ts:1640). Everything in this file is relative to it.
const UIRoute = "/ui"

// uiDefaultPage is the page a request for the mount root renders. The reference
// derives it from an empty path (ui.router.ts:306), where the empty string is
// falsy and the `|| 'login'` behind it decides.
const uiDefaultPage = "login"

// uiFallbackPages are tried, in order, when the requested page has no file of
// its own (ui.router.ts:316). The first that exists is rendered; if none does,
// the request falls through to the static serve.
//
// Only the first of the three is vendored. index.html and index.csr.html are
// the reference's hook for a host that points UIOptions.Assets at a built SPA,
// and they are kept — in this order — because dropping them would change what a
// deployment that has one of those files serves.
var uiFallbackPages = []string{"login.html", "index.html", "index.csr.html"}

// uiPageCacheControl is what the reference sets on an SSR-rendered page
// (ui.router.ts:284). The document embeds a per-request config object, so it is
// not a shared-cacheable resource and the header says so all four ways.
const uiPageCacheControl = "no-store, no-cache, must-revalidate, max-age=0"

// uiStaticCacheControl is what express.static sends under the reference's
// `maxAge: 0` (ui.router.ts:330, :177-178): revalidate every time, but the
// response may be stored. Go's file serving sets no Cache-Control at all, so
// without this line a deployment moving from node-auth would silently lose the
// header its CDN was configured around.
const uiStaticCacheControl = "public, max-age=0"

// UIHandler returns the handler for the built-in UI: the whole of the
// reference's ui.router.ts, mounted at <prefix>/ui.
//
// cfg is the wire configuration the adapter was mounted with; it supplies the
// mount prefix the handler strips to find the router-relative path, the
// branding the injection reads, and UIOptions.Headless and UIOptions.Uploads.
//
// configRoute serves the router-relative /config route — the reference's first
// route (ui.router.ts:165-170), which this port mounted two releases ago and
// which this handler therefore delegates to rather than reimplements. The four
// adapters pass (*nethttp.Adapter).UIConfigHandler(). Passing nil leaves
// <prefix>/ui/config to the catch-all, which would render login.html at it — so
// nil is correct only for a host that has registered a more specific route for
// it on its own router, and never for a host that mounts this handler as the
// whole UI surface.
//
// Assets come from UIOptions.Assets, or from the vendored copies
// (UpstreamUIAssetFS) when a host configures none — the reference's own "if not
// provided, the internal Vanilla JS UI will be served" (ui.router.ts:11-14,
// :72-93). The reference searches six candidate directories on disk to find
// those internal assets; there is nothing to search here, because they are
// compiled in.
func (a *Auth) UIHandler(cfg HTTPConfig, configRoute http.Handler) http.Handler {
	assets := cfg.UI.Assets
	if assets == nil {
		assets = UpstreamUIAssetFS()
	}
	// The uploaded-asset filesystem, resolved once. UIOptions.Uploads wins; with
	// nothing set there, an UploadStore configured on the Auth serves the two
	// mounts through UploadFS, which is what makes one store wire both halves of
	// the reference's arrangement — its admin router writes to uploadDir and its
	// UI router mounts express.static over the same directory. See
	// UIOptions.Uploads for the precedence and UploadFS for what it cannot do.
	uploads := cfg.UI.Uploads
	if uploads == nil {
		uploads = UploadFS(a.service.cfg.Uploads)
	}
	headless := cfg.UI.Headless

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := uiRouterPath(r, cfg)

		// 1. The config endpoint (ui.router.ts:165-170). It is registered with
		// router.get there, so it answers GET and — Express routing HEAD to the
		// GET handler — HEAD, and a POST to the same path falls past it into
		// the catch-all, which next()s every non-GET and ends in a 404.
		if configRoute != nil && rel == "/config" &&
			(r.Method == http.MethodGet || r.Method == http.MethodHead) {
			configRoute.ServeHTTP(w, r)
			return
		}

		// 2. Headless mode (ui.router.ts:172-183). The hosting SPA provides its
		// own login UI, so the pages are not served at all — only /config above
		// and the static assets, which is what a <script src=".../auth.js">
		// integration needs. The return is the behaviour: a headless deployment
		// that still answered login.html would be a different product, and the
		// uploaded-asset routes below are on the far side of it and so are not
		// mounted either.
		if headless {
			if !uiServeStatic(w, r, assets, rel) {
				http.NotFound(w, r)
			}
			return
		}

		// 3. Uploaded assets (ui.router.ts:185-191), under both the legacy
		// /assets/logo path and the unified /assets/uploads one, from the same
		// directory. A miss falls through rather than answering, because
		// express.static calls next() when it finds no file — so an
		// unconfigured deployment, which mounts neither, and a configured one
		// that is asked for a file it does not hold behave alike and end at the
		// same 404.
		//
		// One express.static default is not reproduced. These two mounts are
		// the reference's only ones that leave `index` at its default of
		// 'index.html', so a bare GET of <prefix>/ui/assets/logo there serves an
		// uploaded file of that name as a directory index; here it falls through
		// to the catch-all and renders the login page, which is what the
		// reference does too for every upload directory that does not happen to
		// contain an index.html. Serving one would mean treating a file someone
		// uploaded as a page, which is not a behaviour worth carrying forward.
		if uploads != nil {
			for _, mount := range [...]string{"/assets/logo/", "/assets/uploads/"} {
				if rest, ok := strings.CutPrefix(rel, mount); ok {
					if uiServeStatic(w, r, uploads, rest) {
						return
					}
				}
			}
		}

		// 4. The SSR catch-all (ui.router.ts:295-327).
		if r.Method == http.MethodGet && !uiHasExtension(rel) {
			if name, ok := uiResolvePage(assets, rel); ok {
				a.uiRenderPage(w, r, cfg, assets, name)
				return
			}
		}

		// 5. Static serving last (ui.router.ts:329-332), which is what makes a
		// path with an extension a file and everything else a page.
		if uiServeStatic(w, r, assets, rel) {
			return
		}
		// The reference's router runs out here and Express's own 404 answers.
		// This handler owns the subtree, so it writes that 404 itself; the body
		// is Go's rather than Express's "Cannot GET /x", and no client reads
		// either.
		http.NotFound(w, r)
	})
}

// uiRouterPath is req.path as the reference's mounted router sees it: the
// request path with <prefix>/ui removed, never empty, always leading-slashed.
// Express gives a router mounted with router.use('/ui', ...) a req.path of "/"
// for both <prefix>/ui and <prefix>/ui/, and "/login" for <prefix>/ui/login.
//
// A request whose path is not under the mount at all is passed through whole.
// That happens only when a host has mounted this handler somewhere other than
// where cfg says the API is, in which case the whole path is the best available
// reading of what it asked for — and every page and asset name is resolved
// relative to the asset filesystem, so such a mount still finds its own files.
func uiRouterPath(r *http.Request, cfg HTTPConfig) string {
	mount := cfg.Prefix() + UIRoute
	switch p := r.URL.Path; {
	case p == mount:
		return "/"
	case strings.HasPrefix(p, mount+"/"):
		return p[len(mount):]
	default:
		return p
	}
}

// uiHasExtension is Node's path.extname(req.path) read as a boolean
// (ui.router.ts:300): the test that sends a path with a file extension to the
// static serve and everything else to the SSR catch-all.
//
// It is spelled out rather than delegated to Go's path.Ext because the two
// disagree on dotfiles, and the disagreement is the wrong way round. Node
// returns the empty string for a basename whose only dot is its first
// character, so "/.well-known" has no extension and is a page; Go's path.Ext
// returns ".well-known" for the same input, which would send it to the static
// serve instead. Node returns the empty string for a basename of "." or ".."
// as well, which Go's path.Ext does not. Everything else agrees, "a."
// included: Node returns "." there, which is truthy, so a trailing dot counts
// as an extension on both sides.
func uiHasExtension(p string) bool {
	base := p
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 {
		// No dot, or a leading dot that is the only one: no extension.
		return false
	}
	// A basename of nothing but dots is Node's other empty case.
	return strings.Trim(base, ".") != ""
}

// uiResolvePage maps a router-relative path to the asset that renders it
// (ui.router.ts:306-325), or reports that nothing does.
//
// The page is the path without its single leading slash, defaulting to "login";
// the file is <page>.html. If that file is absent the three fallbacks are tried
// in order, and if none of them exists the caller falls through to the static
// serve, as the reference's next() does.
func uiResolvePage(assets fs.FS, rel string) (string, bool) {
	page := strings.TrimPrefix(rel, "/")
	if page == "" {
		page = uiDefaultPage
	}
	if name := page + ".html"; uiFileExists(assets, name) {
		return name, true
	}
	for _, name := range uiFallbackPages {
		if uiFileExists(assets, name) {
			return name, true
		}
	}
	return "", false
}

// uiFileExists is the reference's fs.existsSync narrowed to regular files
// (ui.router.ts:310, :319).
//
// The narrowing is deliberate. existsSync answers true for a directory, and the
// reference then reads it, throws EISDIR, falls into its own catch and tries to
// sendFile the directory, which fails again and ends as a 500. Treating a
// directory as absent sends the request on to the fallbacks instead, which is
// what a deployment whose assets happen to contain a directory named
// "login.html" would want and what every deployment that does not — the
// vendored set included — cannot tell apart.
//
// An invalid name is absent too. fs.FS rejects paths that are absolute, or that
// walk out with "..", by returning an error rather than a file, so a traversal
// attempt resolves to the login page rather than to anything outside the asset
// set.
func uiFileExists(fsys fs.FS, name string) bool {
	if fsys == nil || !fs.ValidPath(name) {
		return false
	}
	info, err := fs.Stat(fsys, name)
	return err == nil && info.Mode().IsRegular()
}

// uiServeStatic is the reference's expressStatic(dir, {maxAge: 0, index: false})
// (ui.router.ts:329-332): serve the named file if it is there, and report
// whether it was, so the caller can fall through exactly where express.static
// would have called next().
//
// It is hand-rolled rather than http.FileServer for three behaviours that
// differ from express.static and that would all be visible on the wire:
// FileServer writes a directory listing for a directory, redirects a request
// for ".../index.html" to ".../", and redirects a path it wants to clean. None
// of those happen here — a directory is a miss, and the path is either served
// or not.
//
// http.ServeContent supplies the rest: Content-Type from the extension, HEAD
// answered with headers and no body, and Range. It writes no Last-Modified for
// the vendored assets, whose embedded modification time is the zero time.
func uiServeStatic(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	name = strings.TrimPrefix(name, "/")
	if fsys == nil || name == "" || !fs.ValidPath(name) {
		return false
	}
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	// embed.FS and os.DirFS both hand back seekable files; an fs.FS that does
	// not is read into memory rather than refused, because refusing would make
	// the asset seam accept only some filesystems.
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(f)
		if err != nil {
			return false
		}
		rs = bytes.NewReader(data)
	}
	w.Header().Set("Cache-Control", uiStaticCacheControl)
	http.ServeContent(w, r, info.Name(), info.ModTime(), rs)
	return true
}

// uiRenderPage is serveSsrHtml (ui.router.ts:193-291): read the page, build the
// config document for this request, inject both into the HTML, and send it
// uncacheable.
func (a *Auth) uiRenderPage(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, assets fs.FS, name string) {
	data, err := fs.ReadFile(assets, name)
	if err != nil {
		// The reference reaches its catch here and calls res.sendFile on the
		// same path, which fails for the same reason and ends as a 500. There
		// is nothing to send unmodified when the read is what failed.
		a.service.logf("auth: ui: reading page %q failed: %v", name, err)
		http.Error(w, "ui page not found", http.StatusInternalServerError)
		return
	}
	html, err := uiInjectSSR(string(data), a.UIConfig(r.Context(), r, cfg))
	if err != nil {
		// The reference's fallback: on any error inside the injection, send the
		// file unmodified (ui.router.ts:286-290). The page then boots from
		// GET <prefix>/ui/config instead of from the injected object, which is
		// slower and flashes unstyled, but works.
		//
		// Nothing reaches this in practice — the only failure uiInjectSSR can
		// report is a JSON encoding error, and UIConfig is a struct of strings,
		// bools and a map of strings, none of which encoding/json can refuse.
		// The branch is kept because it is the reference's contract and because
		// UIFeatures already carries a hand-written MarshalJSON that a later
		// change could give an error path.
		a.service.logf("auth: ui: SSR injection failed for %q, serving it unmodified: %v", name, err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", uiStaticCacheControl)
		w.Write(data) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", uiPageCacheControl)
	io.WriteString(w, html) //nolint:errcheck
}

// The three patterns the injection rewrites. Each is a contract with a string
// that is actually in the vendored pages, so each carries what it matches
// there — and the vendored pages cannot be edited to suit a pattern, which is
// why these are ported rather than simplified.
//
// JavaScript's regexp engine backtracks and Go's does not, so a lazy quantifier
// is the one construct that had to be checked rather than copied. It survives:
// RE2 implements the same leftmost-first preference Perl and JavaScript do, so
// `.*?` stops at the first following match here exactly as it does there. What
// does not survive untouched is the `s` flag and the replace-once default —
// both are spelled out below.
var (
	// /<title>.*?<\/title>/s — dotall, so a title broken across lines is still
	// one match. All nine vendored pages hold their title on one line, which is
	// why the flag costs nothing today and is kept anyway: a re-vendor that
	// reformatted one would otherwise leave its title unreplaced and the page
	// would silently show the reference's own name.
	uiTitlePattern = regexp.MustCompile(`(?s)<title>.*?</title>`)
	// /(<h1[^>]*class="site-name"[^>]*>).*?(<\/h1>)/s — the open tag and the
	// close tag are captured and kept, and only what is between them is
	// replaced. Both [^>]* are needed: eight of the nine pages write
	// `<h1 class="site-name" data-i18n="site_name">` and account-conflict.html
	// writes an id in between as well. A negated class matches a newline in Go
	// as it does in JavaScript, so only the `.` needed the flag.
	uiSiteNamePattern = regexp.MustCompile(`(?s)(<h1[^>]*class="site-name"[^>]*>).*?(</h1>)`)
	// /<img src=".*?" alt="Logo" class="logo hidden">/ — no `s` flag there and
	// none here, and Go's `.` excludes newline by default, so the two agree
	// without being asked. The vendored pages all write `src=""`, which would
	// make a plain string replacement work today; the pattern is kept because
	// the reference's is a pattern, and a re-vendor that gave the tag a
	// placeholder src would silently stop matching a string and go on matching
	// this. account-conflict.html has no logo tag at all and is simply left
	// alone, as it is there.
	uiLogoPattern = regexp.MustCompile(`<img src=".*?" alt="Logo" class="logo hidden">`)
)

// uiSiteNameEscaper is the reference's five chained .replace calls
// (ui.router.ts:218-223), in their order, which is the only order that is not
// double-escaping: the ampersand goes first, so the ampersands the other four
// introduce are never seen again.
//
// strings.NewReplacer makes one left-to-right pass and never rescans what it
// wrote, so it produces the same bytes as the chain for every input — the
// chain's only order-dependence is the ampersand, and a single pass has none at
// all.
//
// html.EscapeString is deliberately not used. It writes &#34; for the double
// quote where the reference writes &quot;, and both appear in the page title
// and the site heading of every rendered page, so a client diffing this port's
// output against node-auth's would see the difference on the wire.
var uiSiteNameEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#39;",
)

// uiBgImageEscaper is `.replace(/['"\\]/g, m => encodeURIComponent(m))`
// (ui.router.ts:211): the three characters that could break out of the
// url("...") the value is about to be written into, percent-encoded.
//
// encodeURIComponent is a general function applied to a three-character class,
// so the whole of it here is three constants — a quotation mark is %22, an
// apostrophe %27 and a backslash %5C, whatever the rest of the string holds.
// Nothing else is encoded, there as here: a bgImage with a space in it goes out
// with the space in it.
var uiBgImageEscaper = strings.NewReplacer(
	"'", "%27",
	`"`, "%22",
	`\`, "%5C",
)

// The readiness splash (ui.router.ts:231-270). The three literals are the
// reference's template literals byte for byte, leading newline and twelve-space
// indentation included, because they end up in the page and a client that diffs
// the two renderings would see any reflowing.
const (
	uiSplashCSS = `
            <style>
                body { background-color: var(--bg-color, #f8fafc); margin: 0; }
                #global-splash {
                    position: fixed;
                    top: 0; left: 0; width: 100vw; height: 100vh;
                    background-color: var(--bg-color, #f8fafc);
                    z-index: 999999;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    transition: opacity 0.3s ease-out;
                }
                .splash-spinner {
                    width: 40px; height: 40px;
                    border: 4px solid var(--secondary-color, #cbd5e1);
                    border-top: 4px solid var(--primary-color, #4a90d9);
                    border-radius: 50%;
                    animation: splash-spin 1s linear infinite;
                }
                @keyframes splash-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>`

	uiSplashHTML = `
            <div id="global-splash">
                <div class="splash-spinner"></div>
            </div>`

	uiSplashJS = `
            <script>
                window.onload = function() {
                    const splash = document.getElementById('global-splash');
                    if (splash) {
                        splash.style.opacity = '0';
                        setTimeout(() => splash.remove(), 300);
                    }
                };
            </script>`
)

// uiInjectSSR is the body of serveSsrHtml between the read and the send
// (ui.router.ts:198-281): the branding variables, the custom CSS, the site
// name, the logo, the splash and the config object, written into the page in
// the reference's order.
//
// Order matters twice. The site name is substituted before the logo because
// both rewrite the same document and the reference does them that way round;
// and all three insertions at the end go in after every replacement, so the
// styleTags the </head> insertion carries are the finished ones.
func uiInjectSSR(html string, config UIConfig) (string, error) {
	ui := config.UI

	// The :root block, which exists to prevent a flash of unstyled content: the
	// variables are in the document before any stylesheet is fetched.
	var style strings.Builder
	style.WriteString("<style>:root {")
	if ui.PrimaryColor != "" {
		// Two variables from one value (ui.router.ts:204-205). --input-focus is
		// not a second setting a deployment can give; it follows the primary
		// colour, and base.css reads it for the focus ring.
		style.WriteString("--primary-color: " + ui.PrimaryColor + ";")
		style.WriteString("--input-focus: " + ui.PrimaryColor + ";")
	}
	if ui.SecondaryColor != "" {
		style.WriteString("--secondary-color: " + ui.SecondaryColor + ";")
	}
	if ui.BgColor != "" {
		style.WriteString("--bg-color: " + ui.BgColor + ";")
	}
	if ui.CardBg != "" {
		style.WriteString("--card-bg: " + ui.CardBg + ";")
	}
	if ui.BgImage != "" {
		style.WriteString(`--bg-image: url("` + uiBgImageEscaper.Replace(ui.BgImage) + `");`)
	}
	style.WriteString("}</style>")

	// The custom CSS goes in a second <style>, unescaped, as it does there
	// (ui.router.ts:216). It is stylesheet source and there is nothing to
	// escape it into; a host that puts a </style> in it closes the block, in
	// this port exactly as in the reference. UIOptions.CustomCSS is read from
	// the static configuration only — no settings store can reach it — so the
	// string is the host's own code either way.
	if ui.CustomCSS != "" {
		style.WriteString("<style>" + ui.CustomCSS + "</style>")
	}
	styleTags := style.String()

	// The site name, into the tab title and the card heading. The three
	// non-empty guards here and above are the reference's and are kept, though
	// none of them can be false on this port: UIConfigBranding fills
	// primaryColor, secondaryColor and siteName from the defaults, and so does
	// the store-failure fallback.
	if ui.SiteName != "" {
		safe := uiSiteNameEscaper.Replace(ui.SiteName)
		html = uiReplaceFirst(html, uiTitlePattern, func(string, []int) string {
			return "<title>" + safe + "</title>"
		})
		html = uiReplaceFirst(html, uiSiteNamePattern, func(src string, m []int) string {
			// $1 and $2 by hand. Regexp.Expand would read a `$` in the site
			// name as a reference, and the site name is operator-supplied.
			return src[m[2]:m[3]] + safe + src[m[4]:m[5]]
		})
	}

	// The logo, which the pages ship hidden and empty so that a deployment
	// without one shows no broken image. Substituting it drops the `hidden`
	// class, which is what reveals it (ui.router.ts:227-229).
	//
	// The URL is written into the attribute unescaped, as it is there. That is
	// the reference's sink and this port reproduces it: a logoUrl containing a
	// double quote escapes the attribute. It is reachable from a settings store
	// as well as from the static config, which is a lower bar than the custom
	// CSS above — but the only writer of a settings store in this port today is
	// the host's own code, since the admin panel that would let an operator
	// write one lands in M8. It is named here so that the M8 change has to
	// decide about it rather than inherit it.
	if ui.LogoURL != "" {
		html = uiReplaceFirst(html, uiLogoPattern, func(string, []int) string {
			return `<img src="` + ui.LogoURL + `" alt="Logo" class="logo">`
		})
	}

	// The config object, so that auth.js boots from a value already in the
	// document instead of waiting for GET <prefix>/ui/config.
	//
	// encoding/json escapes <, > and & as \u003c, \u003e and \u0026 by default,
	// and that default is kept rather than turned off. It is a deviation — the
	// bytes differ from JSON.stringify's — and it is registered as
	// ui-ssr-config-json-is-html-escaped, which carries the argument.
	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	scriptTag := "<script>window.__AUTH_CONFIG__ = " + string(body) + ";</script>"

	// The three insertions (ui.router.ts:275-281). String replacements, not
	// patterns, there and here — and replace-once there, which is what the
	// count of 1 is: JavaScript's String.prototype.replace with a string
	// pattern rewrites the first occurrence only. Every vendored page holds
	// exactly one of each of these three anchors, so the count decides nothing
	// today and pins the semantics for a page that does not.
	html = strings.Replace(html, "</head>", styleTags+"\n"+uiSplashCSS+"\n"+scriptTag+"\n</head>", 1)
	html = strings.Replace(html, "<body>", "<body>\n"+uiSplashHTML, 1)
	html = strings.Replace(html, "</body>", uiSplashJS+"\n</body>", 1)
	return html, nil
}

// uiReplaceFirst rewrites the first match of pattern in src, which is what
// JavaScript's String.prototype.replace does with a regexp carrying no `g`
// flag — and none of the three patterns above carries one.
//
// Go has no replace-first for regexps: ReplaceAllString rewrites every match.
// On today's pages that is a distinction without a difference, since each
// pattern matches once; it is written this way because "the first <title>" is
// what the reference promises, and a page with two of them must not have both
// rewritten here and only one rewritten there.
//
// repl is handed the source and the submatch index pairs rather than a
// pre-expanded template, so a replacement containing `$` — a site name or a
// logo URL, both operator-supplied — is inserted literally.
func uiReplaceFirst(src string, pattern *regexp.Regexp, repl func(src string, m []int) string) string {
	m := pattern.FindStringSubmatchIndex(src)
	if m == nil {
		return src
	}
	return src[:m[0]] + repl(src, m) + src[m[1]:]
}
