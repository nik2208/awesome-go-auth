package auth

import (
	"embed"
	"net/http"
)

//go:embed ui/admin.html ui/auth.html ui/auth.js
var uiFS embed.FS

// This file is the port's own hand-written UI, which nothing in this module
// serves any more.
//
// Until v0.9.0 these three handlers were the whole of it: two pages someone
// wrote by reading the reference rather than copying it, and an SDK written
// against this port's routes. U10 vendored the reference's own fourteen assets
// (ui_upstream.go) and pointed ServeAuthJS at them; U11 mounted the reference's
// whole ui router at <prefix>/ui (ui_pages.go), which serves the vendored pages
// with the config injection those pages expect. The two page handlers below
// have no caller left inside the module and are kept only so that a host which
// mounted them on its own mux keeps compiling.
//
// All three go in v1.0.0 (U26), together with ui/admin.html, ui/auth.html,
// ui/auth.js, the uiFS embed and the contract tests in ui_test.go that are
// written against those three files.

// ServeAdminUI returns an http.Handler serving the embedded admin dashboard HTML.
//
// The page is this port's own, not the reference's. The reference's admin SPA
// is vendored as admin.js and admin.css and is served by UIHandler along with
// everything else under <prefix>/ui — but it calls an admin API that no adapter
// mounts until M8, so it is bytes on disk rather than a working dashboard, and
// this hand-written page is neither replaced nor removed in this release.
//
// Deprecated: this page is not maintained and nothing in this module serves it.
// It will be removed in v1.0.0; there is no drop-in replacement until the admin
// router lands in M8.
func ServeAdminUI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/admin.html")
		if err != nil {
			http.Error(w, "admin ui not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data) //nolint:errcheck
	})
}

// ServeAuthUI returns an http.Handler serving the embedded auth UI HTML
// (login/register).
//
// It serves this port's hand-written page, and it serves it raw: no branding,
// no site name, no logo, no injected config. The page fetches
// <prefix>/ui/config for itself, so it works, but it flashes unstyled and it is
// not the page the family's deployments show.
//
// Deprecated: mount the UI instead — set HTTPConfig.UI.Enabled and the adapter
// registers <prefix>/ui, where UIHandler serves the reference's own login page
// with the SSR config injection. This function will be removed in v1.0.0.
func ServeAuthUI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/auth.html")
		if err != nil {
			http.Error(w, "auth ui not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data) //nolint:errcheck
	})
}

// ServeAuthJS returns an http.Handler serving the auth.js browser SDK.
//
// What it serves changed in v0.9.0. It now returns the reference's auth.js,
// vendored byte for byte under ui/upstream/assets and pinned by its sha256
// (ui_upstream.go), rather than this port's hand-written ui/auth.js. The
// hand-written file is still in the tree and still embedded, because
// ui_test.go's contract tests are written against it and because removing it
// is a breaking change this release does not make — but nothing serves it any
// more, and it is not maintained.
//
// One behaviour changed with the bytes. The hand-written SDK sent
// X-Auth-Strategy: bearer and exposed the tokens it got back; the reference's
// SDK is a cookie-only client and never sends that header. The server is
// unaffected and still honours X-Auth-Strategy from any caller, so a page that
// wants bearer delivery can still ask for it — but it can no longer ask for it
// through this SDK. See the v0.9.0 CHANGELOG entry.
//
// Deprecated: set HTTPConfig.UI.Enabled and let the adapter mount <prefix>/ui,
// where UIHandler serves this same file — and the rest of the vendored set,
// with the SSR config injection the reference's pages expect — at the path
// those pages actually load it from. Or read it directly: UpstreamUIAssetFS(),
// or ReadUpstreamUIAsset("auth.js"). This function is a thin wrapper kept so
// that existing importers keep compiling, and it will be removed in v1.0.0.
func ServeAuthJS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := ReadUpstreamUIAsset("auth.js")
		if err != nil {
			http.Error(w, "auth.js not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(data) //nolint:errcheck
	})
}
