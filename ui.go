package auth

import (
	"embed"
	"net/http"
)

//go:embed ui/admin.html ui/auth.html ui/auth.js
var uiFS embed.FS

// ServeAdminUI returns an http.Handler serving the embedded admin dashboard HTML.
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

// ServeAuthUI returns an http.Handler serving the embedded auth UI HTML (login/register).
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
// Deprecated: use the vendored asset directly — UpstreamUIAssetFS(), or
// ReadUpstreamUIAsset("auth.js") — or the UI handler U11 introduces, which
// serves the whole vendored set with the SSR config injection the reference's
// pages expect. This function is a thin wrapper kept so that existing importers
// keep compiling, and it will be removed in v1.0.0.
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
