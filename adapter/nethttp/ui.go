package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The built-in UI group. One route so far: GET <prefix>/ui/config, the document
// the UI fetches before it renders — the reference's ui.router.ts:165-170.
//
// The decision is entirely in the root package's (*Auth).UIConfig; this reads
// the request for the lang parameter and writes the shape. It is exported as an
// http.Handler because chi, gin and echo mount the route by delegating here.

// UIConfigHandler serves GET <prefix>/ui/config.
//
// It is wrapped in the CSRF middleware for the cookie that middleware hands out
// and not for any check it makes: the reference seeds the same cookie from a
// router-level middleware registered before its UI router (auth.router.ts:
// 529-535), and a GET is never enforced on either side. The route asks for no
// credential — the login page fetches it before a session exists.
func (a *Adapter) UIConfigHandler() http.Handler {
	return a.guard(http.HandlerFunc(a.UIConfig))
}

// UIConfig handles GET <prefix>/ui/config. The document is the whole body, as
// the reference's res.json(config) sends it.
//
// Cache-Control: no-store is this port's addition, and the one header here that
// does not come from the reference — which sets none on this route, where the
// JWKS route's Cache-Control is the reference's own (jwks.go). The route is
// public, is the first request a login page makes, and the CSRF middleware
// around it seeds a fresh per-client cookie, so a shared cache or CDN that
// stored one 200 would hand one visitor's CSRF cookie to the next. No client
// reads the header; it costs a caching proxy the one small document.
func (a *Adapter) UIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth.WriteJSON(w, http.StatusOK, a.auth.UIConfig(r.Context(), r, a.cfg))
}
