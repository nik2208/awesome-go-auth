package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The built-in UI group: the reference's whole ui.router.ts, mounted at
// <prefix>/ui.
//
// Two handlers, and the second contains the first. UIConfigHandler is
// GET <prefix>/ui/config, the document the UI fetches before it renders
// (ui.router.ts:165-170). UIHandler is the router that route lives in — the
// pages, the SSR injection, the uploaded assets, the static files and headless
// mode — and it is what the four adapters actually register.
//
// The decisions are in the root package: (*Auth).UIConfig builds the document
// and (*Auth).UIHandler is the router. What is here is the request reading, the
// shape, and the CSRF wrapper. Both are exported as http.Handlers because chi,
// gin and echo mount the UI by delegating here.

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

// UIHandler serves everything under <prefix>/ui: the config document above, the
// SSR-rendered HTML pages, the uploaded assets and the static files, in the
// reference's order (ui.router.ts).
//
// It is one handler rather than a route list because the reference's router is
// one mount (auth.router.ts:1640) whose last two layers are catch-alls, and
// because a catch-all sibling of a fixed path is not something every Go router
// will register: gin's tree refuses `<prefix>/ui/*path` outright while
// `<prefix>/ui/config` exists beside it. Delegating the fixed route from inside
// the catch-all is the one shape all four routers can express, and it is also
// the reference's own.
//
// The config route is passed in rather than rebuilt, so that the document and
// its Cache-Control stay in the one place they have been since v0.7.0 and
// cannot come to differ according to which route reached them. What is passed
// in is the bare UIConfig, not UIConfigHandler: guard here wraps the whole
// subtree once, and handing it an already-guarded handler would run the CSRF
// middleware twice on that one route — two Set-Cookie headers for the same
// cookie — and charge the rate limiter twice for one request.
//
// Guarding the whole subtree, pages and static files included, is what the
// reference does. Its CSRF auto-init is a router.use registered at
// auth.router.ts:529-538, about eleven hundred lines before the UI router is
// mounted, and Express runs every earlier use-layer for a route registered
// after it — so every page it serves carries a fresh csrf-token cookie to a
// reader who arrives without one. The login page needs exactly that: it is
// fetched before any session exists and posts to /login with the double-submit
// pair. Nothing can be rejected on the way in, since csrfEnforced passes every
// non-mutating method straight through.
func (a *Adapter) UIHandler() http.Handler {
	return a.guard(a.auth.UIHandler(a.cfg, http.HandlerFunc(a.UIConfig)))
}
