package nethttp

import "net/http"

// The admin console: the reference's whole admin.router.ts, mounted at
// HTTPConfig.Admin.Path — beside the auth router's prefix rather than under it,
// because the reference's createAdminRouter is a second router the host mounts
// wherever it likes and its own default is '/admin' (admin.router.ts:190).
//
// One handler for the whole subtree, as for the UI, and for the same reason:
// the reference mounts one router, the later PRs of M8 fill it with parametered
// paths, and a catch-all beside fixed siblings is not a shape every Go router
// will register. The decisions are all in the root package —
// (*auth.Auth).AdminHandler dispatches the six routes and (*auth.Auth).AdminGuard
// is the access decision in front of five of them.
//
// Unlike every other group here it does **not** go through guard. That wrapper
// is EventContextMiddleware, RateLimitMiddleware and CSRFMiddleware — the auth
// router's three, applied because the reference registers its auth routes after
// a router-level CSRF auto-init (auth.router.ts:529-538). The admin router is a
// separate Express router and sits outside all of it: it has no CSRF layer, no
// rate limiter in the published reference, and publishes no events until U18.
// Wrapping it would also break the vendored SPA, which posts to <admin>/login
// with no CSRF header. See the file comment in admin.go.

// AdminHandler serves the admin console subtree. It is exported because chi,
// gin and echo mount the console by delegating here.
func (a *Adapter) AdminHandler() http.Handler {
	return a.auth.AdminHandler(a.cfg)
}
