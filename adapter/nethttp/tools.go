package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The tools router: the reference's whole tools.router.ts, mounted at
// HTTPConfig.Tools.Path — beside the auth router's prefix rather than under it,
// because createToolsRouter is a second router the host mounts wherever it likes
// and its own swaggerBasePath default names '/tools' (tools.router.ts:114, :127).
//
// One handler for the whole subtree, as for the admin console and the UI, and
// for the same reason: the reference mounts one router, three of its six route
// groups carry a path parameter, and a catch-all beside fixed siblings is not a
// shape every Go router will register. The decisions are all in the root package
// — (*auth.Auth).ToolsHandler dispatches, and auth.ToolsProtectMiddleware is the
// guard the routes of U23 through U25 go behind.
//
// Like the admin console and unlike every other group here it does **not** go
// through guard. That wrapper is EventContextMiddleware, RateLimitMiddleware and
// CSRFMiddleware — the auth router's three, applied because the reference
// registers its auth routes after a router-level CSRF auto-init
// (auth.router.ts:529-538). The tools router is a separate Express router and
// sits outside all of it. Reproducing that is also what keeps the surface usable
// as designed: POST <tools>/track is a server-to-server call carrying no cookie
// and no double-submit pair, so a CSRF layer in front of it would refuse every
// caller the route exists for. See the file comment in tools.go.

// ToolsHandler serves the tools router's subtree. It is exported because chi,
// gin and echo mount the router by delegating here.
func (a *Adapter) ToolsHandler() http.Handler {
	return a.auth.ToolsHandler(a.cfg)
}

// ToolsOpenAPIInfo is the tools document this adapter describes, read off the
// HTTPConfig it was built with. It is exported for the reason OpenAPIInfo is: a
// host that serves the document from its own route, or writes it to a file at
// build time, needs exactly this value.
func (a *Adapter) ToolsOpenAPIInfo() auth.ToolsOpenAPIInfo {
	return a.cfg.ToolsOpenAPIInfo()
}
