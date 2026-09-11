package chi

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// ResourceServerMiddleware returns a Chi-compatible resource-server middleware:
// a bearer token is verified against the issuer JWKS (RS256), an access-token
// cookie against this instance own HS256 secret, and the principal reaches the
// handler through the net/http adapter UserFromContext.
//
// Chi middleware is net/http middleware, so this is the shared one unchanged,
// exactly as Middleware is.
func ResourceServerMiddleware(a *auth.Auth, cfg auth.ResourceServerConfig) func(http.Handler) http.Handler {
	return auth.ResourceServerMiddleware(a, cfg)
}
