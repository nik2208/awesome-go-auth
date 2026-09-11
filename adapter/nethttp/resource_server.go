package nethttp

import (
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// ResourceServerMiddleware guards a host route in resource-server mode: a
// bearer token is verified against the issuer JWKS (RS256), an access-token
// cookie against this instance own HS256 secret, and the principal reaches the
// handler through UserFromContext.
//
// It is auth.ResourceServerMiddleware unchanged — the shared middleware is
// already a net/http one, and it stores the user under the key UserFromContext
// reads. The re-export exists so that a host wiring the net/http adapter finds
// it beside Middleware rather than having to know which package it lives in.
//
// One key cache is built per call. A host mounting several middlewares against
// one issuer that wants them to share a cache builds the client once with
// auth.NewJWKSClient and writes the two lines this function wraps.
func ResourceServerMiddleware(a *auth.Auth, cfg auth.ResourceServerConfig) func(http.Handler) http.Handler {
	return auth.ResourceServerMiddleware(a, cfg)
}
