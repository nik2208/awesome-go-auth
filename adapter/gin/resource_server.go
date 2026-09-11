package gin

import (
	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
)

// ResourceServerMiddleware returns a Gin-native resource-server middleware.
//
// A bearer token is verified against the issuer JWKS (RS256); an access-token
// cookie is verified against this instance own HS256 secret. Neither path reads
// a store: the principal is built from the verified claims either way. No token
// at all is 403 "No access token provided"; any verification failure is 401
// INVALID_TOKEN (jwks-auth.middleware.ts:44-79). The decisions live in
// auth.ResourceServerPrincipal, so the four adapters cannot answer differently.
//
// The user reaches the handler through UserFromContext, this package gin-native
// one, as it does behind Middleware.
//
// One key cache is built per call and shared by every request through the
// returned middleware.
func ResourceServerMiddleware(a *auth.Auth, cfg auth.ResourceServerConfig) gin.HandlerFunc {
	client := auth.NewJWKSClient(cfg)
	return func(c *gin.Context) {
		user, httpErr, ok := auth.ResourceServerPrincipal(c.Request, a, client, cfg.Issuer)
		if !ok {
			auth.WriteHTTPError(c.Writer, httpErr)
			c.Abort()
			return
		}
		c.Set(userContextKey, user)
		c.Next()
	}
}
