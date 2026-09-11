package echo

import (
	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
)

// ResourceServerMiddleware returns an Echo-native resource-server middleware.
//
// A bearer token is verified against the issuer JWKS (RS256); an access-token
// cookie is verified against this instance own HS256 secret. Neither path reads
// a store: the principal is built from the verified claims either way. No token
// at all is 403 "No access token provided"; any verification failure is 401
// INVALID_TOKEN (jwks-auth.middleware.ts:44-79). The decisions live in
// auth.ResourceServerPrincipal, so the four adapters cannot answer differently.
//
// The user reaches the handler through UserFromContext, this package
// echo-native one, as it does behind Middleware.
//
// One key cache is built per call and shared by every request through the
// returned middleware.
func ResourceServerMiddleware(a *auth.Auth, cfg auth.ResourceServerConfig) echo.MiddlewareFunc {
	client := auth.NewJWKSClient(cfg)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, httpErr, ok := auth.ResourceServerPrincipal(c.Request(), a, client, cfg.Issuer)
			if !ok {
				auth.WriteHTTPError(c.Response(), httpErr)
				return nil
			}
			c.Set(userContextKey, user)
			return next(c)
		}
	}
}
