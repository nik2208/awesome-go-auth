package echo_test

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	auth "github.com/nik2208/awesome-go-auth"
	echoadapter "github.com/nik2208/awesome-go-auth/adapter/echo"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

// mountResourceServer is the auth routes plus one host route behind the
// resource-server middleware, which is what the shared matrix drives.
func mountResourceServer(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig, rs auth.ResourceServerConfig) http.Handler {
	e := echo.New()
	echoadapter.MountWithConfig(e.Group(""), a, cfg)
	e.GET(wiretest.ResourceServerProbePath, func(c echo.Context) error {
		user, ok := echoadapter.UserFromContext(c)
		wiretest.WriteResourceServerProbe(c.Response(), user, ok)
		return nil
	}, echoadapter.ResourceServerMiddleware(a, rs))
	return e
}

// TestResourceServer runs the shared resource-server middleware matrix.
func TestResourceServer(t *testing.T) {
	wiretest.RunResourceServer(t, mountResourceServer)
}
