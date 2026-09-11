package gin_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	auth "github.com/nik2208/awesome-go-auth"
	ginadapter "github.com/nik2208/awesome-go-auth/adapter/gin"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

// mountResourceServer is the auth routes plus one host route behind the
// resource-server middleware, which is what the shared matrix drives.
func mountResourceServer(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig, rs auth.ResourceServerConfig) http.Handler {
	r := gin.New()
	ginadapter.MountWithConfig(r, a, cfg)
	r.GET(wiretest.ResourceServerProbePath, ginadapter.ResourceServerMiddleware(a, rs), func(c *gin.Context) {
		user, ok := ginadapter.UserFromContext(c)
		wiretest.WriteResourceServerProbe(c.Writer, user, ok)
	})
	return r
}

// TestResourceServer runs the shared resource-server middleware matrix.
func TestResourceServer(t *testing.T) {
	wiretest.RunResourceServer(t, mountResourceServer)
}
