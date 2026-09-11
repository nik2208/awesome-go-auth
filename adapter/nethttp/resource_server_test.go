package nethttp_test

import (
	"net/http"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// mountResourceServer is the auth routes plus one host route behind the
// resource-server middleware, which is what the shared matrix drives.
func mountResourceServer(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig, rs auth.ResourceServerConfig) http.Handler {
	mux := http.NewServeMux()
	nethttpadapter.MountWithConfig(mux, a, cfg)
	mux.Handle("GET "+wiretest.ResourceServerProbePath,
		nethttpadapter.ResourceServerMiddleware(a, rs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := nethttpadapter.UserFromContext(r.Context())
			wiretest.WriteResourceServerProbe(w, user, ok)
		})))
	return mux
}

// TestResourceServer runs the shared resource-server middleware matrix. The
// same matrix runs against chi, gin and echo.
func TestResourceServer(t *testing.T) {
	wiretest.RunResourceServer(t, mountResourceServer)
}
