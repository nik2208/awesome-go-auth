package chi_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	chiadapter "github.com/nik2208/awesome-go-auth/adapter/chi"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
	nethttpadapter "github.com/nik2208/awesome-go-auth/adapter/nethttp"
)

// mountResourceServer is the auth routes plus one host route behind the
// resource-server middleware, which is what the shared matrix drives.
func mountResourceServer(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig, rs auth.ResourceServerConfig) http.Handler {
	r := chi.NewRouter()
	chiadapter.MountWithConfig(r, a, cfg)
	r.With(chiadapter.ResourceServerMiddleware(a, rs)).
		Get(wiretest.ResourceServerProbePath, func(w http.ResponseWriter, r *http.Request) {
			user, ok := nethttpadapter.UserFromContext(r.Context())
			wiretest.WriteResourceServerProbe(w, user, ok)
		})
	return r
}

// TestResourceServer runs the shared resource-server middleware matrix.
func TestResourceServer(t *testing.T) {
	wiretest.RunResourceServer(t, mountResourceServer)
}
