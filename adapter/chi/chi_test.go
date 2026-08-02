package chi_test

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	auth "github.com/nik2208/awesome-go-auth"
	chiadapter "github.com/nik2208/awesome-go-auth/adapter/chi"
	"github.com/nik2208/awesome-go-auth/adapter/internal/wiretest"
)

func mount(_ *testing.T, a *auth.Auth, cfg auth.HTTPConfig) http.Handler {
	r := chi.NewRouter()
	chiadapter.MountWithConfig(r, a, cfg)
	return r
}

// TestWireContract proves the chi mount, which delegates to the net/http
// handlers, is byte-for-byte the same surface.
func TestWireContract(t *testing.T) {
	wiretest.Run(t, mount)
}
