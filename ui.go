package auth

import (
	"embed"
	"net/http"
)

//go:embed ui/admin.html ui/auth.html ui/auth.js
var uiFS embed.FS

// ServeAdminUI returns an http.Handler serving the embedded admin dashboard HTML.
func ServeAdminUI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/admin.html")
		if err != nil {
			http.Error(w, "admin ui not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data) //nolint:errcheck
	})
}

// ServeAuthUI returns an http.Handler serving the embedded auth UI HTML (login/register).
func ServeAuthUI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/auth.html")
		if err != nil {
			http.Error(w, "auth ui not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data) //nolint:errcheck
	})
}

// ServeAuthJS returns an http.Handler serving the embedded auth.js browser SDK.
func ServeAuthJS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/auth.js")
		if err != nil {
			http.Error(w, "auth.js not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(data) //nolint:errcheck
	})
}
