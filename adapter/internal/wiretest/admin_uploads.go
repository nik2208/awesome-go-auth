package wiretest

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// The two families U15 adds to the admin console, in a file of their own because
// they are the two the rest of admin.go's conventions do not fit: the upload
// routes are the only ones carrying a multipart body, and the documentation pair
// is the only one under /api/* with no guard.
//
// Their route tables live in admin.go beside the read and write ones, because
// adminAllRoutes walks all four and the not-mounted sweep has to see them.

// testAdminUploads is the fourth family on the admin surface
// (admin.router.ts:989-1085).
//
// It is a conditional set within a conditional set: the console has to be
// mounted, and an auth.UploadStore has to be configured, or the four routes are
// not registered at all. Both directions are checked, because the difference
// between "not registered" and "registered and refusing" is the difference
// between a 404 and a 401 to an anonymous caller — and the reference draws it
// with `if (options.uploadDir)` (:991) exactly as U13 drew it for the template
// routes.
func testAdminUploads(t *testing.T, mount Mounter) {
	t.Run("not registered without a store", func(t *testing.T) {
		// Every other optional store is wired, so a 404 here is the upload
		// store's absence and not another's. The policy is session-based and no
		// credential is presented, so a registered route would answer 401 —
		// which is what makes this an assertion about the mount.
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:   auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
			options: adminStoresWithoutUploads(),
		})
		for _, route := range adminUploadRoutes {
			rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d with no upload store, want 404 — unregistered, not guarded",
					route.method, route.path, rec.Code)
			}
		}
	})

	t.Run("guarded", func(t *testing.T) {
		// The invariant the rest of M8 carries, applied to the family that
		// writes: all four behind auth.AdminGuard.Protect and none behind
		// ProtectShell, so the Accept: text/html marker branch reaches the login
		// shell and nothing else.
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin:   auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()},
			options: adminAllStores(),
		})
		for _, route := range adminUploadRoutes {
			AssertError(t, env.Do(env.adminRequest(route.method, route.path, "{}")),
				http.StatusUnauthorized, "Unauthorized", "")
			AssertError(t, env.Do(adminHTML(env.adminRequest(route.method, route.path, "{}"))),
				http.StatusUnauthorized, "Unauthorized", "")
		}
	})

	t.Run("upload, list, delete", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})

		// The key is derived from the client's filename and never taken from it:
		// the directory components are gone and everything outside [A-Za-z0-9_-]
		// is an underscore (admin.router.ts:1005-1013). The stamp is the
		// server's clock, so only the shape is asserted here; the exact strings
		// are pinned by the package's own TestAdminUploadKey against a frozen
		// one.
		body := adminUpload(t, env, auth.AdminUploadLogoPath, "../../My Logo.PNG", []byte("pixels"))
		AssertKeys(t, body, "success", "filename", "url")
		filename, _ := body["filename"].(string)
		if !strings.HasPrefix(filename, "My_Logo_") || !strings.HasSuffix(filename, ".png") {
			t.Fatalf("filename = %v, want the sanitised name, a timestamp and the lowercased extension",
				body["filename"])
		}
		if strings.ContainsAny(filename, "/\\") {
			t.Errorf("filename = %q, which carries a path separator", filename)
		}
		// effectiveUploadBaseUrl is derived from the mount when nothing is
		// configured, so the url is the UI's uploads mount plus the key — a URL
		// this same deployment serves. See the
		// admin-upload-base-url-is-derived-from-the-mount deviation.
		wantURL := env.Config.Prefix() + "/ui/assets/uploads/" + filename
		if body["url"] != wantURL {
			t.Errorf("url = %v, want %q", body["url"], wantURL)
		}

		// bg-image is the same handler registered a second time, writing to the
		// same store.
		AssertKeys(t, adminUpload(t, env, auth.AdminUploadBGImagePath, "bg.webp", []byte("wide")),
			"success", "filename", "url")

		listing := adminGet(t, env, auth.AdminUploadFilesPath, http.StatusOK)
		AssertKeys(t, listing, "files")
		files := adminEntries(t, listing, "files")
		if len(files) != 2 {
			t.Fatalf("files = %v, want both uploads", files)
		}
		for i := range files {
			AssertKeys(t, adminObject(t, files, i), "name", "size", "mtime")
		}

		adminAssertSuccess(t, env, http.MethodDelete, auth.AdminUploadPath+"/"+filename, "")
		if got := adminEntries(t, adminGet(t, env, auth.AdminUploadFilesPath, http.StatusOK), "files"); len(got) != 1 {
			t.Errorf("after the delete the listing is %v, want one entry", got)
		}
		// A repeat delete is the reference's 404 for a file that is not there.
		AssertError(t, env.Do(env.adminRequest(http.MethodDelete, auth.AdminUploadPath+"/"+filename, "")),
			http.StatusNotFound, "File not found", "")
	})

	t.Run("an empty store lists an empty array", func(t *testing.T) {
		// Not null. Every shipped client iterates this.
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})
		if files := adminEntries(t, adminGet(t, env, auth.AdminUploadFilesPath, http.StatusOK), "files"); len(files) != 0 {
			t.Errorf("files = %v, want an empty array", files)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})

		// The reference's own branch: no part named "file", which is also where
		// a request that is not multipart at all ends up (:1025).
		AssertError(t, env.Do(adminUploadRequest(t, env, auth.AdminUploadLogoPath,
			"notfile", "logo.png", []byte("x"))), http.StatusBadRequest, "No file uploaded", "")
		AssertError(t, env.Do(env.adminRequest(http.MethodPost, auth.AdminUploadLogoPath, "{}")),
			http.StatusBadRequest, "No file uploaded", "")

		// The fileFilter's own message, with a status this port chooses because
		// the reference's rejection escapes to the host application's error
		// handler. See the admin-upload-refusals-answer-the-admin-envelope
		// deviation.
		AssertError(t, env.Do(adminUploadRequest(t, env, auth.AdminUploadLogoPath,
			"file", "payload.html", []byte("<script>alert(1)</script>"))),
			http.StatusBadRequest, "Only image files are allowed", "")

		// multer's limits.fileSize, same deviation.
		AssertError(t, env.Do(adminUploadRequest(t, env, auth.AdminUploadLogoPath,
			"file", "big.png", bytes.Repeat([]byte("x"), auth.UploadMaxBytes+1))),
			http.StatusRequestEntityTooLarge, "File too large", "")

		// None of the three stored anything.
		if files := adminEntries(t, adminGet(t, env, auth.AdminUploadFilesPath, http.StatusOK), "files"); len(files) != 0 {
			t.Errorf("the store holds %v after three refused uploads", files)
		}

		// The delete route's three refusals (:1068-1071). A slash or a backslash
		// only survives the router percent-encoded; a leading dot arrives as
		// itself.
		//
		// ".." is deliberately not in this list and is asserted against the
		// handler directly instead (the package's own TestAdminUploadRoutes): a
		// path ending in a "." or ".." segment never reaches any of the four
		// mounts, because net/http's ServeMux — and chi, gin and echo alike —
		// cleans the path and answers 301 before the handler is called. The
		// refusal below it is what the handler would have answered.
		for _, name := range []string{"%2Fetc%2Fpasswd", "%5Cwindows", ".hidden"} {
			AssertError(t, env.Do(env.adminRequest(http.MethodDelete, auth.AdminUploadPath+"/"+name, "")),
				http.StatusBadRequest, "Invalid filename", "")
		}
		// Past those three and still outside the key grammar: no such object can
		// exist, which is the answer the reference's existsSync gives too.
		AssertError(t, env.Do(env.adminRequest(http.MethodDelete, auth.AdminUploadPath+"/my%20logo.png", "")),
			http.StatusNotFound, "File not found", "")
	})

	t.Run("unrouted methods", func(t *testing.T) {
		// Express registers a layer per method, so the ordering of the four is
		// observable: DELETE /api/upload/files reaches the :filename layer,
		// because the fixed registrations above it are a GET and two POSTs.
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})
		AssertError(t, env.Do(env.adminRequest(http.MethodDelete, auth.AdminUploadFilesPath, "")),
			http.StatusNotFound, "File not found", "")

		for _, route := range []adminRoute{
			{http.MethodGet, auth.AdminUploadLogoPath},
			{http.MethodPost, auth.AdminUploadFilesPath},
			{http.MethodDelete, auth.AdminUploadPath},
			{http.MethodDelete, auth.AdminUploadPath + "/a/b.png"},
		} {
			rec := env.Do(env.adminRequest(route.method, route.path, "{}"))
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 404: the reference registers no layer for it",
					route.method, route.path, rec.Code)
			}
		}
	})

	t.Run("the console reports the feature", func(t *testing.T) {
		// features.upload is `!!options.uploadDir` (:656), and the SPA draws its
		// file picker from it (admin.js). Both directions, because a tab whose
		// every request 404s is worse than a hidden one.
		with := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})
		if adminFeature(t, with, "upload") != true {
			t.Error("features.upload is false with an upload store configured")
		}
		without := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminStoresWithoutUploads(),
		})
		if adminFeature(t, without, "upload") != false {
			t.Error("features.upload is true with no upload store")
		}
	})
}

// adminFeature reads one flag out of GET <admin>/api/ping's features object.
func adminFeature(t *testing.T, env *adminEnv, name string) any {
	t.Helper()
	features, ok := adminGet(t, env, auth.AdminPingPath, http.StatusOK)["features"].(map[string]any)
	if !ok {
		t.Fatal("ping answered no features object")
	}
	return features[name]
}

// adminUploadRequest builds a multipart request with one file part, which is
// what multer's upload.single('file') reads and what the shipped console sends
// (admin.js uploadAsset).
func adminUploadRequest(t *testing.T, env *adminEnv, route, field, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, env.Config.AdminPath()+route, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// adminUpload issues one successful upload and decodes the body.
func adminUpload(t *testing.T, env *adminEnv, route, filename string, content []byte) map[string]any {
	t.Helper()
	rec := env.Do(adminUploadRequest(t, env, route, "file", filename, content))
	AssertStatus(t, rec, http.StatusOK)
	return Body(t, rec)
}

// testAdminDocs is the console's own GET /api/openapi.json and GET /api/docs
// (admin.router.ts:1493-1521), and the one thing it exists to pin is that they
// carry no guard.
//
// Every other route under /api/* is registered with the guard spread onto it and
// these two are not, so an anonymous caller reads the admin API's description
// and its Swagger page. That asymmetry is the reference's and is reproduced
// deliberately; what this port changes is that the pair is off until a host asks
// for it, which is the docs-routes-are-opt-in deviation applied to the third of
// the three routers.
func testAdminDocs(t *testing.T, mount Mounter) {
	docsOptions := func() auth.AdminOptions {
		options := auth.AdminOptions{Enabled: true, AccessPolicy: auth.AdminIsAdminFlag()}
		options.Docs.Enabled = true
		return options
	}

	t.Run("off until asked for", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: adminOpenOptions(), options: adminAllStores(),
		})
		for _, route := range adminDocsRoutes {
			rec := env.Do(env.adminRequest(route.method, route.path, ""))
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d with Docs.Enabled unset, want 404",
					route.method, route.path, rec.Code)
			}
		}
	})

	t.Run("unguarded", func(t *testing.T) {
		env := newAdminEnv(t, mount, adminEnvOptions{
			admin: docsOptions(), options: adminAllStores(),
		})

		// The guard is in force: the neighbouring route refuses the same caller.
		// Without this line the two assertions below could pass against a
		// console with no guard at all.
		AssertError(t, env.Do(env.adminRequest(http.MethodGet, auth.AdminPingPath, "")),
			http.StatusUnauthorized, "Unauthorized", "")

		rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminOpenAPIPath, ""))
		AssertStatus(t, rec, http.StatusOK)
		document := Body(t, rec)
		if document["openapi"] != "3.0.3" {
			t.Errorf("openapi = %v, want 3.0.3", document["openapi"])
		}
		paths, ok := document["paths"].(map[string]any)
		if !ok {
			t.Fatalf("paths = %v, want an object", document["paths"])
		}
		// The served document is this mount's and not a default: it is written
		// below the admin path and carries the flags the adapter was configured
		// with.
		base := env.Config.AdminDocsBasePath()
		for _, path := range []string{base + auth.AdminPingPath, base + auth.AdminUsersPath} {
			if _, ok := paths[path]; !ok {
				t.Errorf("the served document omits %q", path)
			}
		}

		rec = env.Do(env.adminRequest(http.MethodGet, auth.AdminDocsPath, ""))
		AssertStatus(t, rec, http.StatusOK)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html", ct)
		}
		if !strings.Contains(rec.Body.String(), base+auth.AdminOpenAPIPath) {
			t.Errorf("the page does not fetch the document beside it:\n%s", rec.Body.String())
		}
	})

	t.Run("the base path moves the description and not the mount", func(t *testing.T) {
		options := docsOptions()
		options.AccessPolicy = auth.AdminOpen()
		options.Docs.BasePath = "/edge/console"
		env := newAdminEnv(t, mount, adminEnvOptions{admin: options, options: adminAllStores()})

		// Still served where the adapter mounted it.
		rec := env.Do(env.adminRequest(http.MethodGet, auth.AdminOpenAPIPath, ""))
		AssertStatus(t, rec, http.StatusOK)

		paths, ok := Body(t, rec)["paths"].(map[string]any)
		if !ok {
			t.Fatal("paths is not an object")
		}
		for path := range paths {
			if !strings.HasPrefix(path, "/edge/console/") {
				t.Errorf("the document describes %q, want it below the configured base path", path)
			}
		}
	})
}
