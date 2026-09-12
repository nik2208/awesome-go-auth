package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// The upload routes' own decisions: the key the client's filename becomes, the
// bounds the request is held to, and the base URL the answers are built from.
//
// The wire itself — the four routes' statuses and bodies on all four adapters —
// is pinned in adapter/internal/wiretest/admin.go. What is here is what that
// suite cannot reach: a frozen clock, a store that fails, and the derivation
// that has no configuration to set it.

// uploadTestTime is the instant the key generator is frozen at. Its
// UnixMilli is 1700000000000, which is what every expected key below carries.
var uploadTestTime = time.UnixMilli(1700000000000).UTC()

// TestAdminUploadKey is multer's filename callback (admin.router.ts:1005-1013),
// including the two shapes a reader will call bugs.
func TestAdminUploadKey(t *testing.T) {
	for name, want := range map[string]string{
		"logo.png":     "logo_1700000000000.png",
		"LOGO.PNG":     "LOGO_1700000000000.png",
		"my logo.png":  "my_logo_1700000000000.png",
		"a.b.c.png":    "a_b_c_1700000000000.png",
		"shot.JPEG":    "shot_1700000000000.jpeg",
		"mark.svg":     "mark_1700000000000.svg",
		"favicon.ico":  "favicon_1700000000000.ico",
		"kebab-ok.png": "kebab-ok_1700000000000.png",
		"snake_ok.png": "snake_ok_1700000000000.png",

		// Traversal, on the write side. path.basename discards every directory
		// component and the character class flattens whatever survives, so the
		// key is a name and never a path — which is the whole write-side
		// argument in one row.
		"../../etc/passwd.png":     "passwd_1700000000000.png",
		"/absolute/path/logo.png":  "logo_1700000000000.png",
		`..\..\windows\evil.png`:   "______windows_evil_1700000000000.png",
		"sub/dir/../../escape.png": "escape_1700000000000.png",

		// A name that is nothing but an extension has no extension at all by
		// Node's rule, so the key ends in a bare dot and carries no type. The
		// fileFilter accepts such a name, so this is reachable.
		".png": "_png_1700000000000.",

		// Unicode is one underscore per UTF-16 code unit, so an astral
		// character is two. A rune-wise loop would produce one, and the
		// difference is visible in the filename the console displays.
		"lögo.png":         "l_go_1700000000000.png",
		"a\U0001F600b.png": "a__b_1700000000000.png",

		// Forty characters of name, and not one more.
		strings.Repeat("x", 50) + ".png": strings.Repeat("x", 40) + "_1700000000000.png",
	} {
		if got := adminUploadKey(name, uploadTestTime); got != want {
			t.Errorf("adminUploadKey(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestAdminUploadKeyIsAlwaysAValidKey is the claim that makes the write side
// safe by construction rather than by review: whatever a client calls its file,
// the key handed to the store is one path element inside the grammar.
//
// The corpus is deliberately hostile and deliberately larger than the table
// above — this case asserts a property, that one asserts the exact strings.
func TestAdminUploadKeyIsAlwaysAValidKey(t *testing.T) {
	names := []string{
		"logo.png", ".png", "..png", "...png", "..", ".", "/", "//", "/.png",
		"../../../../etc/shadow.png", `C:\Windows\System32\evil.png`,
		"%2e%2e%2flogo.png", "a\x00b.png", "NUL.png", "con.png",
		strings.Repeat("../", 100) + "x.png", strings.Repeat("ü", 200) + ".webp",
		"\U0001F600.gif", "  .svg", "-.ico", "_.jpg", "a?b=c.png", "a#b.png",
		"a\nb.png", "a\tb.png", `"quoted".png`, "'quoted'.png", "<x>.png",
	}
	for _, name := range names {
		key := adminUploadKey(name, uploadTestTime)
		if !ValidUploadKey(key) {
			t.Errorf("adminUploadKey(%q) = %q, which is not a valid key", name, key)
		}
		if strings.ContainsAny(key, `/\`) || strings.HasPrefix(key, ".") {
			t.Errorf("adminUploadKey(%q) = %q, which the delete route would refuse", name, key)
		}
	}
}

// TestNodeExtname pins the two carve-outs Node's path.extname has and a naive
// LastIndex does not, both of which a filename the fileFilter accepts can reach.
func TestNodeExtname(t *testing.T) {
	for base, want := range map[string]string{
		"logo.png": ".png",
		"a.b.png":  ".png",
		"logo":     "",
		".png":     "",
		"..":       "",
		"...":      ".",
		"a.":       ".",
	} {
		if got := nodeExtname(base); got != want {
			t.Errorf("nodeExtname(%q) = %q, want %q", base, got, want)
		}
	}
}

// TestAdminUploadBaseURL is effectiveUploadBaseUrl (admin.router.ts:638-643) and
// the one place this port resolves what the reference makes a host pass. See the
// admin-upload-base-url-is-derived-from-the-mount deviation.
func TestAdminUploadBaseURL(t *testing.T) {
	cases := []struct {
		name  string
		store bool
		cfg   HTTPConfig
		want  string
	}{
		{
			name:  "derived from the mount when nothing is configured",
			store: true,
			cfg:   HTTPConfig{APIPrefix: "/auth"},
			want:  "/auth/ui/assets/uploads",
		},
		{
			name:  "derived from AuthAPIPrefix when that is set",
			store: true,
			cfg:   HTTPConfig{APIPrefix: "/auth", Admin: AdminOptions{AuthAPIPrefix: "/edge/auth/"}},
			want:  "/edge/auth/ui/assets/uploads",
		},
		{
			name:  "configured wins over both",
			store: true,
			cfg:   HTTPConfig{APIPrefix: "/auth", Admin: AdminOptions{UploadBaseURL: "https://cdn.example/a"}},
			want:  "https://cdn.example/a",
		},
		{
			// `!effectiveUploadBaseUrl && … && options.uploadDir` (:640): with
			// nowhere to upload to there is nothing to build a URL for, and
			// both upload answers would return the bare filename anyway.
			name:  "no store derives nothing",
			store: false,
			cfg:   HTTPConfig{APIPrefix: "/auth"},
			want:  "",
		},
		{
			// The first arm is not gated on the store, so a host that
			// configured a base keeps it in the injected config either way.
			name:  "configured survives having no store",
			store: false,
			cfg:   HTTPConfig{APIPrefix: "/auth", Admin: AdminOptions{UploadBaseURL: "/assets"}},
			want:  "/assets",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newUploadTestAuth(t, c.store)
			if got := a.adminUploadBaseURL(c.cfg); got != c.want {
				t.Errorf("adminUploadBaseURL() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAdminUploadRoutes walks the four routes' answers against a real store,
// through the mounted handler.
func TestAdminUploadRoutes(t *testing.T) {
	t.Run("an upload answers success, filename and url", func(t *testing.T) {
		_, store, handler := uploadHarness(t, uploadConfig())
		body := uploadRequest(t, "file", "My Logo.PNG", []byte("pixels"))
		rec := doUpload(handler, http.MethodPost, AdminUploadLogoPath, body)
		got := uploadJSON(t, rec, http.StatusOK)

		wantKey := "My_Logo_1700000000000.png"
		if got["success"] != true || got["filename"] != wantKey {
			t.Fatalf("body = %v, want success and the derived key %q", got, wantKey)
		}
		if got["url"] != "/auth/ui/assets/uploads/"+wantKey {
			t.Errorf("url = %v, want the derived upload base plus the key", got["url"])
		}
		if len(got) != 3 {
			t.Errorf("body = %v, want exactly success, filename and url", got)
		}

		rc, info, err := store.Open(context.Background(), wantKey)
		if err != nil {
			t.Fatalf("the object is not in the store: %v", err)
		}
		stored, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(stored) != "pixels" || info.Size != 6 {
			t.Errorf("stored %q / %+v, want the uploaded bytes", stored, info)
		}

		// bg-image is the same handler registered a second time, so it answers
		// alike and writes to the same store.
		rec = doUpload(handler, http.MethodPost, AdminUploadBGImagePath,
			uploadRequest(t, "file", "bg.webp", []byte("x")))
		got = uploadJSON(t, rec, http.StatusOK)
		if got["filename"] != "bg_1700000000000.webp" {
			t.Errorf("bg-image filename = %v", got["filename"])
		}
	})

	t.Run("the bare filename when no base resolves", func(t *testing.T) {
		// A deployment that wants the reference's unconfigured answer has one:
		// the store is what the derivation is gated on, so this is reached by
		// pointing the base at nothing — which a host cannot do — or, as here,
		// by asking the URL builder directly. The route's own branch is the
		// same expression.
		a := newUploadTestAuth(t, false)
		if got := a.adminUploadURL(uploadConfig(), "logo.png"); got != "logo.png" {
			t.Errorf("adminUploadURL with no base = %q, want the bare key", got)
		}
	})

	t.Run("no file part is the reference's own 400", func(t *testing.T) {
		_, _, handler := uploadHarness(t, uploadConfig())

		// A body with no part named "file": multer routes a text field to
		// req.body and leaves req.file unset.
		rec := doUpload(handler, http.MethodPost, AdminUploadLogoPath,
			uploadRequest(t, "notfile", "logo.png", []byte("x")))
		uploadAssertError(t, rec, http.StatusBadRequest, "No file uploaded")

		// A request that is not multipart at all ends in the same place.
		req := httptest.NewRequest(http.MethodPost, "/admin"+AdminUploadLogoPath,
			strings.NewReader(`{"file":"logo.png"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		uploadAssertError(t, rec, http.StatusBadRequest, "No file uploaded")
	})

	t.Run("a name that is not an image is refused before a byte is stored", func(t *testing.T) {
		_, store, handler := uploadHarness(t, uploadConfig())
		rec := doUpload(handler, http.MethodPost, AdminUploadLogoPath,
			uploadRequest(t, "file", "payload.html", []byte("<script>")))
		uploadAssertError(t, rec, http.StatusBadRequest, "Only image files are allowed")

		files, _ := store.List(context.Background())
		if len(files) != 0 {
			t.Errorf("the store holds %+v after a refused upload", files)
		}
	})

	t.Run("a body past the limit is refused before a byte is stored", func(t *testing.T) {
		_, store, handler := uploadHarness(t, uploadConfig())
		rec := doUpload(handler, http.MethodPost, AdminUploadLogoPath,
			uploadRequest(t, "file", "big.png", bytes.Repeat([]byte("x"), UploadMaxBytes+1)))
		uploadAssertError(t, rec, http.StatusRequestEntityTooLarge, "File too large")

		files, _ := store.List(context.Background())
		if len(files) != 0 {
			t.Errorf("the store holds %+v after an over-large upload — nothing may be written", files)
		}

		// Exactly the limit is a whole file, as multer's limits.fileSize is.
		rec = doUpload(handler, http.MethodPost, AdminUploadLogoPath,
			uploadRequest(t, "file", "edge.png", bytes.Repeat([]byte("x"), UploadMaxBytes)))
		uploadJSON(t, rec, http.StatusOK)
	})

	t.Run("the listing is filtered, ordered and never null", func(t *testing.T) {
		_, store, handler := uploadHarness(t, uploadConfig())
		ctx := context.Background()

		body := uploadJSON(t, doUpload(handler, http.MethodGet, AdminUploadFilesPath, nil), http.StatusOK)
		files, ok := body["files"].([]any)
		if !ok || len(files) != 0 {
			t.Fatalf("an empty store listed %v, want []", body["files"])
		}

		for _, key := range []string{"b.png", "a.png"} {
			if _, err := store.Put(ctx, key, strings.NewReader("x")); err != nil {
				t.Fatalf("seed %s: %v", key, err)
			}
		}
		// A key the extension filter hides. The reference's readdirSync sees
		// whatever else is in the directory, and this port's store may hold
		// whatever a host put there.
		if _, err := store.Put(ctx, "notes.txt", strings.NewReader("x")); err != nil {
			t.Fatalf("seed notes.txt: %v", err)
		}
		time.Sleep(3 * time.Millisecond)
		if _, err := store.Put(ctx, "c.png", strings.NewReader("xyz")); err != nil {
			t.Fatalf("seed c.png: %v", err)
		}

		body = uploadJSON(t, doUpload(handler, http.MethodGet, AdminUploadFilesPath, nil), http.StatusOK)
		files, _ = body["files"].([]any)
		if len(files) != 3 {
			t.Fatalf("listing = %v, want the three image objects", files)
		}
		first, _ := files[0].(map[string]any)
		if first["name"] != "c.png" || first["size"] != float64(3) {
			t.Errorf("first entry = %v, want the newest object with its size", first)
		}
		for _, key := range []string{"name", "size", "mtime"} {
			if _, ok := first[key]; !ok {
				t.Errorf("entry %v is missing %q", first, key)
			}
		}
		if len(first) != 3 {
			t.Errorf("entry = %v, want exactly name, size and mtime", first)
		}
		if second, _ := files[1].(map[string]any); second["name"] != "a.png" {
			t.Errorf("second entry = %v, want the key-ascending tie-break", second)
		}
	})

	t.Run("delete answers 200, 404 and 400", func(t *testing.T) {
		_, store, handler := uploadHarness(t, uploadConfig())
		ctx := context.Background()
		if _, err := store.Put(ctx, "logo.png", strings.NewReader("x")); err != nil {
			t.Fatalf("seed: %v", err)
		}

		got := uploadJSON(t, doUpload(handler, http.MethodDelete, AdminUploadPath+"/logo.png", nil),
			http.StatusOK)
		if got["success"] != true || len(got) != 1 {
			t.Errorf("body = %v, want {\"success\": true}", got)
		}
		if _, _, err := store.Open(ctx, "logo.png"); err == nil {
			t.Error("the object survived its delete")
		}

		// A repeat delete is the reference's 404, and it is one store call
		// rather than an exists-then-unlink pair.
		uploadAssertError(t, doUpload(handler, http.MethodDelete, AdminUploadPath+"/logo.png", nil),
			http.StatusNotFound, "File not found")

		// The reference's three refusals, each reached the way a caller would
		// have to reach it: a slash and a backslash only survive the router
		// percent-encoded, and a leading dot arrives as itself.
		for _, name := range []string{"%2Fetc%2Fpasswd", "%5Cevil", ".hidden", "..", "%2e%2e%2fescape"} {
			uploadAssertError(t, doUpload(handler, http.MethodDelete, AdminUploadPath+"/"+name, nil),
				http.StatusBadRequest, "Invalid filename")
		}

		// Past those three and still outside the grammar: no such object can
		// exist, so the answer is the 404 the reference's existsSync gives and
		// the store is never asked.
		for _, name := range []string{"my%20logo.png", "C:logo.png", "l%C3%B6go.png"} {
			uploadAssertError(t, doUpload(handler, http.MethodDelete, AdminUploadPath+"/"+name, nil),
				http.StatusNotFound, "File not found")
		}
	})

	t.Run("the store's own failure is a 500 carrying its message", func(t *testing.T) {
		a := newUploadTestAuth(t, false)
		a.service.cfg.Uploads = failingUploadStore{err: errUploadTestStore}
		handler := a.AdminHandler(uploadConfig())

		uploadAssertError(t, doUpload(handler, http.MethodGet, AdminUploadFilesPath, nil),
			http.StatusInternalServerError, errUploadTestStore.Error())
		uploadAssertError(t, doUpload(handler, http.MethodDelete, AdminUploadPath+"/logo.png", nil),
			http.StatusInternalServerError, errUploadTestStore.Error())
		uploadAssertError(t, doUpload(handler, http.MethodPost, AdminUploadLogoPath,
			uploadRequest(t, "file", "logo.png", []byte("x"))),
			http.StatusInternalServerError, errUploadTestStore.Error())
	})
}

// TestAdminUploadRoutesAreNotRegisteredWithoutAStore is the inert half: with no
// Config.Uploads the four routes are not mounted at all, so an anonymous caller
// meets the router's 404 and not the guard's 401. AdminIsAdminFlag is the policy
// precisely so that a registered route would answer 401 and be told apart.
func TestAdminUploadRoutesAreNotRegisteredWithoutAStore(t *testing.T) {
	a := newUploadTestAuth(t, false)
	cfg := uploadConfig()
	cfg.Admin.AccessPolicy = AdminIsAdminFlag()
	handler := a.AdminHandler(cfg)

	for _, route := range []struct {
		method, path string
	}{
		{http.MethodPost, AdminUploadLogoPath},
		{http.MethodPost, AdminUploadBGImagePath},
		{http.MethodGet, AdminUploadFilesPath},
		{http.MethodDelete, AdminUploadPath + "/logo.png"},
	} {
		rec := doUpload(handler, route.method, route.path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d with no upload store, want 404", route.method, route.path, rec.Code)
		}
	}

	// And the console says so, so the SPA draws no file picker.
	if a.adminFeatures(cfg).Upload {
		t.Error("features.upload is true with no upload store")
	}
	withStore := newUploadTestAuth(t, true)
	if !withStore.adminFeatures(cfg).Upload {
		t.Error("features.upload is false with an upload store configured")
	}
}

// TestAdminUploadUnroutedMethods pins the layer ordering matchAdminUpload
// describes: the two paths that fall to the :filename layer because the fixed
// registrations above them are registered for other methods, and the ones with
// no layer at all.
func TestAdminUploadUnroutedMethods(t *testing.T) {
	_, store, handler := uploadHarness(t, uploadConfig())
	if _, err := store.Put(context.Background(), "files", strings.NewReader("x")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// DELETE /api/upload/files is a delete of an object called "files".
	if got := uploadJSON(t, doUpload(handler, http.MethodDelete, AdminUploadFilesPath, nil),
		http.StatusOK); got["success"] != true {
		t.Errorf("DELETE %s = %v, want the :filename layer", AdminUploadFilesPath, got)
	}

	for _, route := range []struct {
		method, path string
	}{
		{http.MethodGet, AdminUploadLogoPath},
		{http.MethodPost, AdminUploadFilesPath},
		{http.MethodPut, AdminUploadLogoPath},
		{http.MethodDelete, AdminUploadPath},
		{http.MethodDelete, AdminUploadPath + "/a/b"},
		{http.MethodPost, AdminUploadPath + "/logo.png"},
	} {
		if rec := doUpload(handler, route.method, route.path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404: the reference registers no layer for it",
				route.method, route.path, rec.Code)
		}
	}
}

// TestUIServesTheUploadStore is the composition UIOptions.Uploads promises: one
// configured store, and the UI's two asset mounts serve what the admin routes
// wrote — with an explicit fs.FS still winning.
func TestUIServesTheUploadStore(t *testing.T) {
	a := newUploadTestAuth(t, true)
	if _, err := a.service.cfg.Uploads.Put(context.Background(), "logo.png",
		strings.NewReader("pixels")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := DefaultHTTPConfig()
	cfg.UI.Enabled = true
	handler := a.UIHandler(cfg, nil)

	for _, mount := range []string{"/assets/logo/", "/assets/uploads/"} {
		target := cfg.Prefix() + UIRoute + mount + "logo.png"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "pixels" {
			t.Errorf("GET %s = %d %q, want the stored object", target, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
			t.Errorf("GET %s served Content-Type %q", target, ct)
		}
	}

	// A traversal under the upload prefix misses and falls through to the SSR
	// catch-all, exactly as it did against an os.DirFS.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		cfg.Prefix()+UIRoute+"/assets/uploads/../../../secret", nil))
	if rec.Body.String() == "pixels" {
		t.Error("a traversal under the upload prefix reached the store")
	}

	// UIOptions.Uploads wins: the store is not consulted at all.
	cfg.UI.Uploads = fstest.MapFS{}
	handler = a.UIHandler(cfg, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		cfg.Prefix()+UIRoute+"/assets/uploads/logo.png", nil))
	if rec.Body.String() == "pixels" {
		t.Error("an explicit UIOptions.Uploads must win over the upload store")
	}
}

// ── the harness ──────────────────────────────────────────────────────────────

// errUploadTestStore is what the broken-store cases fail with, and its message
// is what the three 500s must carry.
var errUploadTestStore = errors.New("upload store is unavailable")

// uploadConfig is the wire configuration the upload cases mount: the console
// open, so that a case asserting on a body is not also asserting on the guard.
func uploadConfig() HTTPConfig {
	cfg := DefaultHTTPConfig()
	cfg.APIPrefix = "/auth"
	cfg.Admin = AdminOptions{Enabled: true, AccessPolicy: AdminOpen()}
	return cfg
}

// newUploadTestAuth builds an Auth with or without an upload store, its clock
// frozen at uploadTestTime so that every generated key is the one the tables
// above spell out.
func newUploadTestAuth(t *testing.T, withStore bool) *Auth {
	t.Helper()
	opts := []Option{WithUserStore(NewMemoryUserStore()), WithSessionStore(NewMemorySessionStore())}
	if withStore {
		opts = append(opts, WithUploadStore(NewMemoryUploadStore()))
	}
	a, err := New(opts...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	a.service.now = func() time.Time { return uploadTestTime }
	return a
}

func uploadHarness(t *testing.T, cfg HTTPConfig) (*Auth, UploadStore, http.Handler) {
	t.Helper()
	a := newUploadTestAuth(t, true)
	return a, a.service.cfg.Uploads, a.AdminHandler(cfg)
}

// uploadRequest builds a multipart body with one file part.
type uploadPayload struct {
	contentType string
	body        []byte
}

func uploadRequest(t *testing.T, field, filename string, content []byte) *uploadPayload {
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
		t.Fatalf("close writer: %v", err)
	}
	return &uploadPayload{contentType: writer.FormDataContentType(), body: buf.Bytes()}
}

func doUpload(handler http.Handler, method, route string, payload *uploadPayload) *httptest.ResponseRecorder {
	var body io.Reader = strings.NewReader("")
	if payload != nil {
		body = bytes.NewReader(payload.body)
	}
	req := httptest.NewRequest(method, "/admin"+route, body)
	if payload != nil {
		req.Header.Set("Content-Type", payload.contentType)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func uploadJSON(t *testing.T, rec *httptest.ResponseRecorder, want int) map[string]any {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, want, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

// uploadAssertError pins the admin router's own envelope: {"error": "…"} and
// nothing beside it.
func uploadAssertError(t *testing.T, rec *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	body := uploadJSON(t, rec, status)
	if body["error"] != message {
		t.Errorf("error = %v, want %q", body["error"], message)
	}
	if len(body) != 1 {
		t.Errorf("body = %v, want the {\"error\": …} envelope alone", body)
	}
}
