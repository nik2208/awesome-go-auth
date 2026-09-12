package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// The upload seam: the key grammar, the memory implementation and the fs.FS
// view the UI reads through.
//
// The four routes that use it are pinned once for all four adapters in
// adapter/internal/wiretest/admin.go; what is here is the seam itself, which no
// adapter suite can reach.

// TestValidUploadKey is the traversal argument stated as a table. Every entry
// below that is refused is refused by the *grammar* and not by a check for the
// thing it was trying to do, which is what makes filepath.Join(root, key) one
// element below root rather than probably one element below root.
func TestValidUploadKey(t *testing.T) {
	valid := []string{
		"logo_1700000000000.png",
		"a",
		"A-Z_a-z.0-9",
		"_leading-underscore.svg",
		"trailing-dot.",
		strings.Repeat("k", MaxUploadKeyLen),
	}
	for _, key := range valid {
		if !ValidUploadKey(key) {
			t.Errorf("ValidUploadKey(%q) = false, want true", key)
		}
	}

	invalid := map[string]string{
		"":                                     "empty",
		".":                                    "the current directory",
		"..":                                   "the parent directory",
		".hidden.png":                          "a leading dot, which is the reference's own third refusal",
		"../escape.png":                        "a relative path",
		"a/b.png":                              "a separator, so a key is always one path element",
		`a\b.png`:                              "a Windows separator, refused on every platform and not only on Windows",
		"C:logo.png":                           "a colon, so no drive-relative path and no NTFS stream",
		"logo .png":                            "a space, which no generated key can contain",
		"lögo.png":                             "a non-ASCII byte, so no normalisation turns two keys into one",
		"logo%2fescape.png":                    "a percent, because a key is never decoded a second time",
		strings.Repeat("k", MaxUploadKeyLen+1): "longer than MaxUploadKeyLen",
	}
	for key, why := range invalid {
		if ValidUploadKey(key) {
			t.Errorf("ValidUploadKey(%q) = true, want false — %s", key, why)
		}
	}

	// The grammar implies fs.ValidPath, which is what lets UploadFS hand a key
	// straight to an fs.FS consumer.
	for _, key := range valid {
		if !fs.ValidPath(key) {
			t.Errorf("ValidUploadKey admits %q, which is not a valid fs.FS name", key)
		}
	}
}

// TestUploadNameAllowed is the reference's fileFilter regexp
// (admin.router.ts:1020), including the two shapes that read like mistakes and
// are not: the match is case-insensitive and it is a suffix match on the whole
// name, so a directory component ending in ".png" is not enough and a name that
// is nothing but an extension is.
func TestUploadNameAllowed(t *testing.T) {
	allowed := []string{
		"logo.png", "logo.PNG", "photo.jpg", "photo.jpeg", "anim.gif",
		"mark.svg", "shot.webp", "favicon.ico", ".png", "a.b.c.png",
	}
	for _, name := range allowed {
		if !UploadNameAllowed(name) {
			t.Errorf("UploadNameAllowed(%q) = false, want true", name)
		}
	}
	refused := []string{
		"", "logo", "logo.png.txt", "logo.pngx", "logo.png ", "png",
		"evil.svg.js", "archive.zip", "doc.pdf",
	}
	for _, name := range refused {
		if UploadNameAllowed(name) {
			t.Errorf("UploadNameAllowed(%q) = true, want false", name)
		}
	}
}

// TestUploadContentType pins the table an object store's implementor writes
// alongside its PutObject. ".ico" is the reason it is a table and not
// mime.TypeByExtension: Go's built-in map has no entry for it, so that function
// answers differently depending on which mime.types the host image ships.
func TestUploadContentType(t *testing.T) {
	for key, want := range map[string]string{
		"a.png":  "image/png",
		"a.jpg":  "image/jpeg",
		"a.JPEG": "image/jpeg",
		"a.gif":  "image/gif",
		"a.svg":  "image/svg+xml",
		"a.webp": "image/webp",
		"a.ico":  "image/x-icon",
		"a.txt":  "",
		"a":      "",
		"a.":     "",
	} {
		if got := UploadContentType(key); got != want {
			t.Errorf("UploadContentType(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestMemoryUploadStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUploadStore()

	info, err := store.Put(ctx, "logo.png", strings.NewReader("first"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if info.Name != "logo.png" || info.Size != 5 {
		t.Errorf("Put returned %+v, want the key and the byte count", info)
	}

	rc, got, err := store.Open(ctx, "logo.png")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(body) != "first" || got.Size != 5 {
		t.Errorf("Open returned %q / %+v, want the stored bytes", body, got)
	}

	// Put replaces, which is what the reference's write stream does when two
	// uploads land on one key — and what makes adminUploadKey's
	// same-filename-same-millisecond collision a replacement rather than an
	// error. See adminUploadKey.
	if _, err := store.Put(ctx, "logo.png", strings.NewReader("second")); err != nil {
		t.Fatalf("Put again: %v", err)
	}
	rc, _, err = store.Open(ctx, "logo.png")
	if err != nil {
		t.Fatalf("Open after replace: %v", err)
	}
	body, _ = io.ReadAll(rc)
	_ = rc.Close()
	if string(body) != "second" {
		t.Errorf("after a second Put the object is %q, want the second body", body)
	}

	if _, _, err := store.Open(ctx, "absent.png"); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("Open of an absent key = %v, want ErrUploadNotFound", err)
	}
	if err := store.Delete(ctx, "absent.png"); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("Delete of an absent key = %v, want ErrUploadNotFound", err)
	}
	if err := store.Delete(ctx, "logo.png"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := store.Open(ctx, "logo.png"); !errors.Is(err, ErrUploadNotFound) {
		t.Errorf("the deleted object is still readable: %v", err)
	}

	// A key outside the grammar is refused rather than stored, so a host that
	// calls the store directly cannot put something the routes could never
	// address or delete.
	if _, err := store.Put(ctx, "../escape.png", strings.NewReader("x")); err == nil {
		t.Error("Put accepted a key outside the grammar")
	}
}

// TestMemoryUploadStoreListOrder pins the order UploadStore.List documents:
// newest first, ties broken by key ascending. The tie-break is the half the
// reference does not have — its comparator returns 0 for two files stamped the
// same second and readdir order decides — and it is what makes a listing
// reproducible.
func TestMemoryUploadStoreListOrder(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUploadStore()
	for _, key := range []string{"b.png", "a.png"} {
		if _, err := store.Put(ctx, key, strings.NewReader("x")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	// A measurable gap, so that "newest first" is decided by the clock and not
	// by the tie-break below it.
	time.Sleep(3 * time.Millisecond)
	if _, err := store.Put(ctx, "c.png", strings.NewReader("x")); err != nil {
		t.Fatalf("Put c.png: %v", err)
	}

	files, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(files) != 3 || files[0].Name != "c.png" {
		t.Fatalf("List = %+v, want the newest object first", files)
	}
	if files[1].Name != "a.png" || files[2].Name != "b.png" {
		t.Errorf("List = %+v, want the two same-instant objects in key order", files)
	}
}

// TestUploadFS is the composition UIOptions.Uploads documents: one configured
// store, read back through the seam the UI already had.
func TestUploadFS(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUploadStore()
	if _, err := store.Put(ctx, "logo.png", strings.NewReader("bytes")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	fsys := UploadFS(store)

	data, err := fs.ReadFile(fsys, "logo.png")
	if err != nil || string(data) != "bytes" {
		t.Fatalf("ReadFile = %q, %v; want the stored bytes", data, err)
	}

	info, err := fs.Stat(fsys, "logo.png")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Error("a stored object must stat as a regular file, or uiServeStatic treats it as a miss")
	}
	if info.Size() != 5 || info.Name() != "logo.png" {
		t.Errorf("Stat = %+v, want the key and the size", info)
	}

	// MemoryUploadStore hands back a seekable reader, so the UI can serve a
	// Range over a stored object without buffering it.
	f, err := fsys.Open("logo.png")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seeker, ok := f.(io.ReadSeeker)
	if !ok {
		t.Fatal("the file is not an io.ReadSeeker, so every Range read buffers the object")
	}
	if _, err := seeker.Seek(2, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	rest, _ := io.ReadAll(seeker)
	if string(rest) != "tes" {
		t.Errorf("after Seek(2) the reader gave %q, want %q", rest, "tes")
	}
	_ = f.Close()

	// Every name outside the grammar misses here rather than reaching the
	// store, which is what keeps the UI's fall-through unchanged: a traversal
	// attempt under the upload prefix ends at the same 404 it ended at against
	// an os.DirFS.
	for _, name := range []string{"absent.png", "../escape", "sub/logo.png", ".hidden"} {
		if _, err := fsys.Open(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open(%q) = %v, want fs.ErrNotExist", name, err)
		}
	}

	// No store is no filesystem, which is how UIHandler leaves both asset
	// mounts unregistered.
	if UploadFS(nil) != nil {
		t.Error("UploadFS(nil) must be nil, or the UI mounts an empty upload prefix")
	}
}

// TestUploadFSSurfacesStoreErrors pins that a store failure is not silently a
// miss: a 404 for an object that exists and could not be read would send the UI
// on to its SSR fallback and render a login page where an image was asked for.
func TestUploadFSSurfacesStoreErrors(t *testing.T) {
	boom := errors.New("s3: throttled")
	fsys := UploadFS(failingUploadStore{err: boom})
	_, err := fsys.Open("logo.png")
	if !errors.Is(err, boom) {
		t.Errorf("Open = %v, want the store's own error", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Error("a store failure must not read as fs.ErrNotExist")
	}
}

// failingUploadStore is an UploadStore whose every method fails, for the two
// cases that need a store that is configured and broken.
type failingUploadStore struct{ err error }

func (s failingUploadStore) Put(context.Context, string, io.Reader) (UploadedFile, error) {
	return UploadedFile{}, s.err
}

func (s failingUploadStore) List(context.Context) ([]UploadedFile, error) { return nil, s.err }

func (s failingUploadStore) Open(context.Context, string) (io.ReadCloser, UploadedFile, error) {
	return nil, UploadedFile{}, s.err
}

func (s failingUploadStore) Delete(context.Context, string) error { return s.err }

// TestSortUploadedFiles pins the comparator on its own, because the listing
// route applies it to whatever a host's store returned rather than trusting the
// order the interface asks for.
func TestSortUploadedFiles(t *testing.T) {
	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	files := []UploadedFile{
		{Name: "b.png", ModTime: older},
		{Name: "z.png", ModTime: newer},
		{Name: "a.png", ModTime: older},
	}
	SortUploadedFiles(files)
	got := []string{files[0].Name, files[1].Name, files[2].Name}
	want := []string{"z.png", "a.png", "b.png"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SortUploadedFiles = %v, want %v", got, want)
		}
	}
}

// TestUploadLimitedReader is the difference between multer's limits.fileSize and
// io.LimitReader: exactly the limit is a whole file, one byte more is a refusal,
// and neither is a silently truncated object.
func TestUploadLimitedReader(t *testing.T) {
	read := func(body string, limit int64) ([]byte, error) {
		return io.ReadAll(&uploadLimitedReader{r: strings.NewReader(body), remaining: limit})
	}

	if got, err := read("12345", 5); err != nil || string(got) != "12345" {
		t.Errorf("a body of exactly the limit gave %q, %v; want it whole", got, err)
	}
	if got, err := read("1234", 5); err != nil || string(got) != "1234" {
		t.Errorf("a short body gave %q, %v; want it whole", got, err)
	}
	if _, err := read("123456", 5); !errors.Is(err, errUploadTooLarge) {
		t.Errorf("a body past the limit = %v, want errUploadTooLarge", err)
	}
	if _, err := read("", 0); err != nil {
		t.Errorf("an empty body at a zero limit = %v, want no error", err)
	}

	// The underlying reader's own failure is reported as itself, so a client
	// that hung up mid-body is not reported as one that sent too much.
	boom := errors.New("connection reset")
	_, err := io.ReadAll(&uploadLimitedReader{
		r:         io.MultiReader(bytes.NewReader([]byte("12")), errReader{boom}),
		remaining: UploadMaxBytes,
	})
	if !errors.Is(err, boom) {
		t.Errorf("a mid-body failure = %v, want the reader's own error", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
