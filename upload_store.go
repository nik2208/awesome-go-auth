package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file is the upload seam: the store the admin console's four upload
// routes write through, and the read side the built-in UI serves back.
//
// The reference has no such seam. Its admin router is handed `uploadDir`, a
// path on a local filesystem, and it writes to it with multer's disk storage
// and reads it back with fs.readdirSync and fs.statSync
// (admin.router.ts:991-1085); the UI router mounts express.static over the same
// directory twice, at /assets/logo and /assets/uploads (ui.router.ts:185-191).
// Two processes sharing that directory is the reference's scaling story and a
// mounted volume is its persistence story.
//
// That shape does not survive into every host this library serves. The product
// downstream is a Lambda whose only writable path is a per-execution-environment
// /tmp: writable, but private to one execution environment, emptied without
// warning, and invisible to the next cold start — so a logo an administrator
// uploads is served back by the environment that took it and by no other. A
// directory is therefore not a portable answer, and the port takes the same
// route it took for every other piece of state: an interface, an in-memory
// implementation for tests and single-process deployments, and the real one —
// S3, GCS, a blob column — supplied by the host.
//
// # What the four operations are
//
// Put, List, Delete and Open. The first three are the three upload routes that
// mutate or enumerate; Open is the read-back, and it exists because the read
// side already had a consumer before this store did. UIOptions.Uploads is an
// fs.FS that v0.9.0 added as a read-only seam, and UploadFS below turns any
// UploadStore into exactly that — so a host configures one thing and both the
// admin routes and the UI's two asset mounts work. See UploadFS.
//
// # What a key is
//
// One path segment, drawn from a grammar narrow enough that no key can name
// anything but an object in the store: see ValidUploadKey. The admin upload
// routes never take a key from a caller — they derive one from the client's
// filename through the reference's own sanitiser (adminUploadKey, admin_upload.go)
// — and the one route that is handed a name checks it against this grammar
// before the store ever sees it.

// ErrUploadNotFound is what Open and Delete report for a key the store does not
// hold. It is a sentinel rather than a bare error so that DELETE
// <admin>/api/upload/:filename can answer the reference's 404 for an absent
// object and its 500 for a store that failed, which is a distinction the
// reference draws with fs.existsSync before it calls fs.unlinkSync
// (admin.router.ts:1074-1080).
//
// Drawing it with one store call instead of two is deliberate: the reference's
// exists-then-unlink pair races with a second administrator deleting the same
// file, and answering 500 for that race would be worse than answering 404 for
// it.
var ErrUploadNotFound = errors.New("auth: uploaded file not found")

// MaxUploadKeyLen bounds a key. The keys the admin routes generate are at most
// 59 bytes — forty of sanitised name, an underscore, thirteen of millisecond
// timestamp, a dot and four of extension — and the rest of the budget is for a
// host that puts objects in the store itself.
//
// It is a byte count and the grammar is ASCII, so it is also a character count
// and a safe column width.
const MaxUploadKeyLen = 128

// UploadMaxBytes is the largest file the admin upload routes accept, and it is
// the reference's multer `limits: { fileSize: 5 * 1024 * 1024 }`
// (admin.router.ts:1016).
//
// It bounds the route rather than the store: Put is handed a reader the route
// has already held to this, so an implementation may stream its argument
// without a limit of its own. A host calling Put directly is responsible for
// its own bound, because nothing else is.
const UploadMaxBytes = 5 << 20

// UploadedFile is one stored object as the listing route reports it, and as
// Open and Put hand it back: the reference's
// `{ name, size, mtime: stat.mtime.toISOString() }` (admin.router.ts:1051-1055).
//
// The JSON tags are that object's three keys, because this struct is what GET
// <admin>/api/upload/files serialises. mtime is written by encoding/json's
// RFC 3339 rather than by JavaScript's toISOString, so it carries no fixed
// three-digit fraction — the same treatment every other timestamp on the admin
// API already gets (adminUserRow.CreatedAt).
type UploadedFile struct {
	// Name is the key. The field is called name because the reference's key is
	// called name, and a client reading this listing reads that.
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
}

// UploadStore is where uploaded assets live: the seam over the reference's
// uploadDir. It is optional, and leaving it nil is not a degraded mode — it is
// the deployment that has no upload feature at all. The four upload routes are
// then not registered, the way GET <admin>/api/templates/* is registered only
// with a TemplateStore, and adminFeatures reports upload false so the console
// draws no file picker.
//
// # Keys
//
// Every key passed to any method must satisfy ValidUploadKey, and an
// implementation may assume it does — every call this package makes is checked
// first. An implementation that is also called directly by its host should
// check too, because that grammar is the only thing standing between a key and
// the storage namespace behind it: see ValidUploadKey for why checking for
// "../" is the wrong shape of defence.
//
// # Put
//
// Put stores content under key, replacing whatever was there. It must read
// content to EOF, and it must leave nothing behind if content returns an error
// — a half-written object under a key a listing will report is worse than a
// failed upload, and a store that cannot write atomically should write to a
// temporary key and rename, or delete what it wrote before returning. The
// returned UploadedFile describes what is now stored.
//
// content is bounded at UploadMaxBytes by the route that calls it, and the
// reader the route passes is an *bytes.Reader — so an implementation that wants
// a length or a checksum before it writes can type-assert io.Seeker rather than
// buffer a second copy.
//
// # List
//
// List returns every object the store holds, newest first, ties broken by key
// ascending. That order is part of the interface so a caller can rely on it
// without sorting, and it is total so that two stores holding the same objects
// answer alike.
//
// The listing route re-applies the same order over the result anyway. That is
// not distrust of a particular implementation: the reference's route sorts what
// readdirSync handed it (admin.router.ts:1057) because readdir order is the
// filesystem's business, and a wire contract that holds only while every host's
// store is diligent is not a wire contract.
//
// # Open
//
// Open reads one object back, for the UI's asset mounts and for anything else
// that wants the bytes. It returns ErrUploadNotFound for a key the store does
// not hold, and the caller closes the reader. Returning an io.ReadSeeker where
// that is cheap lets the UI serve Range requests without buffering; see
// UploadFS.
//
// # Delete
//
// Delete removes one object and returns ErrUploadNotFound if there was none.
//
// # Concurrency
//
// Every method may be called concurrently.
type UploadStore interface {
	Put(ctx context.Context, key string, content io.Reader) (UploadedFile, error)
	List(ctx context.Context) ([]UploadedFile, error)
	Open(ctx context.Context, key string) (io.ReadCloser, UploadedFile, error)
	Delete(ctx context.Context, key string) error
}

// ValidUploadKey reports whether key names an object: non-empty, at most
// MaxUploadKeyLen bytes, made only of ASCII letters, digits, '.', '_' and '-',
// and not beginning with '.'.
//
// # Why this shape, and not a traversal check
//
// The reference's delete route defends by inspection: it refuses a filename
// containing '/' or '\' or beginning with '.', then calls path.join(uploadDir,
// filename) (admin.router.ts:1067-1073). That check happens to be sufficient
// for its own three cases, and it is the wrong shape of defence anyway, because
// it enumerates what a caller must not send. This grammar enumerates what a key
// may be, and the difference is that traversal stops being something to catch:
//
//   - No key contains '/' or '\', so a key is exactly one path element under
//     any root, on every operating system. There is no separator to build a
//     second element out of.
//   - No key begins with '.', so no key is "." or "..", the only two names that
//     move a path upwards without a separator.
//   - No key contains ':', so a key cannot name a Windows drive or an NTFS
//     alternate data stream, and no key is a URL scheme or an S3 endpoint.
//   - Every byte is ASCII, so no key survives a Unicode normalisation or an
//     overlong-encoding round trip as a different key.
//
// filepath.Join(root, key) is therefore root plus one element, and
// strings.TrimSuffix(prefix, "/") + "/" + key is one object below the prefix,
// by construction rather than by check. A future implementation that resolves a
// key against something else — a database row, a URL — inherits the same
// property, which is the reason the rule lives on the seam and not in the one
// route that reads a name off the wire.
//
// It implies fs.ValidPath, so a key is always a legal fs.FS name too.
//
// # What it does not settle
//
// Two things an implementation still owns. A filesystem-backed store on Windows
// must refuse the reserved device names — "NUL.png" satisfies this grammar and
// opens the null device — and any store must decide whether its namespace is
// case-sensitive, because "Logo.png" and "logo.png" are two keys here and one
// file on a case-insensitive volume.
func ValidUploadKey(key string) bool {
	if key == "" || len(key) > MaxUploadKeyLen || key[0] == '.' {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// UploadNameAllowed is the reference's multer fileFilter
// (admin.router.ts:1018-1022): the client-supplied filename must end in one of
// seven image extensions, compared case-insensitively.
//
// It tests the name and nothing else — no magic bytes, no declared
// Content-Type — which is the reference's rule and is reproduced rather than
// improved on. The consequences are worth stating where a host will meet them,
// because both are served back from the auth origin:
//
//   - A file named "logo.png" holding HTML is stored and served as image/png.
//     A browser will not render it as a document at that type, but a host that
//     serves the upload prefix without X-Content-Type-Options: nosniff is
//     relying on the type header alone.
//   - An SVG is an XML document that may carry script, and it is on this list.
//     Served same-origin it runs with the auth cookies. The upload routes are
//     behind the admin guard, so the author is an administrator — but a host
//     that would rather not take that trade serves the upload prefix from a
//     separate origin, or behind a Content-Security-Policy, or drops "svg" by
//     wrapping the store. Dropping it here would be a different product from
//     the reference and would break a console that offers it.
func UploadNameAllowed(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range uploadAllowedExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// uploadAllowedExtensions is the alternation of the reference's fileFilter
// regexp, in its order (admin.router.ts:1020).
var uploadAllowedExtensions = [...]string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"}

// UploadContentType is the media type for a key's extension, or "" for an
// extension that is not one of the seven.
//
// Nothing in this package needs it: the UI serves an object through
// http.ServeContent, which types it from the same extension. It is exported for
// the store implementations a host writes, because an object store records a
// content type at write time and serves it forever after — an S3 PutObject
// without ContentType serves binary/octet-stream, and a browser will not paint
// a logo it is handed under that type.
//
// The table is written out rather than taken from mime.TypeByExtension because
// that function reads the system's mime.types on unix: ".ico" is absent from
// Go's built-in table, so the answer for it would depend on which files the
// host image happens to ship.
func UploadContentType(key string) string {
	switch strings.ToLower(path.Ext(key)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	default:
		return ""
	}
}

// ── the read side, as an fs.FS ───────────────────────────────────────────────

// UploadFS presents an UploadStore as the read-only fs.FS UIOptions.Uploads is,
// so that one configured store serves both halves of the reference's
// arrangement: the admin routes write through the store, and the UI's
// <prefix>/ui/assets/logo/ and <prefix>/ui/assets/uploads/ mounts read the same
// objects back (ui.router.ts:185-191).
//
// A host does not normally call this. UIHandler falls back to it when
// UIOptions.Uploads is nil and an UploadStore is configured, which is what makes
// "configure an UploadStore" enough — see UIOptions.Uploads for the precedence.
// It is exported for the host that wants the read side somewhere else: its own
// static mount, an http.FileServer, an fs.WalkDir over what has accumulated.
//
// # What it does with names
//
// A name that is not a valid key does not reach the store: Open answers
// fs.ErrNotExist for it. So the UI's fall-through behaviour is unchanged — a
// request for "../../secrets" under the upload prefix misses here exactly as it
// missed against an os.DirFS, and ends at the same 404 — and the store is never
// asked to defend a name this package could have refused.
//
// # What it cannot do
//
// fs.FS.Open takes no context, so the store is called with
// context.Background(): there is no request deadline and no cancellation on a
// client that hung up. A store whose reads can block indefinitely should carry
// its own timeout, and a host that needs per-request cancellation on the read
// path sets UIOptions.Uploads to its own fs.FS instead of relying on this.
//
// The returned file implements io.Seeker only when the store's reader does.
// Without one the UI reads the object into memory before serving it, which is
// bounded by UploadMaxBytes for anything these routes wrote.
func UploadFS(store UploadStore) fs.FS {
	if store == nil {
		return nil
	}
	return uploadFS{store: store}
}

type uploadFS struct{ store UploadStore }

func (u uploadFS) Open(name string) (fs.File, error) {
	if !ValidUploadKey(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	rc, info, err := u.store.Open(context.Background(), name)
	if err != nil {
		if errors.Is(err, ErrUploadNotFound) {
			err = fs.ErrNotExist
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if seeker, ok := rc.(io.ReadSeekCloser); ok {
		return uploadSeekableFile{uploadFile{rc: rc, info: info}, seeker}, nil
	}
	return uploadFile{rc: rc, info: info}, nil
}

type uploadFile struct {
	rc   io.ReadCloser
	info UploadedFile
}

func (f uploadFile) Stat() (fs.FileInfo, error) { return uploadFileInfo{f.info}, nil }
func (f uploadFile) Read(p []byte) (int, error) { return f.rc.Read(p) }
func (f uploadFile) Close() error               { return f.rc.Close() }

// uploadSeekableFile carries a store reader's own Seek through to the UI, so a
// Range request over a stored object is served without buffering it.
type uploadSeekableFile struct {
	uploadFile
	seeker io.Seeker
}

func (f uploadSeekableFile) Seek(offset int64, whence int) (int64, error) {
	return f.seeker.Seek(offset, whence)
}

// uploadFileInfo is UploadedFile as an fs.FileInfo. The mode is a read-only
// regular file, and regular is the part that matters: uiServeStatic refuses
// anything that is not, which is how a directory in an asset filesystem becomes
// a miss rather than a 500.
type uploadFileInfo struct{ file UploadedFile }

func (i uploadFileInfo) Name() string       { return i.file.Name }
func (i uploadFileInfo) Size() int64        { return i.file.Size }
func (i uploadFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i uploadFileInfo) ModTime() time.Time { return i.file.ModTime }
func (i uploadFileInfo) IsDir() bool        { return false }
func (i uploadFileInfo) Sys() any           { return nil }

// ── the in-memory implementation ─────────────────────────────────────────────

// MemoryUploadStore is the in-process UploadStore, safe for concurrent use. It
// is the counterpart of every other Memory*Store in this package: what the
// tests run against, what an example wires, and what a single-process
// deployment that does not mind losing its logos on restart can ship.
//
// It holds every object in memory, so it is bounded by what is uploaded through
// it — UploadMaxBytes per object and no cap on the count. A deployment that
// leaves the console open to an administrator with a large disk should give it
// a real store rather than this one.
//
// It is not the default. A nil Config.Uploads is a deployment with no upload
// feature, and defaulting to this one would turn that into a feature that
// silently forgets — which is the exact failure the Lambda /tmp shape has and
// the reason this seam exists.
type MemoryUploadStore struct {
	mu    sync.RWMutex
	files map[string]memoryUpload
}

type memoryUpload struct {
	data    []byte
	modTime time.Time
}

// NewMemoryUploadStore returns an empty MemoryUploadStore.
func NewMemoryUploadStore() *MemoryUploadStore {
	return &MemoryUploadStore{files: make(map[string]memoryUpload)}
}

// Put reads content whole and stores it under key, replacing any object already
// there. A read error stores nothing, which is the contract UploadStore.Put
// states: the buffer is only published once it is complete.
func (s *MemoryUploadStore) Put(_ context.Context, key string, content io.Reader) (UploadedFile, error) {
	if !ValidUploadKey(key) {
		return UploadedFile{}, errors.New("auth: invalid upload key")
	}
	data, err := io.ReadAll(content)
	if err != nil {
		return UploadedFile{}, err
	}
	entry := memoryUpload{data: data, modTime: time.Now()}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[key] = entry
	return UploadedFile{Name: key, Size: int64(len(entry.data)), ModTime: entry.modTime}, nil
}

// List returns every stored object, newest first with ties broken by key
// ascending, which is the order UploadStore documents.
func (s *MemoryUploadStore) List(_ context.Context) ([]UploadedFile, error) {
	s.mu.RLock()
	out := make([]UploadedFile, 0, len(s.files))
	for key, entry := range s.files {
		out = append(out, UploadedFile{Name: key, Size: int64(len(entry.data)), ModTime: entry.modTime})
	}
	s.mu.RUnlock()

	SortUploadedFiles(out)
	return out, nil
}

// Open returns a reader over the stored bytes. The reader is a *bytes.Reader
// over the stored slice rather than a copy of it, which is safe because nothing
// mutates a stored slice: Put replaces the entry wholesale.
func (s *MemoryUploadStore) Open(_ context.Context, key string) (io.ReadCloser, UploadedFile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.files[key]
	if !ok {
		return nil, UploadedFile{}, ErrUploadNotFound
	}
	info := UploadedFile{Name: key, Size: int64(len(entry.data)), ModTime: entry.modTime}
	return bytesReadSeekCloser{bytes.NewReader(entry.data)}, info, nil
}

// bytesReadSeekCloser is a *bytes.Reader with a no-op Close, so that
// MemoryUploadStore.Open hands back a seekable reader and the UI can serve a
// Range over a stored object without buffering it. See UploadFS.
type bytesReadSeekCloser struct{ *bytes.Reader }

func (bytesReadSeekCloser) Close() error { return nil }

// Delete removes one object, reporting ErrUploadNotFound if there was none.
func (s *MemoryUploadStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[key]; !ok {
		return ErrUploadNotFound
	}
	delete(s.files, key)
	return nil
}

// SortUploadedFiles applies the listing order UploadStore.List documents and GET
// <admin>/api/upload/files answers with: newest first, ties broken by key
// ascending.
//
// The first half is the reference's `sort((a, b) => b.mtime.localeCompare(a.mtime))`
// over ISO-8601 strings (admin.router.ts:1057), which orders by time because
// that encoding sorts lexicographically. The second half the reference does not
// have: its comparator returns 0 for two files stamped the same second and
// Array.prototype.sort is stable, so equal timestamps come back in readdir
// order — the filesystem's, and not a contract. A total order is, and it is what
// lets a test and a paginating client see the same page twice.
//
// It is exported because a store implementing List has to produce this order and
// should not have to re-derive it.
func SortUploadedFiles(files []UploadedFile) {
	sort.SliceStable(files, func(i, j int) bool {
		if !files[i].ModTime.Equal(files[j].ModTime) {
			return files[i].ModTime.After(files[j].ModTime)
		}
		return files[i].Name < files[j].Name
	})
}
