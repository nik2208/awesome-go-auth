package auth

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// The upload half of the admin API: four routes that write, enumerate and
// remove the assets an administrator uploads for the built-in UI's branding
// (admin.router.ts:989-1085).
//
// M8 is split by class of risk rather than by route count, and this file is the
// only one in it that parses a multipart body and the only one that writes
// somewhere other than a store this package already had. Both are the reason it
// stands alone: everything below is either the reference's multer configuration
// turned into explicit bounds, or the seam that replaces its uploadDir.
//
// # Registered only with a store
//
// All four sit inside `if (options.uploadDir)` there (:991), so a deployment
// with no upload directory has no such routes rather than guarded ones — a
// plain 404 from the router and not a 401. Config.Uploads is this port's
// counterpart and adminUploadRegistered is where that is asked, in AdminHandler
// and before the guard, exactly as the two template routes are asked (U13).
//
// Unconfigured is therefore inert: nothing is written, nothing is listed, and
// nothing answers. That is also why there is no default store. A
// MemoryUploadStore default would turn "this deployment has no uploads" into
// "this deployment forgets its uploads on restart", which is the precise failure
// the seam exists to avoid — see UploadStore.
//
// # What replaces multer
//
// Nothing, in the sense that there is nothing to replace: the dependency rule
// is stdlib plus golang.org/x/crypto, and mime/multipart is stdlib. The parts
// are read as a stream with (*http.Request).MultipartReader rather than through
// ParseMultipartForm, so no temporary file is ever created — which matters for
// the same host multer's disk storage fails on.
//
// What multer's configuration *is*, in this port, is four explicit rules, each
// with a citation and each enforced before the store is touched:
//
//   - one part, named "file", carrying a filename (upload.single('file'), :1024)
//   - whose name ends in one of seven image extensions (fileFilter, :1018-1022)
//   - whose body is at most UploadMaxBytes (limits.fileSize, :1016)
//   - stored under a key this package derives, never one the client chose
//     (the filename callback, :1005-1013)
//
// The whole request is additionally bounded — see uploadRequestMaxBytes — which
// multer's configuration is not: its limits.fields, limits.parts and
// limits.fileSize-for-non-file-parts are all left at Infinity there, so a
// request carrying one small image and a gigabyte of text fields is read whole.

// The upload routes, relative to the admin mount.
const (
	// AdminUploadLogoPath and AdminUploadBGImagePath are two registrations of
	// one handler (admin.router.ts:1024, :1035). The reference's two bodies are
	// identical, down to the comment on the first and not the second, and
	// neither reads which of the two it is: the SPA tells them apart only by
	// which input it puts the answer into (admin.js uploadAsset).
	AdminUploadLogoPath    = "/api/upload/logo"
	AdminUploadBGImagePath = "/api/upload/bg-image"
	// AdminUploadFilesPath is the listing (admin.router.ts:1047).
	AdminUploadFilesPath = "/api/upload/files"
	// AdminUploadPath is the prefix DELETE /api/upload/:filename captures below
	// (admin.router.ts:1066). It is not a route of its own.
	AdminUploadPath = "/api/upload"
)

// adminUploadNameLimit is the reference's .slice(0, 40) on the sanitised base
// name (admin.router.ts:1011).
const adminUploadNameLimit = 40

// uploadRequestMaxBytes bounds the whole multipart request, where UploadMaxBytes
// bounds only the file part.
//
// The reference bounds neither: multer is configured with limits.fileSize alone
// (admin.router.ts:1016), so every other part of the body is read without a cap
// and a request carrying one 1-pixel PNG and a gigabyte of text fields is a
// gigabyte this process buffers. A port that streams a client-supplied body into
// storage needs the outer bound as much as the inner one, and it is not a
// deviation in any observable sense: the console sends exactly one part
// (admin.js uploadAsset builds a FormData with a single 'file' entry), so the
// slack is for MIME headers and for any text field a host's own client adds.
//
// Exceeding it is answered like exceeding the file limit, because from the
// caller's side it is the same mistake.
const uploadRequestMaxBytes = UploadMaxBytes + 64<<10

// errUploadTooLarge is what uploadLimitedReader reports past UploadMaxBytes. It
// never reaches a caller: the route turns it into the 413 below.
var errUploadTooLarge = errors.New("auth: uploaded file exceeds the size limit")

// adminUploadRoute names one of the four.
type adminUploadRoute int

const (
	adminUploadNone adminUploadRoute = iota
	adminUploadLogo
	adminUploadBGImage
	adminUploadList
	adminUploadDelete
)

// matchAdminUpload classifies a method and a path below the admin mount, and is
// matchAdminRead's and matchAdminWrite's counterpart: rel is the *escaped* path,
// so the DELETE route's parameter is split before it is decoded, for the reason
// matchAdminRead gives.
//
// The method is part of the match because Express registers a layer per method,
// and the ordering of the four layers is observable on two paths:
//
//   - DELETE /api/upload/files and DELETE /api/upload/logo match the
//     :filename layer, because the fixed registrations above it are a GET and
//     two POSTs. So those two paths are delete attempts on objects named
//     "files" and "logo", which is what happens here.
//   - GET /api/upload/logo and POST /api/upload/files match nothing, and end at
//     the router's own 404.
func matchAdminUpload(method, rel string) (adminUploadRoute, string) {
	switch method {
	case http.MethodPost:
		switch rel {
		case AdminUploadLogoPath:
			return adminUploadLogo, ""
		case AdminUploadBGImagePath:
			return adminUploadBGImage, ""
		}
	case http.MethodGet, http.MethodHead:
		// HEAD because Express falls back to a GET layer for it, which every
		// router.get in the reference's admin router inherits; see isAdminRead.
		if rel == AdminUploadFilesPath {
			return adminUploadList, ""
		}
	case http.MethodDelete:
		if name, tail, ok := adminPathParam(rel, AdminUploadPath); ok && tail == "" {
			return adminUploadDelete, name
		}
	}
	return adminUploadNone, ""
}

// adminUploadRegistered reports whether the reference registers this route in
// this deployment at all, and is adminReadRegistered's counterpart for the
// fourth family.
//
// All four are conditional on one thing — `if (options.uploadDir)` (:991) — so
// unlike the read and write tables there is nothing per-route to ask.
func (a *Auth) adminUploadRegistered(route adminUploadRoute) bool {
	return route != adminUploadNone && a.service.cfg.Uploads != nil
}

// serveAdminUpload dispatches one classified upload route. It runs behind
// Protect, so everything below may assume an authorised caller and nothing below
// may assume an identified one — the reference spreads the same guard onto all
// four (:1024, :1035, :1047, :1066) and none of them reads req.user.
//
// The store is non-nil: adminUploadRegistered refused the route otherwise.
func (a *Auth) serveAdminUpload(w http.ResponseWriter, r *http.Request, cfg HTTPConfig, route adminUploadRoute, param string) {
	switch route {
	case adminUploadLogo, adminUploadBGImage:
		a.adminUploadFile(w, r, cfg)
	case adminUploadList:
		a.adminListUploads(w, r)
	case adminUploadDelete:
		a.adminDeleteUpload(w, r, param)
	default:
		http.NotFound(w, r)
	}
}

// adminUploadFile is POST <admin>/api/upload/logo and POST
// <admin>/api/upload/bg-image (:1024-1042), which are one handler registered
// twice.
//
// The answer on success is {success, filename, url}: the key the store now
// holds, and either the browser-ready URL or — with no upload base URL resolved
// — the key again, which is the reference's `url = base ? … : filename`
// (:1028-1031). The SPA reads `data.url || data.filename` and puts it straight
// into the logo or background field (admin.js uploadAsset), which is why both
// members are sent and why neither may be omitted.
//
// # The refusals, and where they part company with the reference
//
// One of the four is the reference's own: no file part is 400 `{"error": "No
// file uploaded"}` (:1025), which is also where a request that is not multipart
// at all ends up, because multer's middleware passes such a request through
// without setting req.file.
//
// The other three — a name that is not an image, a body past the limit, a store
// that failed — reach no handler there. multer calls next(err) and the admin
// router registers no error middleware, so the response is whatever the *host
// application's* error handler produces: for a plain Express app, a 500 carrying
// an HTML error page. There is no such pipeline to port, so each one answers the
// admin router's own envelope and a status that names the problem. That is the
// admin-upload-refusals-answer-the-admin-envelope deviation.
func (a *Auth) adminUploadFile(w http.ResponseWriter, r *http.Request, cfg HTTPConfig) {
	store := a.service.cfg.Uploads

	// The outer bound, before a single part is read. See uploadRequestMaxBytes.
	r.Body = http.MaxBytesReader(w, r.Body, uploadRequestMaxBytes)

	part, err := adminUploadPart(r)
	if err != nil {
		// Not multipart, a malformed body, or no part named "file" carrying a
		// filename: req.file is unset on all of them there, and the handler's
		// own first line answers (:1025).
		writeAdminError(w, http.StatusBadRequest, "No file uploaded")
		return
	}
	defer part.Close() //nolint:errcheck

	// fileFilter (:1018-1022), on the client's name and before a byte of the
	// body is read — as there, where the filter runs before the storage engine
	// opens its write stream.
	if !UploadNameAllowed(part.FileName()) {
		writeAdminError(w, http.StatusBadRequest, "Only image files are allowed")
		return
	}

	// limits.fileSize (:1016). The body is buffered to this bound and only then
	// handed to the store, which is deliberately not a stream: deciding the 413
	// before the first store call is what guarantees that an over-large upload
	// leaves nothing behind under a key the listing would then report, whatever
	// a host's store does with a reader that fails halfway. UploadMaxBytes is
	// five megabytes, so the buffer is the price of that guarantee — and it
	// buys the store an io.Seeker as well, which an object-store client can use
	// to length or checksum the body without copying it again.
	body, err := io.ReadAll(&uploadLimitedReader{r: part, remaining: UploadMaxBytes})
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, errUploadTooLarge), errors.As(err, &tooBig):
		writeAdminError(w, http.StatusRequestEntityTooLarge, "File too large")
		return
	case err != nil:
		// The body stopped arriving. No file was uploaded, which is the
		// reference's own branch for a request that delivered none.
		writeAdminError(w, http.StatusBadRequest, "No file uploaded")
		return
	}

	key := adminUploadKey(part.FileName(), a.service.now())
	if _, err := store.Put(r.Context(), key, bytes.NewReader(body)); err != nil {
		writeAdminError(w, http.StatusInternalServerError, adminUploadErrorMessage(err, "Could not store file"))
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"filename": key,
		"url":      a.adminUploadURL(cfg, key),
	})
}

// adminUploadURL is the `url` member of both upload answers (:1028-1031):
// the resolved base with its trailing slash trimmed, a slash, and the key
// percent-encoded — or the bare key when no base resolved.
//
// url.PathEscape is encodeURIComponent for every key ValidUploadKey admits:
// that grammar is letters, digits, '.', '_' and '-', all of which both leave
// alone. The two disagree on characters no key can contain, so the difference is
// not observable — and writing the escape rather than the concatenation is what
// keeps that true if the grammar ever widens.
func (a *Auth) adminUploadURL(cfg HTTPConfig, key string) string {
	base := a.adminUploadBaseURL(cfg)
	if base == "" {
		return key
	}
	return strings.TrimSuffix(base, "/") + "/" + url.PathEscape(key)
}

// adminListUploads is GET <admin>/api/upload/files (:1047-1062).
//
// The body is {files: [{name, size, mtime}]} and the list is never null. Two
// things happen to what the store returned, and both are the reference's:
//
//   - the same seven-extension filter the upload routes apply on the way in
//     (:1050), because the reference's readdirSync sees whatever else is in that
//     directory — a .DS_Store, a stray README, an object some other process
//     wrote — and this port's store may hold keys a host put there itself;
//   - the listing order, newest first (:1057). UploadStore.List already promises
//     it; SortUploadedFiles re-applies it here because the reference's route
//     sorts what readdir handed it, and a wire order that holds only while every
//     host's store is diligent is not a wire order. See SortUploadedFiles for
//     the tie-break the reference does not have.
//
// A failure is 500 carrying the error's own message and a fallback string
// (:1058-1061) — the shape PATCH /api/settings/ui already has on this router,
// and for the same reason: the message goes only to a caller the guard has
// already admitted to a console that serves the whole user table.
func (a *Auth) adminListUploads(w http.ResponseWriter, r *http.Request) {
	files, err := a.service.cfg.Uploads.List(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, adminUploadErrorMessage(err, "Could not list files"))
		return
	}
	out := make([]UploadedFile, 0, len(files))
	for _, file := range files {
		if UploadNameAllowed(file.Name) {
			out = append(out, file)
		}
	}
	SortUploadedFiles(out)
	WriteJSON(w, http.StatusOK, map[string]any{"files": out})
}

// adminDeleteUpload is DELETE <admin>/api/upload/:filename (:1066-1084), the one
// route on this surface that is handed a name by the caller.
//
// # The three answers
//
// 400 `{"error": "Invalid filename"}` for the reference's own three refusals,
// 404 `{"error": "File not found"}` for a key the store does not hold, 200
// `{"success": true}` otherwise, and 500 with the error's message for a store
// that failed. No extension check: the reference has none here, so an object a
// host put in the store under a name the listing above hides is still deletable
// through this route.
//
// # Why the grammar check answers 404 and not a second 400
//
// The reference's guard is `filename.includes('/') || filename.includes('\\') ||
// filename.startsWith('.')` and then path.join (:1068-1073). Those three are
// reproduced first and verbatim, so every name it calls invalid is invalid here.
//
// A name that passes them and still fails ValidUploadKey — "my logo.png", a name
// carrying a colon, anything non-ASCII — is a name no key can be, because the
// only keys these routes create come from adminUploadKey and every one of them
// satisfies the grammar. So the store provably holds no such object, and "File
// not found" is both the true answer and the one the reference gives, by way of
// its existsSync. The store is never asked to defend a name this package could
// refuse, which is the arrangement ValidUploadKey exists to make possible.
//
// # Why the existence check is the delete itself
//
// The reference checks existsSync and then unlinks (:1073-1078), which races two
// administrators deleting the same file and turns the loser's request into its
// generic 500. One store call cannot race: UploadStore.Delete reports
// ErrUploadNotFound, and the 404 is the same 404.
func (a *Auth) adminDeleteUpload(w http.ResponseWriter, r *http.Request, filename string) {
	if strings.ContainsAny(filename, `/\`) || strings.HasPrefix(filename, ".") {
		writeAdminError(w, http.StatusBadRequest, "Invalid filename")
		return
	}
	if !ValidUploadKey(filename) {
		writeAdminError(w, http.StatusNotFound, "File not found")
		return
	}
	switch err := a.service.cfg.Uploads.Delete(r.Context(), filename); {
	case errors.Is(err, ErrUploadNotFound):
		writeAdminError(w, http.StatusNotFound, "File not found")
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, adminUploadErrorMessage(err, "Could not delete file"))
	default:
		writeAdminSuccess(w)
	}
}

// adminUploadErrorMessage is the reference's `err instanceof Error ? err.message
// : '<fallback>'` (:1059-1060, :1079-1080).
//
// In Go every non-nil error has a message, so the fallback stands in for the one
// case that maps onto a thrown non-Error: an error whose Error() is empty, which
// would otherwise put `{"error": ""}` on the wire.
func adminUploadErrorMessage(err error, fallback string) string {
	if err == nil || err.Error() == "" {
		return fallback
	}
	return err.Error()
}

// ── the multipart body ───────────────────────────────────────────────────────

// adminUploadPart finds the part upload.single('file') would have taken: the
// first one whose field name is "file" and which carries a filename.
//
// Parts before it are skipped rather than refused, which is multer's treatment
// of the text fields it collects into req.body. A *file* part under some other
// field name is multer's LIMIT_UNEXPECTED_FILE and reaches the host's error
// handler there; here it is skipped too, so a request carrying only such a part
// ends at the same "No file uploaded" the caller gets for sending none — one
// refusal instead of two for a request that delivered no usable file either
// way.
//
// A part with no filename is not a file on either side: multer routes it to
// req.body, so a text field literally named "file" does not satisfy
// upload.single('file').
func adminUploadPart(r *http.Request) (*multipart.Part, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	for {
		part, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		if part.FormName() == "file" && part.FileName() != "" {
			return part, nil
		}
		_ = part.Close()
	}
}

// uploadLimitedReader is io.LimitReader that reports an error instead of an EOF
// past its limit, so that a body of exactly the limit is accepted and one byte
// more is refused rather than silently truncated.
//
// io.LimitReader cannot express that: it ends in EOF, and a caller reading
// through it stores a truncated file and reports success. multer's own
// limits.fileSize is the refusing kind, which is the behaviour being ported.
type uploadLimitedReader struct {
	r         io.Reader
	remaining int64
}

func (l *uploadLimitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		// The allowance is spent. One more byte anywhere in the underlying
		// reader means the body was over the limit; an EOF means it was exactly
		// at it.
		var probe [1]byte
		for {
			n, err := l.r.Read(probe[:])
			if n > 0 {
				return 0, errUploadTooLarge
			}
			if err != nil {
				return 0, err
			}
		}
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// ── the key ──────────────────────────────────────────────────────────────────

// adminUploadKey is multer's filename callback (admin.router.ts:1005-1013): the
// key the store is given, derived from the client's filename and never taken
// from it.
//
//	const rawExt = path.extname(file.originalname).toLowerCase();
//	const ext = rawExt.replace(/[^a-z0-9]/g, '');
//	const name = path.basename(file.originalname, path.extname(file.originalname))
//	  .replace(/[^a-z0-9_-]/gi, '_')
//	  .slice(0, 40);
//	cb(null, `${name}_${Date.now()}.${ext}`);
//
// Deriving rather than accepting is what makes traversal impossible on the write
// side: path.basename discards every directory component, and the character
// class turns whatever survives into letters, digits, underscores and hyphens.
// Every key this function can produce satisfies ValidUploadKey — the name part
// draws from a subset of that grammar, the timestamp is digits, and the
// extension is at most four lowercase alphanumerics — which is pinned by a test
// over a corpus of hostile filenames rather than left as a reading of the code.
//
// # The quirks, which are reproduced
//
//   - Two uploads of the same filename in the same millisecond produce the same
//     key, and the second replaces the first. There the write stream truncates;
//     here UploadStore.Put is documented to replace.
//   - A filename that is nothing but an extension — ".png" — has no extension
//     at all by Node's rule, so the key is "_png_<millis>." with a trailing dot
//     and no type. The fileFilter accepts such a name, so this is reachable, and
//     the object is then served back with no content type derived from its key.
//   - The timestamp is the server's wall clock in milliseconds. It is the
//     service's clock rather than time.Now directly, so a test that freezes time
//     sees a stable key.
func adminUploadKey(originalName string, now time.Time) string {
	base := originalName
	// path.basename, in its POSIX form: the reference runs on a POSIX host, so
	// only '/' separates. A backslash is not a separator here and does not need
	// to be — it is outside the character class below and becomes an underscore,
	// so a Windows-style path survives as its own underscores on both sides
	// rather than being split differently by each.
	if cut := strings.LastIndexByte(base, '/'); cut >= 0 {
		base = base[cut+1:]
	}
	ext := nodeExtname(base)
	return adminUploadSanitiseName(strings.TrimSuffix(base, ext)) +
		"_" + strconv.FormatInt(now.UnixMilli(), 10) +
		"." + adminUploadSanitiseExt(ext)
}

// nodeExtname is Node's path.extname over a basename: the suffix from the last
// '.', unless that dot is the first character — a dotfile has no extension there
// — or the whole basename is "..".
//
// Both carve-outs are Node's and both are reachable from a filename the
// fileFilter accepts, which is why they are ported rather than approximated
// with strings.LastIndex alone.
func nodeExtname(base string) string {
	i := strings.LastIndexByte(base, '.')
	if i <= 0 || base == ".." {
		return ""
	}
	return base[i:]
}

// adminUploadSanitiseName is `.replace(/[^a-z0-9_-]/gi, '_').slice(0, 40)`.
//
// It iterates UTF-16 code units and not runes, which is not pedantry: a
// JavaScript regexp without the /u flag matches code units, so an astral
// character — an emoji in a filename — is a surrogate pair there and becomes
// *two* underscores, where a rune-wise loop would produce one. The replacement
// is one code unit for one, so slicing to forty afterwards is the same as
// stopping the loop at forty, and every kept unit is ASCII.
func adminUploadSanitiseName(name string) string {
	units := utf16.Encode([]rune(name))
	out := make([]byte, 0, len(units))
	for _, u := range units {
		switch {
		case u >= 'a' && u <= 'z', u >= 'A' && u <= 'Z', u >= '0' && u <= '9', u == '_', u == '-':
			out = append(out, byte(u))
		default:
			out = append(out, '_')
		}
		if len(out) == adminUploadNameLimit {
			break
		}
	}
	return string(out)
}

// adminUploadSanitiseExt is `path.extname(...).toLowerCase().replace(/[^a-z0-9]/g, ”)`:
// lowercase, then drop everything that is not a lowercase letter or a digit —
// the leading dot included, which is why the key template writes one back.
//
// Dropping bytes is the same as dropping code units for anything this can be
// handed: every multi-byte character has no byte in [a-z0-9], so both sides
// remove all of it.
func adminUploadSanitiseExt(ext string) string {
	lower := strings.ToLower(ext)
	out := make([]byte, 0, len(lower))
	for i := 0; i < len(lower); i++ {
		if c := lower[i]; (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		}
	}
	return string(out)
}

// ── the upload base URL ──────────────────────────────────────────────────────

// adminUploadBaseURL is the reference's effectiveUploadBaseUrl
// (admin.router.ts:638-643): the public base the SPA and the two upload answers
// build asset URLs from.
//
// Configured wins; otherwise it is derived, and it is derived only when there is
// something to serve — `&& options.uploadDir` there, an UploadStore here.
//
// The derivation is where this port answers differently, and it is worth being
// precise about how. The reference's condition is `!effective && options.apiPrefix
// && options.uploadDir`, so a host that does not pass apiPrefix gets no base and
// both upload routes answer `url === filename`; its own documentation for that
// option says `@default '/auth'` (:152-157). This port resolves the same field
// against the mount it was configured with — HTTPConfig.Prefix() — which makes
// that documented default true rather than aspirational, and is the identical
// resolution the shell already applies to authApiPrefix (adminShellHTML). A
// client that reads `url` therefore sees a usable URL where the reference's
// would have handed it a bare filename; that is the
// admin-upload-base-url-is-derived-from-the-mount deviation.
//
// The path it derives is the UI router's unified uploads mount, which is where
// UIHandler serves an UploadStore's objects back from — so the URL this returns
// resolves against this same deployment without the host arranging anything.
func (a *Auth) adminUploadBaseURL(cfg HTTPConfig) string {
	if base := strings.TrimSpace(cfg.Admin.UploadBaseURL); base != "" {
		return base
	}
	if a.service.cfg.Uploads == nil {
		return ""
	}
	return strings.TrimSuffix(cfg.adminAuthAPIPrefix(), "/") + UIRoute + "/assets/uploads"
}
