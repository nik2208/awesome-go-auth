package auth

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The drift check.
//
// Vendored bytes rot in a particular way: not by anyone deciding to fork them,
// but by a one-line fix applied where the reader happened to be standing. The
// file is right there in the tree, it looks like source, and changing it makes
// the symptom go away. Nothing in Go's tooling objects — there is no
// `go mod verify` for a directory of HTML.
//
// So the objection is this test. It re-derives the sha256 of every embedded
// asset on every `go test ./...` and compares it against upstreamUIAssetTable,
// which is checked in beside the bytes. CI runs `go test -race ./...`
// (.github/workflows/ci.yml), and the local gate runs the same command, so the
// check is already wired everywhere this repository is built; vendoring needed
// no workflow change and got none.
//
// It fails in five distinct ways, because the interesting failures are not all
// "a byte changed":
//
//  1. a vendored file's contents differ from the table (someone edited an asset);
//  2. a file is embedded that the table does not list (someone added an asset);
//  3. the table lists a file that is not embedded (someone deleted one);
//  4. the number of assets is no longer the stated fourteen;
//  5. the bytes were re-mangled to CRLF by a checkout, which gets its own
//     message because the fix is a .gitattributes entry and not a re-vendor.
//
// Cases 2 and 3 are why this test walks the embedded filesystem instead of
// ranging over the table. A check that only iterates the table is blind in
// exactly the direction that matters: it can never see a file that was added.

// revendorHint is the remedy every drift message ends with. A failure that says
// only "the hash is wrong" leaves the reader to guess whether the bytes or the
// table is the thing in error, and those have opposite fixes.
func revendorHint(name string) string {
	return fmt.Sprintf(
		"\n  if the bytes are wrong (an asset was edited here, which is never allowed), restore them:\n"+
			"    git -C <awesome-node-auth> cat-file blob %s:%s/%s > %s/%s\n"+
			"  if this is a deliberate move to a new upstream revision, re-vendor all of them and\n"+
			"  update upstreamUIAssetTable, UpstreamUIAssetCommit and ReferenceRevision together;\n"+
			"  see ui/upstream/README.md.",
		UpstreamUIAssetCommit, UpstreamUIAssetDir, name, upstreamUIAssetRoot, name)
}

// embeddedUpstreamAssets lists what is actually embedded, by base name.
func embeddedUpstreamAssets(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := fs.WalkDir(upstreamUIFS, upstreamUIAssetRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The table is keyed by base name, which is only unambiguous while
			// the directory stays flat. A subdirectory would silently give two
			// assets the same key, so it is refused rather than flattened.
			if p != upstreamUIAssetRoot {
				t.Errorf("%s contains a subdirectory %q: the vendored set is flat, and the "+
					"provenance table is keyed by base name", upstreamUIAssetRoot, p)
			}
			return nil
		}
		data, readErr := upstreamUIFS.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		out[path.Base(p)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", upstreamUIAssetRoot, err)
	}
	if len(out) == 0 {
		t.Fatalf("no assets embedded under %s: every check below would pass vacuously",
			upstreamUIAssetRoot)
	}
	return out
}

// TestVendoredUIAssetsHaveNotDrifted is the check the whole vendoring design
// rests on: the bytes in the tree are still the bytes the reference publishes.
func TestVendoredUIAssetsHaveNotDrifted(t *testing.T) {
	embedded := embeddedUpstreamAssets(t)

	if len(upstreamUIAssetTable) != upstreamUIAssetCount {
		t.Errorf("upstreamUIAssetTable has %d entries, but upstreamUIAssetCount says %d: "+
			"the vendored set changed size, which is a decision and has to be written down "+
			"in both places", len(upstreamUIAssetTable), upstreamUIAssetCount)
	}

	tabled := make(map[string]UpstreamUIAsset, len(upstreamUIAssetTable))
	for _, a := range upstreamUIAssetTable {
		if _, dup := tabled[a.Name]; dup {
			t.Errorf("upstreamUIAssetTable lists %q twice: one of the two entries is dead "+
				"and neither is being checked the way its author thought", a.Name)
		}
		tabled[a.Name] = a
	}

	// Direction 1: everything embedded must be declared. This is the direction a
	// table-driven loop cannot see, and the reason this test walks the FS.
	for _, name := range sortedKeys(embedded) {
		if _, ok := tabled[name]; !ok {
			t.Errorf("%s/%s is embedded but has no entry in upstreamUIAssetTable.\n"+
				"  a file added to the vendored directory is un-provenanced and unhashed: "+
				"nothing records where it came from and nothing would notice it changing.\n"+
				"  add it to the table (name, size, sha256 of the upstream blob) and to "+
				"upstreamUIAssetCount, or delete it.%s",
				upstreamUIAssetRoot, name, revendorHint(name))
		}
	}

	// Direction 2: everything declared must be present.
	for _, a := range upstreamUIAssetTable {
		data, ok := embedded[a.Name]
		if !ok {
			t.Errorf("upstreamUIAssetTable lists %q but no such file is embedded under %s.\n"+
				"  the asset was deleted or renamed; restore it, or drop its table entry and "+
				"decrement upstreamUIAssetCount.%s",
				a.Name, upstreamUIAssetRoot, revendorHint(a.Name))
			continue
		}

		got := sha256Hex(data)
		if got == a.SHA256 && len(data) == a.Size {
			continue
		}

		// The CRLF case gets its own message because its fix is not a re-vendor.
		// awesome-node-auth ships no .gitattributes and this machine sets
		// core.autocrlf=true, so a checkout that is not pinned rewrites every LF
		// in these files and every hash changes at once. Telling someone to
		// re-vendor in that state sends them to copy bytes that will be mangled
		// again on the next checkout.
		if bytes.Contains(data, []byte("\r\n")) {
			t.Errorf("vendored asset %q contains CRLF line endings and no longer matches its hash "+
				"(%d bytes, sha256 %s; the table says %d bytes, sha256 %s).\n"+
				"  the reference publishes these files with LF, so this is almost certainly a "+
				"checkout that rewrote them rather than an edit.\n"+
				"  the fix is the .gitattributes entry that holds %s/** at eol=lf; check it is "+
				"still there, then re-checkout these paths.",
				a.Name, len(data), got, a.Size, a.SHA256, upstreamUIAssetRoot)
			continue
		}

		if len(data) != a.Size {
			t.Errorf("vendored asset %q is %d bytes, but the table says %d.%s",
				a.Name, len(data), a.Size, revendorHint(a.Name))
		}
		if got != a.SHA256 {
			t.Errorf("vendored asset %q has drifted from upstream:\n"+
				"    have sha256 %s\n    want sha256 %s\n"+
				"  these files are byte-for-byte copies of %s@%s and are not editable in this "+
				"repository.%s",
				a.Name, got, a.SHA256, UpstreamUIAssetDir, UpstreamUIAssetCommit[:8],
				revendorHint(a.Name))
		}
	}
}

// TestVendoredUIAssetsAgreeWithReferenceRevision keeps the two places this
// package names the reference commit from drifting apart. The deviation
// register's citations resolve against ReferenceRevision; the assets resolve
// against UpstreamUIAssetCommit. If someone moves one forward and not the
// other, the citations and the bytes start describing different trees and
// nothing else in the build would say so.
func TestVendoredUIAssetsAgreeWithReferenceRevision(t *testing.T) {
	if !strings.Contains(ReferenceRevision, UpstreamUIAssetCommit[:8]) {
		t.Errorf("ReferenceRevision is %q but the vendored assets come from %s: "+
			"the citations and the assets must name one revision",
			ReferenceRevision, UpstreamUIAssetCommit)
	}
}

// TestUpstreamUIAssetsAccessorsAreHonest pins the exported surface: the table a
// caller reads is the table the drift check verified, the provenance fields are
// filled in, and the returned data cannot be used to mutate the embedded bytes.
func TestUpstreamUIAssetsAccessorsAreHonest(t *testing.T) {
	assets := UpstreamUIAssets()
	if len(assets) != len(upstreamUIAssetTable) {
		t.Fatalf("UpstreamUIAssets returned %d entries, table has %d",
			len(assets), len(upstreamUIAssetTable))
	}
	for _, a := range assets {
		if a.Commit != UpstreamUIAssetCommit {
			t.Errorf("%s: Commit is %q, want %q", a.Name, a.Commit, UpstreamUIAssetCommit)
		}
		if want := UpstreamUIAssetDir + "/" + a.Name; a.UpstreamPath != want {
			t.Errorf("%s: UpstreamPath is %q, want %q", a.Name, a.UpstreamPath, want)
		}
	}

	// The register is documented as sharing nothing with the package.
	assets[0].SHA256 = "tampered"
	if UpstreamUIAssets()[0].SHA256 == "tampered" {
		t.Error("UpstreamUIAssets shares state between calls: a caller that edits the result " +
			"changes what every later caller sees")
	}

	// ReadUpstreamUIAsset likewise hands out a copy, not the embedded array.
	data, err := ReadUpstreamUIAsset("auth.js")
	if err != nil {
		t.Fatalf("ReadUpstreamUIAsset(auth.js): %v", err)
	}
	data[0] = 'X'
	again, err := ReadUpstreamUIAsset("auth.js")
	if err != nil {
		t.Fatalf("ReadUpstreamUIAsset(auth.js) second call: %v", err)
	}
	if again[0] == 'X' {
		t.Error("ReadUpstreamUIAsset returns the embedded backing array: a caller that writes " +
			"through it corrupts the asset for the rest of the process")
	}

	if _, err := ReadUpstreamUIAsset("no-such-asset.js"); err == nil {
		t.Error("ReadUpstreamUIAsset succeeded for a name that is not vendored")
	}

	// The fs.FS seam U11 mounts is rooted at the asset directory.
	if _, err := fs.Stat(UpstreamUIAssetFS(), "login.html"); err != nil {
		t.Errorf("UpstreamUIAssetFS is not rooted at the asset directory: %v", err)
	}
}

// concatenatedTail matches the text immediately before a quoted literal when
// that literal continues an expression rather than starting one.
var concatenatedTail = regexp.MustCompile(`\+\s*$`)

// TestVendoredAssetsCallRoutesThatExist extends ui_test.go's contract — asset
// path literals ⊆ GenerateOpenAPISpec paths — to the vendored files.
//
// This is the check that makes vendoring safe rather than merely tidy. The two
// auth.js files were written against two different servers: the port's against
// this port's routes, the reference's against the reference's. Swapping one for
// the other is only sound if the reference's SDK calls routes this port
// actually serves, and nothing but a test can establish that.
//
// It holds today: all 41 auth-route literals across the fourteen assets resolve
// to a documented path. The exemption ui_test.go already grants to /ui/*,
// /tools/* and /admin/* literals is kept and is what makes this PR possible
// before M8 and M9 land — the vendored admin SPA calls an admin router that
// this port will not mount until U16.
//
// One rule is added here that ui_test.go does not need: a quoted literal
// preceded by `+` is a fragment of a concatenation, not the start of a path.
// The vendored admin.js builds every request as BASE + path, where BASE is the
// admin mount injected at render time (admin.js:154, reading
// window.__ADMIN_CONFIG__.base), so `'/api/users/' + id + '/metadata'` puts the
// bare literal "/metadata" in the source. Read as a path start that is a call
// to <prefix>/metadata, which this port does not serve and the reference does
// not have either; read correctly it is the tail of
// /admin/api/users/:id/metadata (admin.router.ts:855). Six literals in admin.js
// are fragments of this kind and all six are admin-surface.
func TestVendoredAssetsCallRoutesThatExist(t *testing.T) {
	documented := documentedAssetPaths(t)
	embedded := embeddedUpstreamAssets(t)

	checked := 0
	for _, name := range sortedKeys(embedded) {
		t.Run(name, func(t *testing.T) {
			source := string(embedded[name])
			for _, m := range assetRoutePattern.FindAllStringSubmatchIndex(source, -1) {
				literal := source[m[2]:m[3]]
				if !isAuthRouteLiteral(literal) {
					continue
				}
				// Look back a short way rather than at the whole prefix: the
				// question is only what token immediately precedes the quote.
				before := source[max(0, m[0]-40):m[0]]
				if concatenatedTail.MatchString(before) {
					continue
				}
				checked++
				if !knownAssetPath(literal, documented) {
					t.Errorf("vendored %s calls %q, which no adapter mounts.\n"+
						"  the vendored assets are not editable here, so the answer is either a "+
						"route this port still owes the family, or a literal that needs the "+
						"concatenation or prefix exemption above.",
						name, literal)
				}
			}
		})
	}
	if checked == 0 {
		t.Error("no auth route literals found in any vendored asset — the extraction regex has " +
			"stopped matching, and this test is now passing on an empty set")
	}
}

// TestVendoredAssetsSpeakTheCurrentWire runs ui_test.go's field-shape bans over
// the vendored files.
//
// Every one of those patterns is a mistake the port's own pre-0.2.0 assets made
// — snake_case bodies, a `tokens` envelope the server stopped returning. The
// interesting result is that the reference's assets make none of them: the
// family's UI and this port's wire already agree on camelCase, which is the
// evidence that the swap in ServeAuthJS is safe rather than merely intended.
//
// Keeping the assertion live matters more than the fact that it passes today.
// If a future re-vendor brings in an asset that speaks a different wire, this
// is the test that refuses it, and the fix then is a deviation entry in
// compatibility.go — not an edit to the asset.
func TestVendoredAssetsSpeakTheCurrentWire(t *testing.T) {
	banned := []struct {
		pattern *regexp.Regexp
		why     string
	}{
		{regexp.MustCompile(`\btenant_id\b`), "request fields are camelCase: tenantId"},
		{regexp.MustCompile(`\buser_id\b`), "request fields are camelCase: userId"},
		{regexp.MustCompile(`\bnew_password\b`), "reset-password takes `password`; change-password takes `newPassword`"},
		{regexp.MustCompile(`\bcurrent_password\b`), "request fields are camelCase: currentPassword"},
		{regexp.MustCompile(`\brefresh_token\b`), "request fields are camelCase: refreshToken"},
		{regexp.MustCompile(`\baccess_token\b`), "response fields are camelCase: accessToken"},
		{regexp.MustCompile(`\bnew_email\b`), "request fields are camelCase: newEmail"},
		{regexp.MustCompile(`\bexpires_in\b`), "the token response carries no lifetime; read exp from the JWT"},
		{regexp.MustCompile(`\.tokens\b`), "there is no `tokens` object: bearer callers get top-level accessToken/refreshToken"},
	}

	embedded := embeddedUpstreamAssets(t)
	for _, name := range sortedKeys(embedded) {
		t.Run(name, func(t *testing.T) {
			source := string(embedded[name])
			for _, b := range banned {
				if loc := b.pattern.FindStringIndex(source); loc != nil {
					t.Errorf("vendored %s uses %q — %s", name, source[loc[0]:loc[1]], b.why)
				}
			}
		})
	}
}

// TestVendoredAuthJSIsAWorkingCookieClient pins the vendored SDK against this
// port's cookie contract, name for name.
//
// ServeAuthJS now serves this file, so these are not trivia: the CSRF cookie
// names and the session-revoked code are strings the two sides have to spell
// identically, and a rename on the Go side would otherwise break the served
// client with nothing failing.
//
// Two facts from TestAuthJSHonoursTheCookieContract are deliberately absent
// here, and the difference is the one behavioural consequence of the swap.
// The port's hand-written auth.js sent X-Auth-Strategy: bearer to opt into
// token delivery. The reference's auth.js never sends that header: it is a
// cookie-only client, and the header is read by the server (auth.router.ts:391)
// for callers that choose to send it — the Angular and Flutter clients — rather
// than by its own SDK. Serving the reference's file therefore removes the
// bearer opt-in from the *served* SDK while changing nothing about the server,
// which still honours X-Auth-Strategy from any caller. That is the intended
// result of vendoring byte for byte and is called out in the CHANGELOG, because
// a host whose page relied on window.AuthSDK returning tokens has to know.
func TestVendoredAuthJSIsAWorkingCookieClient(t *testing.T) {
	data, err := ReadUpstreamUIAsset("auth.js")
	if err != nil {
		t.Fatalf("ReadUpstreamUIAsset(auth.js): %v", err)
	}
	source := string(data)

	for _, required := range []string{
		"credentials",
		"'include'",
		CSRFHeaderName,
		hostCookiePrefix + CSRFTokenCookieName,
		secureCookiePrefix + CSRFTokenCookieName,
		CodeSessionRevoked,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("vendored auth.js does not mention %q: the served SDK and this port no "+
				"longer agree on a name they both have to spell", required)
		}
	}
}

// TestServeAuthJSServesTheVendoredAsset pins the deprecation: the exported
// symbol still works, and what comes out of it is the reference's bytes rather
// than the port's hand-written ones.
func TestServeAuthJSServesTheVendoredAsset(t *testing.T) {
	want, err := ReadUpstreamUIAsset("auth.js")
	if err != nil {
		t.Fatalf("ReadUpstreamUIAsset(auth.js): %v", err)
	}

	rec := httptest.NewRecorder()
	ServeAuthJS().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth.js", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("ServeAuthJS returned %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("ServeAuthJS served %d bytes (sha256 %s), want the vendored asset's %d "+
			"(sha256 %s)", len(got), sha256Hex(got), len(want), sha256Hex(want))
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
		t.Errorf("ServeAuthJS Content-Type is %q, want application/javascript", ct)
	}
}

// sortedKeys makes the subtest order and the failure order deterministic, so a
// drift failure names the same file first on every machine.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
