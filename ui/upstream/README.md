# Vendored upstream UI assets — do not edit

Everything under `assets/` is a **byte-for-byte copy** of another repository.
Nothing in this directory is this port's code, and nothing in it may be edited
here. If you change one of these files, `TestVendoredUIAssetsHaveNotDrifted`
fails and your change is rejected — by design.

| | |
|---|---|
| Source repository | `awesome-node-auth` (npm `awesome-node-auth`) |
| Source commit | `cc01e9975fe9e425dc6d938a9c5d0738b59c79d8` (v1.9.0) |
| Source directory | `src/ui/assets/` |
| Vendored on | 2026-09-12 |
| Files | 14 |
| Total bytes | 192,107 |

The authoritative per-file provenance — upstream path, byte count and sha256 —
is the `upstreamUIAssetTable` in `../../ui_upstream.go`. It is Go source rather
than a sidecar file so the compiler and `go test ./...` both see it.

## Why the provenance is here and not in the files

A vendored file cannot both carry a "do not edit, generated from X" banner and
be byte for byte what upstream ships: adding the banner changes the bytes, and
the first thing the drift check would then report is that all 14 files differ
from their upstream blobs. The two goals are in direct conflict, so the
provenance is recorded **beside** the bytes instead of inside them — in this
file, in the table in `ui_upstream.go`, and in the drift test's failure message,
which is the place a person who is about to edit one of these files will
actually be standing.

## Re-vendoring

To move to a new upstream revision, replace the bytes and the table together:

```sh
REF=/path/to/awesome-node-auth
COMMIT=<new full object name>
for f in "$REF"/src/ui/assets/*; do
  n=$(basename "$f")
  git -C "$REF" cat-file blob "$COMMIT:src/ui/assets/$n" > ui/upstream/assets/"$n"
done
sha256sum ui/upstream/assets/*   # paste into upstreamUIAssetTable
```

`git cat-file blob` — not `cp`, and not a read of the working tree. This
machine checks `awesome-node-auth` out with CRLF line endings (it sets
`core.autocrlf=true` and that repository ships no `.gitattributes`), so the
working-tree copy of `login.html` is 7,198 bytes hashing to `facd1ced…` while
the blob the reference actually publishes is 7,064 bytes hashing to
`f22f3a3d…`. Copying from the working tree vendors 14 files that are not what
anybody upstream has, and pins the wrong bytes forever.

The matching guard on this side is the `.gitattributes` entry for
`ui/upstream/assets/**`, which holds these paths at LF on every host. Without
it the next Windows checkout rewrites all 14 files to CRLF and the drift check
fails on a tree nobody touched.
