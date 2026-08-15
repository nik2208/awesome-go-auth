package auth

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests are what stops the deviation register drifting away from what the
// port actually does, and away from what the README tells a reader it does.
//
// The README half used to be a second copy, asserted only by identity: the test
// required every id and citation to appear somewhere in README.md. That caught a
// deletion and nothing else. An entry could be reworded on either side, weakened,
// or reversed outright — the README could assert the exact opposite of the
// register — and the suite stayed green. So the README section is now generated
// from CompatibilityNotes() and compared byte for byte, and the identity-only
// mirror test is gone: it asserted a subset of what the comparison asserts.
//
// What is left is three things, and the prose is deliberately still free within
// them:
//
//   - Identity, exactly. TestCompatibilityNotesRegister compares the whole ID
//     set. Dropping a deviation fails, and so does adding one — an addition has
//     to be a deliberate act, declared here as well as in the register.
//   - Sameness with the README, exactly.
//     TestREADMEIsGeneratedFromCompatibilityNotes re-renders the section and
//     compares it to the committed file, so a Go edit that was not regenerated
//     fails, and a README edit with no Go edit behind it fails.
//   - Substance, by load-bearing token. TestCompatibilityNotesClaims requires a
//     handful of wire facts per entry — the status codes, the header and field
//     names, the numbers, the reference mechanism. Generation alone cannot carry
//     this: someone who weakens an entry *and* regenerates has a green README.
//     These claims are what makes that fail too. They are what the entry means,
//     not how it is phrased, so a rewrite survives while a hollowing-out or a
//     reversal does not.
//   - Form. TestCompatibilityNotesAreWellFormed requires every field populated
//     and every citation shaped like file:line, so an entry cannot be reduced to
//     an unfalsifiable sentence with the evidence removed.

// updateREADME rewrites the generated section of README.md from the register
// instead of asserting against it. This is the regeneration path the section's
// own header comment points at:
//
//	go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .
var updateREADME = flag.Bool("update", false,
	"rewrite the generated deviations section of README.md from CompatibilityNotes()")

// wantDeviationIDs is the register. Changing this set is the point at which a
// deviation is added or retired, and it must be changed together with
// CompatibilityNotes — after which README.md is regenerated, not edited.
var wantDeviationIDs = []string{
	"advertised-2fa-methods-require-store-support",
	"cookie-max-age-follows-configured-ttl",
	"csrf-cookie-not-reissued-with-tokens",
	"forgot-password-succeeds-on-delivery-failure",
	"link-request-exempts-bearer-from-csrf",
	"one-time-tokens-are-base64url",
	"password-policy-on-reset-and-change",
	"temp-token-is-typed-not-an-access-token",
	"totp-setup-omits-qrcode",
}

// wantClaims are the facts each entry has to keep stating. They are wire facts
// and named reference mechanisms rather than phrases, so they hold across a
// rewording and fail on a reversal. Each must appear somewhere in the entry.
var wantClaims = map[string][]string{
	"forgot-password-succeeds-on-delivery-failure": {"200", "500", "enumeration"},
	"temp-token-is-typed-not-an-access-token":      {"access token", "second factor"},
	"link-request-exempts-bearer-from-csrf":        {"Bearer", "CSRF_INVALID", "CORS-safelisted"},
	"password-policy-on-reset-and-change":          {"WEAK_PASSWORD", "400", "minLength: 8"},
	"totp-setup-omits-qrcode":                      {"otpauthUrl", "qrCode"},
	"one-time-tokens-are-base64url":                {"43", "64", "base64url"},
	"advertised-2fa-methods-require-store-support": {"available2faMethods", "501"},
	"csrf-cookie-not-reissued-with-tokens":         {"Set-Cookie", "setTokenCookies"},
	"cookie-max-age-follows-configured-ttl": {
		"Max-Age=2592000", "Max-Age=604800", "RefreshTokenTTL", "refreshTokenExpiresIn",
	},
}

// citationPattern is the reference source citation shape: a TypeScript file and
// either a line or a line range.
var citationPattern = regexp.MustCompile(`^[a-z0-9.\-]+\.ts:\d+(-\d+)?$`)

// entryText flattens an entry so a claim can be asserted against the whole of
// it. Which field carries a fact is an editorial matter; that the entry states
// it is not.
func entryText(d Deviation) string {
	parts := []string{d.ID, d.Title, d.Surface, d.Behaviour, d.Reference, d.Why}
	for _, n := range d.Notes {
		parts = append(parts, n.Label, n.Text)
	}
	return strings.Join(parts, "\n")
}

func TestCompatibilityNotesRegister(t *testing.T) {
	notes := CompatibilityNotes()

	got := make(map[string]bool, len(notes.KnownDeviations))
	for _, d := range notes.KnownDeviations {
		if got[d.ID] {
			t.Errorf("deviation %q is listed twice", d.ID)
		}
		got[d.ID] = true
	}

	want := make(map[string]bool, len(wantDeviationIDs))
	for _, id := range wantDeviationIDs {
		want[id] = true
		if !got[id] {
			t.Errorf("deviation %q has dropped out of CompatibilityNotes; "+
				"retiring one means removing it from wantDeviationIDs and regenerating the README too", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("deviation %q is new to CompatibilityNotes; add it to wantDeviationIDs, "+
				"give it an entry in wantClaims and regenerate the README", id)
		}
	}
}

func TestCompatibilityNotesClaims(t *testing.T) {
	for _, d := range CompatibilityNotes().KnownDeviations {
		t.Run(d.ID, func(t *testing.T) {
			claims, ok := wantClaims[d.ID]
			if !ok {
				t.Fatalf("no claims pinned for %q: every deviation needs the facts that make it "+
					"falsifiable, or the entry can be emptied without failing anything", d.ID)
			}
			text := entryText(d)
			for _, claim := range claims {
				if !strings.Contains(text, claim) {
					t.Errorf("entry no longer states %q.\nRewording is fine; dropping the fact is "+
						"the thing this catches. Entry was:\n%s", claim, text)
				}
			}
		})
	}
}

func TestCompatibilityNotesAreWellFormed(t *testing.T) {
	for _, d := range CompatibilityNotes().KnownDeviations {
		t.Run(d.ID, func(t *testing.T) {
			for _, f := range []struct{ name, value string }{
				{"ID", d.ID},
				{"Title", d.Title},
				{"Surface", d.Surface},
				{"Behaviour", d.Behaviour},
				{"Reference", d.Reference},
				{"Why", d.Why},
			} {
				if strings.TrimSpace(f.value) == "" {
					t.Errorf("%s is empty", f.name)
				}
			}
			for i, n := range d.Notes {
				if strings.TrimSpace(n.Label) == "" || strings.TrimSpace(n.Text) == "" {
					t.Errorf("note %d has an empty label or text", i)
				}
			}
			if len(d.Citations) == 0 {
				t.Error("no citation: a claim about the reference that cannot be checked is not a record of one")
			}
			for _, c := range d.Citations {
				if !citationPattern.MatchString(c) {
					t.Errorf("citation %q is not file:line or file:line-line into %s", c, ReferenceRevision)
				}
			}
		})
	}
}

func TestCompatibilityNotesDescribeBothDeliveryModes(t *testing.T) {
	notes := CompatibilityNotes()
	for _, f := range []struct{ name, value, want string }{
		{"ContractTarget", notes.ContractTarget, "awesome-node-auth"},
		{"ReferenceRevision", notes.ReferenceRevision, "cc01e997"},
		{"CookieConventions", notes.CookieConventions, "X-CSRF-Token"},
		{"BearerConventions", notes.BearerConventions, AuthStrategyHeader},
	} {
		if !strings.Contains(f.value, f.want) {
			t.Errorf("%s = %q, which no longer mentions %q", f.name, f.value, f.want)
		}
	}
	if notes.ReferenceRevision != ReferenceRevision {
		t.Errorf("ReferenceRevision = %q, want the package constant %q", notes.ReferenceRevision, ReferenceRevision)
	}
}

// The README is the half of the discipline a human actually reads, and it is
// generated rather than mirrored: this test is the binding. It fails in both
// directions, which is the whole point — the earlier identity-only mirror let a
// README line assert the opposite of the register it claimed to reflect.
func TestREADMEIsGeneratedFromCompatibilityNotes(t *testing.T) {
	const path = "README.md"

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// A checkout with autocrlf on would otherwise fail on every line.
	readme := strings.ReplaceAll(string(raw), "\r\n", "\n")
	want := renderCompatibilityNotes()

	if *updateREADME {
		updated, err := replaceGeneratedSection(readme, want)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("%s regenerated from CompatibilityNotes()", path)
		return
	}

	got, err := generatedSection(readme)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("the deviations section of %s does not match CompatibilityNotes().\n\n"+
			"That section is generated, not hand-maintained. If you changed the register, "+
			"regenerate it;\nif you changed the README, make the change in "+
			"CompatibilityNotes() (compatibility.go) instead and\nthen regenerate:\n\n"+
			"    go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .\n\n%s",
			path, firstDifference(got, want))
	}
}

// firstDifference reports where the committed section and the freshly rendered
// one part company, because a whole-section dump is unreadable and the first
// differing line is almost always the edit that caused the failure.
func firstDifference(got, want string) string {
	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		g, w := "", ""
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			return fmt.Sprintf("first difference at line %d of the section:\n"+
				"  README.md:                %q\n"+
				"  CompatibilityNotes() renders: %q", i+1, g, w)
		}
	}
	return "the sections differ only in trailing content"
}

// A caller that sorts or filters the register must not affect the next caller.
func TestCompatibilityNotesReturnsAFreshValue(t *testing.T) {
	first := CompatibilityNotes()
	if len(first.KnownDeviations) == 0 {
		t.Fatal("no deviations to test against")
	}
	first.KnownDeviations[0].ID = "clobbered"
	first.KnownDeviations = first.KnownDeviations[:0]

	if second := CompatibilityNotes(); len(second.KnownDeviations) == 0 || second.KnownDeviations[0].ID == "clobbered" {
		t.Error("CompatibilityNotes shares state between calls: editing one caller's copy changed the next's")
	}
}
