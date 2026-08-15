package auth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These tests are the third layer of the deviation discipline: the exported
// list is the first, the README mirror the second, and this file is what stops
// either drifting.
//
// What to assert is a real choice. Pinning every word makes the test a second
// copy of the data — every wording fix becomes a two-file edit, so the test
// gets updated reflexively and stops being read. Pinning only len() != 0 is
// worthless: it passes on an empty register with one entry left in it. So the
// tests below pin three things and deliberately leave the prose free:
//
//   - Identity, exactly. TestCompatibilityNotesRegister compares the whole ID
//     set. Dropping a deviation fails, and so does adding one — an addition has
//     to be a deliberate act that also updates the README, which is the rule
//     this mechanism exists to enforce.
//   - Substance, by load-bearing token. TestCompatibilityNotesClaims requires a
//     handful of wire facts per entry — the status codes, the header and field
//     names, the numbers, the reference mechanism. They are what the entry
//     means, not how it is phrased, so a rewrite survives while a hollowing-out
//     or a reversal does not.
//   - Form. TestCompatibilityNotesAreWellFormed requires every field populated
//     and every citation shaped like file:line, so an entry cannot be reduced to
//     an unfalsifiable sentence with the evidence removed.

// wantDeviationIDs is the register. Changing this set is the point at which a
// deviation is added or retired, and it must be changed together with
// CompatibilityNotes and the README.
var wantDeviationIDs = []string{
	"advertised-2fa-methods-require-store-support",
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
}

// citationPattern is the reference source citation shape: a TypeScript file and
// either a line or a line range.
var citationPattern = regexp.MustCompile(`^[a-z0-9.\-]+\.ts:\d+(-\d+)?$`)

// entryText flattens an entry so a claim can be asserted against the whole of
// it. Which field carries a fact is an editorial matter; that the entry states
// it is not.
func entryText(d Deviation) string {
	return strings.Join([]string{d.ID, d.Surface, d.Behaviour, d.Reference, d.Why}, "\n")
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
				"retiring one means removing it from wantDeviationIDs and the README too", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("deviation %q is new to CompatibilityNotes; add it to wantDeviationIDs, "+
				"give it an entry in wantClaims and mirror it in the README", id)
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
				{"Surface", d.Surface},
				{"Behaviour", d.Behaviour},
				{"Reference", d.Reference},
				{"Why", d.Why},
			} {
				if strings.TrimSpace(f.value) == "" {
					t.Errorf("%s is empty", f.name)
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

// The README is the half of the discipline a human actually reads, so the
// mirror is machine-checked rather than promised. Keying on the ID and the
// citations pins that the entry and its evidence are present without pinning
// how the README words them.
func TestREADMEMirrorsCompatibilityNotes(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	text := string(readme)

	for _, d := range CompatibilityNotes().KnownDeviations {
		t.Run(d.ID, func(t *testing.T) {
			if !strings.Contains(text, d.ID) {
				t.Errorf("README.md does not mention %q. Every deviation is mirrored there; "+
					"that is the rule this test exists to keep.", d.ID)
			}
			for _, c := range d.Citations {
				if !strings.Contains(text, c) {
					t.Errorf("README.md does not carry citation %q for %q, so a reader cannot "+
						"check the claim against the reference", c, d.ID)
				}
			}
		})
	}
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
