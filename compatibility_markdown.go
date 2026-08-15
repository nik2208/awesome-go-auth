package auth

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The README's "Deliberate deviations from the reference" section is generated
// from CompatibilityNotes() rather than written alongside it.
//
// The earlier arrangement kept the two in step by asserting that every id and
// citation in the register also appeared somewhere in the README. That binds
// identity and nothing else: an entry could be reworded, weakened or reversed on
// either side and the suite stayed green — the README was free to assert the
// exact opposite of the data it claimed to mirror. Generation removes the
// second copy instead of policing it. There is one set of words, in
// compatibility.go, and the README section is a rendering of it that
// compatibility_test.go recomputes and compares byte for byte.
//
// The renderer owns layout — headings, bullet labels, citation placement, the
// 80-column wrap — and the register owns every word. That is why the prose
// fields in compatibility.go are markdown.
//
// Nothing here runs at request time; it exists for the test and the -update
// flag that rewrites the section.

const (
	// readmeGeneratedBegin and readmeGeneratedEnd delimit the generated section
	// in README.md. They are anchors, not content: the text between them is
	// replaced wholesale on regeneration, and removing one is itself a test
	// failure.
	readmeGeneratedBegin = "<!-- BEGIN GENERATED: deviations -->"
	readmeGeneratedEnd   = "<!-- END GENERATED: deviations -->"

	// readmeWrapWidth is the column the generated prose wraps at, matching the
	// rest of README.md.
	readmeWrapWidth = 80
)

// readmeGeneratedHeader is the first thing inside the generated block: the
// section's own instructions to whoever opens README.md next. It is generated
// too, so hand-editing the warning fails the same test as hand-editing the
// entries.
const readmeGeneratedHeader = `<!--
GENERATED FILE SECTION — do not edit by hand.

Every word below comes from CompatibilityNotes() in compatibility.go, which is
the single source of truth for the deviation register. To change what this
section says, change the register, then regenerate:

    go test -run TestREADMEIsGeneratedFromCompatibilityNotes -update .

TestREADMEIsGeneratedFromCompatibilityNotes re-renders the register and compares
it against the text below, failing on any difference in either direction: a Go
edit that was not regenerated, and a README edit that has no Go edit behind it,
both fail.
-->`

// renderCompatibilityNotes renders the register as the exact markdown block
// README.md carries between the generated-section markers, with no leading or
// trailing blank lines.
func renderCompatibilityNotes() string {
	notes := CompatibilityNotes()

	var b strings.Builder
	b.WriteString(readmeGeneratedHeader)
	b.WriteString("\n\n## Deliberate deviations from the reference\n\n")

	for _, para := range []string{
		"The standing rule is to reproduce `awesome-node-auth` including its quirks, " +
			"because the family clients are pinned to it. The entries below are the places " +
			"this port knowingly does **not**, each with the reason the rule was set aside.",
		"This section is generated from `CompatibilityNotes()`, which returns the same " +
			"register as data — it is not a second copy kept in step by hand. " +
			"`compatibility_test.go` re-renders it and compares it against this file, so a " +
			"deviation cannot be edited on one side only, and cannot be added to the " +
			"register without appearing here. The test also pins the set of ids and the wire " +
			"facts each entry has to keep stating, so an entry cannot be quietly hollowed " +
			"out by someone who does regenerate.",
		"Citations are `file:line` into `" + notes.ReferenceRevision + "`, the revision the " +
			"whole contract was extracted from.",
	} {
		b.WriteString(wrapMarkdown("", "", para))
		b.WriteString("\n")
	}

	for _, d := range notes.KnownDeviations {
		b.WriteString("### " + d.Title + "\n\n")
		b.WriteString("`" + d.ID + "`\n\n")
		writeBullet(&b, "Surface", d.Surface)
		writeBullet(&b, "This port", d.Behaviour)
		writeBullet(&b, "The reference", withCitations(d.Reference, d.Citations))
		writeBullet(&b, "Why", d.Why)
		for _, n := range d.Notes {
			writeBullet(&b, n.Label, n.Text)
		}
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// writeBullet emits one `- **Label**: text` bullet, wrapped, with continuation
// lines indented under the text.
func writeBullet(b *strings.Builder, label, text string) {
	b.WriteString(wrapMarkdown("- **"+label+"**: ", "  ", sentence(text)))
}

// withCitations appends a Deviation's citations to its Reference sentence, in
// parentheses before the full stop, which is where a reader looks for the
// evidence of the claim they have just read.
func withCitations(reference string, citations []string) string {
	if len(citations) == 0 {
		return reference
	}
	quoted := make([]string, len(citations))
	for i, c := range citations {
		quoted[i] = "`" + c + "`"
	}
	return strings.TrimRight(sentence(reference), ".") + " (" + strings.Join(quoted, ", ") + ")."
}

// sentence gives text a full stop unless it already ends in terminal
// punctuation, so that Surface — a bare route, in the register — reads as a
// sentence in the README without the register having to carry the stop.
func sentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return text
	}
	switch text[len(text)-1] {
	case '.', '!', '?', ':':
		return text
	}
	return text + "."
}

// wrapMarkdown greedily wraps text at readmeWrapWidth runes, prefixing the
// first line with first and every later line with cont. Whitespace in text is
// normalised first, so how the Go string literal happens to be broken across
// source lines does not reach the output.
//
// A token never gets a line break in the middle, even when it overruns the
// width on its own: `POST <prefix>/login` reads as one thing and is written as
// one, and a split code span, though CommonMark folds the newline back to a
// space, makes the raw markdown hard to read and hard to grep.
func wrapMarkdown(first, cont, text string) string {
	words := splitOutsideCodeSpans(text)
	if len(words) == 0 {
		return first + "\n"
	}

	var b strings.Builder
	line := first
	width := utf8.RuneCountInString(first)
	contWidth := utf8.RuneCountInString(cont)

	for i, w := range words {
		wordWidth := utf8.RuneCountInString(w)
		if i > 0 && width+1+wordWidth > readmeWrapWidth {
			b.WriteString(line)
			b.WriteString("\n")
			line, width = cont, contWidth
		} else if i > 0 {
			line += " "
			width++
		}
		line += w
		width += wordWidth
	}
	b.WriteString(line)
	b.WriteString("\n")
	return b.String()
}

// splitOutsideCodeSpans splits text into wrappable tokens on whitespace, except
// inside a backtick code span, whose spaces are part of the thing being quoted
// and must survive. An unterminated backtick makes the rest of the text one
// token, which is conservative in the right direction: it wraps badly rather
// than corrupting the span.
func splitOutsideCodeSpans(text string) []string {
	var (
		words  []string
		cur    strings.Builder
		inCode bool
	)
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	for _, r := range text {
		switch {
		case r == '`':
			inCode = !inCode
			cur.WriteRune(r)
		case !inCode && (r == ' ' || r == '\t' || r == '\n'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return words
}

// generatedSection returns the text README.md currently carries between the
// generated-section markers.
func generatedSection(readme string) (string, error) {
	start := strings.Index(readme, readmeGeneratedBegin)
	if start < 0 {
		return "", fmt.Errorf("README.md has no %s marker: the deviations section is generated, "+
			"and the marker is what says where it goes", readmeGeneratedBegin)
	}
	start += len(readmeGeneratedBegin)

	end := strings.Index(readme[start:], readmeGeneratedEnd)
	if end < 0 {
		return "", fmt.Errorf("README.md has %s but no closing %s", readmeGeneratedBegin, readmeGeneratedEnd)
	}
	return strings.Trim(readme[start:start+end], "\n"), nil
}

// replaceGeneratedSection returns readme with the text between the markers
// replaced by section.
func replaceGeneratedSection(readme, section string) (string, error) {
	if _, err := generatedSection(readme); err != nil {
		return "", err
	}
	start := strings.Index(readme, readmeGeneratedBegin) + len(readmeGeneratedBegin)
	end := start + strings.Index(readme[start:], readmeGeneratedEnd)
	return readme[:start] + "\n" + section + "\n" + readme[end:], nil
}
