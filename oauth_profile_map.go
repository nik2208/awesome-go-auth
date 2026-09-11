package auth

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// profileMapKeys are the five fields a ProfileMap may set, in the order they
// are evaluated — the reference profile's {id, email, emailVerified?, name?,
// picture?} (generic-oauth.strategy.ts:71-77). id is evaluated first so a
// document that cannot identify the user fails before anything else is read.
var profileMapKeys = []string{"id", "email", "emailVerified", "name", "picture"}

func isProfileMapKey(key string) bool {
	for _, k := range profileMapKeys {
		if k == key {
			return true
		}
	}
	return false
}

// CompileProfileMap compiles a declarative profile map into the function
// OAuthProvider.MapProfile takes. It is what NewOAuthService runs over every
// OAuthProvider.ProfileMap, exported so a deployment can validate a map it
// loaded from configuration before it wires anything.
//
// The keys are id, email, emailVerified, name and picture — the fields of the
// reference profile a mapProfile hook returns (generic-oauth.strategy.ts:71-77).
// Any other key is an error, and so is a map without id, since the profile it
// would produce can never identify a user. The values are expressions in this
// grammar, which is this port's own (the reference takes a function):
//
//	expr    = alt ("??" alt)*
//	alt     = path | literal
//	path    = "$" ("." key | "[" index "]")+
//	key     = one or more letters, digits, "_" or "-"
//	index   = one or more decimal digits
//	literal = a double-quoted string, allowed only as the last alternative
//
// Whitespace around an alternative is ignored. Anything else — "$" alone, a
// single-quoted literal, a wildcard, a filter, a slice, a function call, a
// quoted key — is a compile error naming the expression.
//
// Evaluation follows JavaScript's ?? operator: the alternatives are tried in
// order and the first path that resolves to a value that is neither missing
// nor null wins, so an empty string, false or 0 is a value and stops the
// chain; a literal always resolves. A string is taken as is, a number is
// rendered as JavaScript's String() renders it (an integer-valued number has
// no decimal point and no exponent below 1e21) and a boolean becomes "true"
// or "false"; a value that is an object or an array is an evaluation error.
// emailVerified is the one non-string field: its value must be a boolean or
// the strings "true" and "false", and a literal that is neither is refused at
// compile time. id is required — an id that resolves to nothing, or to the
// empty string, is an evaluation error; the other four are optional and stay
// empty (emailVerified nil) when no alternative resolves.
//
// The returned function fills ProviderID, Email, Name, AvatarURL,
// EmailVerified and Raw; Provider is left for the service to set.
func CompileProfileMap(m map[string]string) (func(map[string]any) (OAuthUserInfo, error), error) {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	compiled := make(map[string]profileExpr, len(m))
	for _, key := range keys {
		if !isProfileMapKey(key) {
			return nil, fmt.Errorf("auth: profile map: unknown key %q (want one of %s)", key, strings.Join(profileMapKeys, ", "))
		}
		expr, err := compileProfileExpr(m[key])
		if err != nil {
			return nil, fmt.Errorf("auth: profile map: %s: %w", key, err)
		}
		if key == "emailVerified" && expr.literal != nil {
			if _, err := profileBool(*expr.literal); err != nil {
				return nil, fmt.Errorf("auth: profile map: %s: literal %q is not \"true\" or \"false\" in %q", key, *expr.literal, expr.source)
			}
		}
		compiled[key] = expr
	}
	if _, ok := compiled["id"]; !ok {
		return nil, errors.New("auth: profile map: id is required")
	}

	return func(raw map[string]any) (OAuthUserInfo, error) {
		info := OAuthUserInfo{Raw: raw}
		for _, key := range profileMapKeys {
			expr, ok := compiled[key]
			if !ok {
				continue
			}
			value, found := expr.eval(raw)
			if !found {
				if key == "id" {
					return OAuthUserInfo{}, fmt.Errorf("auth: profile map: id: no alternative resolved in %q", expr.source)
				}
				continue
			}
			if key == "emailVerified" {
				verified, err := profileBool(value)
				if err != nil {
					return OAuthUserInfo{}, fmt.Errorf("auth: profile map: %s: %v in %q", key, err, expr.source)
				}
				info.EmailVerified = &verified
				continue
			}
			text, err := profileString(value)
			if err != nil {
				return OAuthUserInfo{}, fmt.Errorf("auth: profile map: %s: %v in %q", key, err, expr.source)
			}
			switch key {
			case "id":
				if text == "" {
					return OAuthUserInfo{}, fmt.Errorf("auth: profile map: id: resolved to an empty value in %q", expr.source)
				}
				info.ProviderID = text
			case "email":
				info.Email = text
			case "name":
				info.Name = text
			case "picture":
				info.AvatarURL = text
			}
		}
		return info, nil
	}, nil
}

// profileExpr is one compiled ProfileMap value: the paths of its ?? chain in
// order, and the literal that ends the chain when there is one.
type profileExpr struct {
	source  string
	paths   [][]pathSegment
	literal *string
}

// pathSegment is one step of a path: a key into an object or an index into an
// array.
type pathSegment struct {
	key     string
	index   int
	isIndex bool
}

// compileProfileExpr parses one expression. Every error names the expression,
// because a map is usually loaded from configuration and the key alone does
// not say which of several providers is wrong.
func compileProfileExpr(source string) (profileExpr, error) {
	expr := profileExpr{source: source}
	fail := func(msg string) (profileExpr, error) {
		return profileExpr{}, fmt.Errorf("%s in %q", msg, source)
	}
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return fail("empty expression")
	}
	alternatives, err := splitProfileAlternatives(trimmed)
	if err != nil {
		return fail(err.Error())
	}
	for i, alt := range alternatives {
		alt = strings.TrimSpace(alt)
		last := i == len(alternatives)-1
		switch {
		case alt == "":
			return fail("empty alternative around ??")
		case alt[0] == '"':
			text, err := parseProfileLiteral(alt)
			if err != nil {
				return fail(err.Error())
			}
			if !last {
				return fail("a literal must be the last alternative")
			}
			expr.literal = &text
		case alt[0] == '\'':
			return fail("single-quoted literal; use double quotes")
		case alt[0] == '$':
			path, err := parseProfilePath(alt)
			if err != nil {
				return fail(err.Error())
			}
			expr.paths = append(expr.paths, path)
		default:
			return fail(fmt.Sprintf("alternative %q is neither a $ path nor a double-quoted literal", alt))
		}
	}
	return expr, nil
}

// splitProfileAlternatives cuts an expression at every ?? that is outside a
// double-quoted literal, so a literal may contain the two characters.
func splitProfileAlternatives(s string) ([]string, error) {
	var out []string
	start := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			inQuote = !inQuote
		case !inQuote && s[i] == '?':
			if i+1 < len(s) && s[i+1] == '?' {
				out = append(out, s[start:i])
				start = i + 2
				i++
				continue
			}
			return nil, errors.New("a lone ? (the fallback operator is ??)")
		}
	}
	if inQuote {
		return nil, errors.New("unterminated string literal")
	}
	return append(out, s[start:]), nil
}

// parseProfileLiteral reads a double-quoted literal. There are no escapes: the
// text between the quotes is the value, so a literal cannot itself contain a
// double quote.
func parseProfileLiteral(alt string) (string, error) {
	closing := strings.IndexByte(alt[1:], '"')
	if closing < 0 {
		return "", errors.New("unterminated string literal")
	}
	text := alt[1 : 1+closing]
	if rest := strings.TrimSpace(alt[2+closing:]); rest != "" {
		return "", fmt.Errorf("unexpected %q after the literal %q", rest, text)
	}
	return text, nil
}

// parseProfilePath reads a $ path: one or more .key or [index] steps. It is
// deliberately small — no wildcards, filters, slices, quoted keys or recursive
// descent — so that a map can be read without a JSONPath reference at hand.
func parseProfilePath(alt string) ([]pathSegment, error) {
	if alt == "$" {
		return nil, errors.New("$ alone selects the whole document; name a field")
	}
	var path []pathSegment
	i := 1
	for i < len(alt) {
		switch alt[i] {
		case '.':
			i++
			start := i
			for i < len(alt) && isProfileKeyChar(alt[i]) {
				i++
			}
			if start == i {
				return nil, fmt.Errorf("expected a field name after . at offset %d", start)
			}
			path = append(path, pathSegment{key: alt[start:i]})
		case '[':
			i++
			start := i
			for i < len(alt) && alt[i] >= '0' && alt[i] <= '9' {
				i++
			}
			if start == i {
				return nil, fmt.Errorf("expected a decimal index after [ at offset %d", start)
			}
			if i >= len(alt) || alt[i] != ']' {
				return nil, fmt.Errorf("expected ] after the index at offset %d", i)
			}
			index, err := strconv.Atoi(alt[start:i])
			if err != nil {
				return nil, fmt.Errorf("index %q is out of range", alt[start:i])
			}
			i++
			path = append(path, pathSegment{index: index, isIndex: true})
		default:
			return nil, fmt.Errorf("unexpected %q at offset %d (a path is $ followed by .key or [index] steps)", string(alt[i]), i)
		}
	}
	return path, nil
}

// isProfileKeyChar bounds a bare key: ASCII letters, digits, underscore and
// hyphen. The scanner walks bytes, so the set is ASCII by construction; a key
// with any other character has no spelling in the grammar.
func isProfileKeyChar(b byte) bool {
	return b == '_' || b == '-' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// eval returns the first alternative that resolves, JavaScript ?? style: a
// path whose value is missing or null is skipped, anything else wins, and the
// literal, when present, always does.
func (e profileExpr) eval(raw map[string]any) (any, bool) {
	for _, path := range e.paths {
		if value, ok := resolveProfilePath(raw, path); ok {
			return value, true
		}
	}
	if e.literal != nil {
		return *e.literal, true
	}
	return nil, false
}

// resolveProfilePath walks the document. A key step needs an object and a
// present key; an index step needs an array long enough; a null at the end is
// as good as absent, since JavaScript's ?? treats the two alike.
func resolveProfilePath(raw map[string]any, path []pathSegment) (any, bool) {
	var current any = raw
	for _, segment := range path {
		if segment.isIndex {
			array, ok := current.([]any)
			if !ok || segment.index >= len(array) {
				return nil, false
			}
			current = array[segment.index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = object[segment.key]; !ok {
			return nil, false
		}
	}
	if current == nil {
		return nil, false
	}
	return current, true
}

// profileString renders a resolved scalar the way JavaScript's String() would
// render the JSON value: strings as they are, numbers through jsNumberString,
// booleans as true/false. An object or an array has no sensible string form
// and is an error rather than "[object Object]".
func profileString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case float64:
		return jsNumberString(v), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case map[string]any:
		return "", errors.New("resolves to an object, not a scalar")
	case []any:
		return "", errors.New("resolves to an array, not a scalar")
	default:
		return "", fmt.Errorf("resolves to an unsupported %T", value)
	}
}

// profileBool reads emailVerified: a JSON boolean, or the strings "true" and
// "false" for providers that send the flag as text. Nothing else is coerced —
// a 1, a "yes" or an object is an error, not a guess.
func profileBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		switch v {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return false, fmt.Errorf("resolves to %q, want a boolean or \"true\"/\"false\"", v)
	case map[string]any:
		return false, errors.New("resolves to an object, want a boolean or \"true\"/\"false\"")
	case []any:
		return false, errors.New("resolves to an array, want a boolean or \"true\"/\"false\"")
	default:
		return false, fmt.Errorf("resolves to %v, want a boolean or \"true\"/\"false\"", value)
	}
}

// jsNumberString renders a float64 the way ECMAScript's Number::toString does,
// so that a numeric provider id maps to the same text a mapProfile hook
// written in JavaScript would produce: the shortest digits that round-trip,
// laid out without an exponent for magnitudes from 1e-6 up to (excluding)
// 1e21, and as d.ddde±x beyond — 12345 is "12345", 1.5 is "1.5", 1e21 is
// "1e+21", 1e-7 is "1e-7".
func jsNumberString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	negative := f < 0
	if negative {
		f = -f
	}
	// Shortest round-trip digits with the decimal exponent: d.ddde±xx.
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, _ := strconv.Atoi(exponent)
	k := len(digits)
	n := e + 1 // the value is 0.<digits> × 10^n
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		sign, exp := "+", n-1
		if exp < 0 {
			sign, exp = "-", -exp
		}
		if k == 1 {
			out = digits + "e" + sign + strconv.Itoa(exp)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(exp)
		}
	}
	if negative {
		return "-" + out
	}
	return out
}
