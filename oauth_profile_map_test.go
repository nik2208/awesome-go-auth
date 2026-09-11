package auth

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nestedProfileDoc is the shape a ProfileMap exists for: the identity buried
// two levels down, the address split over two fields the way Microsoft Graph
// splits mail and userPrincipalName, the verified flag sent as text, the
// picture inside an array.
const nestedProfileDoc = `{
  "data": {
    "user": {
      "id": 7001,
      "mail": null,
      "userPrincipalName": "nested@example.com",
      "verified": "true",
      "profile": {"displayName": "Nested User", "photos": [{"url": "https://img.example.com/n.png"}]},
      "tags": ["a", "b"],
      "empty": "",
      "zero": 0,
      "off": false
    }
  }
}`

func decodeDoc(t *testing.T, doc string) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	return raw
}

// evalExpr compiles one expression and evaluates it as a string field.
func evalExpr(t *testing.T, expr, doc string) (string, bool, error) {
	t.Helper()
	compiled, err := compileProfileExpr(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	value, found := compiled.eval(decodeDoc(t, doc))
	if !found {
		return "", false, nil
	}
	text, err := profileString(value)
	return text, true, err
}

// The grammar's valid forms, evaluated over documents, with JavaScript's ??
// semantics: a missing or null path falls through, anything else — an empty
// string, false, 0 — is a value and wins.
func TestProfileMapGrammar_Valid(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
		doc  string
		want string
		none bool // the expression compiles and resolves to nothing
	}{
		{"top-level key", `$.id`, `{"id":"u1"}`, "u1", false},
		{"nested keys", `$.data.user.userPrincipalName`, nestedProfileDoc, "nested@example.com", false},
		{"index into an array of objects", `$.data.user.profile.photos[0].url`, nestedProfileDoc, "https://img.example.com/n.png", false},
		{"index into an array of scalars", `$.data.user.tags[1]`, nestedProfileDoc, "b", false},
		{"nested arrays", `$.m[1][0]`, `{"m":[[1,2],[3,4]]}`, "3", false},
		{"an index past the end resolves to nothing", `$.data.user.tags[2]`, nestedProfileDoc, "", true},
		{"an index on an object resolves to nothing", `$[0]`, `{"0":"zero"}`, "", true},
		{"a key on an array resolves to nothing", `$.data.user.tags.length`, nestedProfileDoc, "", true},
		{"a key on a scalar resolves to nothing", `$.data.user.id.value`, nestedProfileDoc, "", true},
		{"null resolves to nothing", `$.data.user.mail`, nestedProfileDoc, "", true},
		{"null falls through to the next alternative", `$.data.user.mail ?? $.data.user.userPrincipalName`, nestedProfileDoc, "nested@example.com", false},
		{"missing falls through to the next alternative", `$.mail ?? $.userPrincipalName`, `{"userPrincipalName":"upn@example.com"}`, "upn@example.com", false},
		{"the first resolved alternative wins", `$.mail ?? $.userPrincipalName`, `{"mail":"mail@example.com","userPrincipalName":"upn@example.com"}`, "mail@example.com", false},
		{"a chain with nothing resolved and no literal resolves to nothing", `$.a ?? $.b`, `{}`, "", true},
		{"a three-way chain ending in a literal", `$.a ?? $.b ?? "fallback"`, `{}`, "fallback", false},
		{"a literal alone", `"literal"`, `{}`, "literal", false},
		{"an empty literal", `""`, `{}`, "", false},
		{"a literal keeps ?? inside its quotes", `"a ?? b"`, `{}`, "a ?? b", false},
		{"a literal keeps its inner whitespace", `"  spaced  "`, `{}`, "  spaced  ", false},
		{"whitespace around alternatives is ignored", `   $.a   ??   $.b   `, `{"b":"bee"}`, "bee", false},
		{"no whitespace around ?? is fine too", `$.a??$.b`, `{"b":"bee"}`, "bee", false},
		{"keys may carry underscores and hyphens", `$.given_name ?? $.family-name`, `{"family-name":"Doe"}`, "Doe", false},
		{"keys may be digits", `$.0`, `{"0":"zero"}`, "zero", false},
		{"an empty string is a value", `$.data.user.empty ?? "x"`, nestedProfileDoc, "", false},
		{"false is a value", `$.data.user.off ?? "x"`, nestedProfileDoc, "false", false},
		{"zero is a value", `$.data.user.zero ?? "x"`, nestedProfileDoc, "0", false},
		{"true is rendered as text", `$.v`, `{"v":true}`, "true", false},
		{"an integer-valued number has no decimal point", `$.data.user.id`, nestedProfileDoc, "7001", false},
		{"a large integer is not rendered with an exponent", `$.n`, `{"n":123456789012345680000}`, "123456789012345680000", false},
		{"a fraction keeps its digits", `$.n`, `{"n":1.5}`, "1.5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found, err := evalExpr(t, tc.expr, tc.doc)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.expr, err)
			}
			if tc.none {
				if found {
					t.Fatalf("%q resolved to %q, want nothing", tc.expr, got)
				}
				return
			}
			if !found {
				t.Fatalf("%q resolved to nothing, want %q", tc.expr, tc.want)
			}
			if got != tc.want {
				t.Fatalf("%q = %q, want %q", tc.expr, got, tc.want)
			}
		})
	}
}

// Every way an expression can fail to compile. Each error names the whole
// expression, which is the only thing a configuration author can search for.
func TestProfileMapGrammar_CompileErrors(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want string
	}{
		{``, "empty expression"},
		{`   `, "empty expression"},
		{`$`, "$ alone"},
		{`$a`, "unexpected \"a\""},
		{`$.`, "expected a field name after ."},
		{`$.a.`, "expected a field name after ."},
		{`$.a..b`, "expected a field name after ."},
		{`$..a`, "expected a field name after ."},
		{`$.*`, "expected a field name after ."},
		{`$.a[]`, "expected a decimal index after ["},
		{`$.a[*]`, "expected a decimal index after ["},
		{`$.a[-1]`, "expected a decimal index after ["},
		{`$.a["b"]`, "expected a decimal index after ["},
		{`$.a['b']`, "expected a decimal index after ["},
		{`$.a[0:1]`, "expected ] after the index"},
		{`$.a[1`, "expected ] after the index"},
		{`$.a[?(@.x)]`, "a lone ?"},
		{`$.a b`, "unexpected \" \""},
		{`$.a()`, "unexpected \"(\""},
		{`$.a.toLowerCase()`, "unexpected \"(\""},
		{`$.a/b`, "unexpected \"/\""},
		{`$.a.@odata`, "expected a field name after ."},
		{`'single'`, "single-quoted literal"},
		{`"unterminated`, "unterminated string literal"},
		{`"a" "b"`, "after the literal"},
		{`"a"x`, "after the literal"},
		{`"first" ?? $.b`, "a literal must be the last alternative"},
		{`"a" ?? "b"`, "a literal must be the last alternative"},
		{`$.a ??`, "empty alternative"},
		{`?? $.a`, "empty alternative"},
		{`$.a ?? ?? $.b`, "empty alternative"},
		{`$.a ? $.b`, "a lone ?"},
		{`email`, "neither a $ path nor a double-quoted literal"},
		{`@.email`, "neither a $ path nor a double-quoted literal"},
		{`${email}`, "unexpected \"{\""},
		{`$.a ?? email`, "neither a $ path nor a double-quoted literal"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			_, err := compileProfileExpr(tc.expr)
			if err == nil {
				t.Fatalf("%q compiled, want an error containing %q", tc.expr, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%q: error %q does not contain %q", tc.expr, err, tc.want)
			}
			if !strings.Contains(err.Error(), strconvQuote(tc.expr)) {
				t.Fatalf("%q: error %q does not name the expression", tc.expr, err)
			}
		})
	}
}

// strconvQuote is how the compiler renders the expression inside its errors.
func strconvQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// Evaluation errors: a resolved value that is not a scalar. The alternative
// resolved, so — exactly as JavaScript's ?? would — the chain does not move
// on to the next one.
func TestProfileMapGrammar_EvalErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
		want string
	}{
		{"an object", `$.data.user.profile`, "resolves to an object"},
		{"an array", `$.data.user.tags`, "resolves to an array"},
		{"an object does not fall through to the literal", `$.data ?? "fallback"`, "resolves to an object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, found, err := evalExpr(t, tc.expr, nestedProfileDoc)
			if !found {
				t.Fatalf("%q resolved to nothing", tc.expr)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%q: error %v, want one containing %q", tc.expr, err, tc.want)
			}
		})
	}
}

// jsNumberString is ECMAScript's Number::toString, so a numeric id maps to
// the text a JavaScript mapProfile hook would have produced.
func TestJSNumberString(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{1, "1"},
		{-1, "-1"},
		{7001, "7001"},
		{12345678, "12345678"},
		{1e20, "100000000000000000000"},
		{123456789012345680000, "123456789012345680000"},
		{1e21, "1e+21"},
		{1.5e21, "1.5e+21"},
		{-1e21, "-1e+21"},
		{1.5, "1.5"},
		{0.1, "0.1"},
		{0.000001, "0.000001"},
		{1e-7, "1e-7"},
		{1.5e-7, "1.5e-7"},
		{123.456, "123.456"},
		{9007199254740993, "9007199254740992"}, // past 2^53, as JSON.parse would have read it
		{math.NaN(), "NaN"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
	} {
		if got := jsNumberString(tc.in); got != tc.want {
			t.Errorf("jsNumberString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// CompileProfileMap accepts the five reference profile keys and nothing else,
// requires id, and checks an emailVerified literal at compile time.
func TestCompileProfileMap_Keys(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    map[string]string
		want string
	}{
		{"unknown key", map[string]string{"id": "$.id", "avatar": "$.picture"}, `unknown key "avatar" (want one of id, email, emailVerified, name, picture)`},
		{"the keys are case-sensitive", map[string]string{"id": "$.id", "Email": "$.email"}, `unknown key "Email"`},
		{"id is required", map[string]string{"email": "$.email"}, "id is required"},
		{"an empty map has no id", map[string]string{}, "id is required"},
		{"a nil map has no id", nil, "id is required"},
		{"a bad expression names its key", map[string]string{"id": "$.id", "email": "$"}, `email: $ alone selects the whole document; name a field in "$"`},
		{"an emailVerified literal must be true or false", map[string]string{"id": "$.id", "emailVerified": `$.v ?? "yes"`}, `emailVerified: literal "yes" is not "true" or "false" in "$.v ?? \"yes\""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapper, err := CompileProfileMap(tc.m)
			if err == nil {
				t.Fatalf("compiled, want an error containing %q", tc.want)
			}
			if mapper != nil {
				t.Fatal("a failed compile returned a mapper")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}

	t.Run("every reference key compiles", func(t *testing.T) {
		if _, err := CompileProfileMap(map[string]string{
			"id":            "$.id",
			"email":         "$.email",
			"emailVerified": `$.email_verified ?? "false"`,
			"name":          "$.name",
			"picture":       "$.picture",
		}); err != nil {
			t.Fatalf("CompileProfileMap: %v", err)
		}
	})
}

// The compiled function over documents: every field lands where the default
// mapping would have put it, optional fields stay empty, emailVerified reads a
// boolean or its text form, id is enforced, Raw is the document.
func TestCompileProfileMap_Evaluate(t *testing.T) {
	full := map[string]string{
		"id":            "$.data.user.id",
		"email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
		"emailVerified": "$.data.user.verified",
		"name":          "$.data.user.profile.displayName",
		"picture":       "$.data.user.profile.photos[0].url",
	}
	mapper, err := CompileProfileMap(full)
	if err != nil {
		t.Fatalf("CompileProfileMap: %v", err)
	}
	raw := decodeDoc(t, nestedProfileDoc)
	info, err := mapper(raw)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if info.ProviderID != "7001" {
		t.Errorf("ProviderID = %q, want %q", info.ProviderID, "7001")
	}
	if info.Email != "nested@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "nested@example.com")
	}
	if describeBool(info.EmailVerified) != "true" {
		t.Errorf("EmailVerified = %s, want true", describeBool(info.EmailVerified))
	}
	if info.Name != "Nested User" {
		t.Errorf("Name = %q, want %q", info.Name, "Nested User")
	}
	if info.AvatarURL != "https://img.example.com/n.png" {
		t.Errorf("AvatarURL = %q, want the photo url", info.AvatarURL)
	}
	if info.Provider != "" {
		t.Errorf("Provider = %q, want it left for the service", info.Provider)
	}
	if info.Raw == nil || info.Raw["data"] == nil {
		t.Errorf("Raw = %v, want the document", info.Raw)
	}

	t.Run("optional fields stay empty when nothing resolves", func(t *testing.T) {
		info, err := mapper(decodeDoc(t, `{"data":{"user":{"id":"only-id"}}}`))
		if err != nil {
			t.Fatalf("map: %v", err)
		}
		if info.ProviderID != "only-id" || info.Email != "" || info.Name != "" || info.AvatarURL != "" || info.EmailVerified != nil {
			t.Fatalf("info = %+v, want only the id set", info)
		}
	})

	t.Run("emailVerified", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			doc  string
			want string // describeBool, or the error substring
			fail bool
		}{
			{"boolean true", `{"id":"1","v":true}`, "true", false},
			{"boolean false", `{"id":"1","v":false}`, "false", false},
			{"the string true", `{"id":"1","v":"true"}`, "true", false},
			{"the string false", `{"id":"1","v":"false"}`, "false", false},
			{"absent", `{"id":"1"}`, "nil", false},
			{"null", `{"id":"1","v":null}`, "nil", false},
			{"a number is not coerced", `{"id":"1","v":1}`, "resolves to 1, want a boolean", true},
			{"another string is not coerced", `{"id":"1","v":"yes"}`, `resolves to "yes", want a boolean`, true},
			{"an object is refused", `{"id":"1","v":{}}`, "resolves to an object, want a boolean", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mapper, err := CompileProfileMap(map[string]string{"id": "$.id", "emailVerified": "$.v"})
				if err != nil {
					t.Fatalf("CompileProfileMap: %v", err)
				}
				info, err := mapper(decodeDoc(t, tc.doc))
				if tc.fail {
					if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("error %v, want one containing %q", err, tc.want)
					}
					if !strings.Contains(err.Error(), `emailVerified: `) || !strings.HasSuffix(err.Error(), ` in "$.v"`) {
						t.Fatalf("error %q does not name the key and the expression", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("map: %v", err)
				}
				if describeBool(info.EmailVerified) != tc.want {
					t.Fatalf("EmailVerified = %s, want %s", describeBool(info.EmailVerified), tc.want)
				}
			})
		}
	})

	t.Run("id", func(t *testing.T) {
		mapper, err := CompileProfileMap(map[string]string{"id": "$.id ?? $.sub"})
		if err != nil {
			t.Fatalf("CompileProfileMap: %v", err)
		}
		for _, tc := range []struct {
			name string
			doc  string
			want string
		}{
			{"nothing resolves", `{"email":"x@example.com"}`, `id: no alternative resolved in "$.id ?? $.sub"`},
			{"an empty string resolves and is refused", `{"id":"","sub":"the-sub"}`, `id: resolved to an empty value in "$.id ?? $.sub"`},
			{"an object resolves and is refused", `{"id":{"nested":true},"sub":"the-sub"}`, `id: resolves to an object, not a scalar in "$.id ?? $.sub"`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := mapper(decodeDoc(t, tc.doc))
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %v, want one containing %q", err, tc.want)
				}
			})
		}
		info, err := mapper(decodeDoc(t, `{"sub":"the-sub"}`))
		if err != nil || info.ProviderID != "the-sub" {
			t.Fatalf("info = %+v, err = %v; want the sub", info, err)
		}
	})

	t.Run("a literal id always resolves", func(t *testing.T) {
		mapper, err := CompileProfileMap(map[string]string{"id": `$.id ?? "anonymous"`})
		if err != nil {
			t.Fatalf("CompileProfileMap: %v", err)
		}
		info, err := mapper(map[string]any{})
		if err != nil || info.ProviderID != "anonymous" {
			t.Fatalf("info = %+v, err = %v; want the literal", info, err)
		}
	})
}

// The MapProfile hook, applied by ExchangeCodePKCE in place of the default
// mapping (generic-oauth.strategy.ts:151-153): the hook sees the raw
// document, the service fills Provider and Raw, and a hook error takes the
// profile-failed path.
func TestOAuthService_ExchangeCode_MapProfile(t *testing.T) {
	srv := newFakeUserInfoServer(t, nestedProfileDoc, "[]", http.StatusOK)
	p := srv.provider("acme")
	var seen map[string]any
	p.MapProfile = func(raw map[string]any) (OAuthUserInfo, error) {
		seen = raw
		user := raw["data"].(map[string]any)["user"].(map[string]any)
		verified := true
		return OAuthUserInfo{
			ProviderID:    "hook-" + jsNumberString(user["id"].(float64)),
			Email:         user["userPrincipalName"].(string),
			EmailVerified: &verified,
			Name:          "from the hook",
			Provider:      "not-the-service", // overwritten by the service
		}, nil
	}
	svc := NewOAuthService(p)
	info, err := svc.ExchangeCode(context.Background(), "acme", "code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if seen == nil || seen["data"] == nil {
		t.Fatalf("the hook did not receive the raw document: %v", seen)
	}
	if info.ProviderID != "hook-7001" || info.Email != "nested@example.com" || info.Name != "from the hook" {
		t.Fatalf("info = %+v, want the hook's profile", info)
	}
	if describeBool(info.EmailVerified) != "true" {
		t.Fatalf("EmailVerified = %s, want true", describeBool(info.EmailVerified))
	}
	if info.Provider != "acme" {
		t.Fatalf("Provider = %q, want the service to set %q", info.Provider, "acme")
	}
	if info.Raw == nil || info.Raw["data"] == nil {
		t.Fatalf("Raw = %v, want the document filled in by the service", info.Raw)
	}

	t.Run("a hook error is a profile failure", func(t *testing.T) {
		p := srv.provider("acme")
		p.MapProfile = func(map[string]any) (OAuthUserInfo, error) {
			return OAuthUserInfo{}, errors.New("no id in this document")
		}
		svc := NewOAuthService(p)
		_, err := svc.ExchangeCode(context.Background(), "acme", "code")
		if !errors.Is(err, errOAuthProfile) {
			t.Fatalf("err = %v, want the profile-failed sentinel", err)
		}
		if !strings.Contains(err.Error(), "no id in this document") {
			t.Fatalf("err = %v, want the hook's message kept", err)
		}
		if got := OAuthHTTPError(err); got.Status != http.StatusUnauthorized || got.Code != CodeOAuthProfileFailed {
			t.Fatalf("wire error = %+v, want 401 %s", got, CodeOAuthProfileFailed)
		}
	})

	// The hook replaces the whole mapping, the preset's second call included:
	// a github provider with a hook never consults /user/emails.
	t.Run("a hook on the github preset skips the emails fallback", func(t *testing.T) {
		srv := newFakeUserInfoServer(t, `{"id":42,"login":"octo"}`, `[{"email":"e@example.com","primary":true,"verified":true}]`, http.StatusOK)
		p := srv.provider("github")
		p.MapProfile = func(raw map[string]any) (OAuthUserInfo, error) {
			return OAuthUserInfo{ProviderID: "gh-" + jsNumberString(raw["id"].(float64)), Email: "hook@example.com"}, nil
		}
		svc := NewOAuthService(p)
		info, err := svc.ExchangeCode(context.Background(), "github", "code")
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if info.ProviderID != "gh-42" || info.Email != "hook@example.com" {
			t.Fatalf("info = %+v, want the hook's profile", info)
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.emailsCalls != 0 {
			t.Fatalf("/user/emails was called %d times under a hook", srv.emailsCalls)
		}
	})
}

// The declarative map through the service: compiled by NewOAuthService,
// applied by ExchangeCodePKCE, its evaluation errors on the profile-failed
// path, and an unrelated provider unaffected.
func TestOAuthService_ExchangeCode_ProfileMap(t *testing.T) {
	srv := newFakeUserInfoServer(t, nestedProfileDoc, "[]", http.StatusOK)
	p := srv.provider("acme")
	p.ProfileMap = map[string]string{
		"id":            "$.data.user.id",
		"email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
		"emailVerified": "$.data.user.verified",
		"name":          "$.data.user.profile.displayName",
		"picture":       "$.data.user.profile.photos[0].url",
	}
	svc, err := NewOAuthServiceWithConfig(p)
	if err != nil {
		t.Fatalf("NewOAuthServiceWithConfig: %v", err)
	}
	info, err := svc.ExchangeCode(context.Background(), "acme", "code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	want := OAuthUserInfo{
		ProviderID: "7001",
		Provider:   "acme",
		Email:      "nested@example.com",
		Name:       "Nested User",
		AvatarURL:  "https://img.example.com/n.png",
	}
	if info.ProviderID != want.ProviderID || info.Provider != want.Provider || info.Email != want.Email || info.Name != want.Name || info.AvatarURL != want.AvatarURL {
		t.Fatalf("info = %+v, want %+v", info, want)
	}
	if describeBool(info.EmailVerified) != "true" {
		t.Fatalf("EmailVerified = %s, want true (the string form)", describeBool(info.EmailVerified))
	}
	if info.Raw == nil || info.Raw["data"] == nil {
		t.Fatalf("Raw = %v, want the document", info.Raw)
	}

	t.Run("an evaluation error is a profile failure", func(t *testing.T) {
		flat := newFakeUserInfoServer(t, `{"sub":"acme-1","email":"flat@example.com"}`, "[]", http.StatusOK)
		p := flat.provider("acme")
		p.ProfileMap = map[string]string{"id": "$.data.user.id"}
		svc := NewOAuthService(p)
		_, err := svc.ExchangeCode(context.Background(), "acme", "code")
		if !errors.Is(err, errOAuthProfile) {
			t.Fatalf("err = %v, want the profile-failed sentinel", err)
		}
		if !strings.Contains(err.Error(), `id: no alternative resolved in "$.data.user.id"`) {
			t.Fatalf("err = %v, want the map's message kept", err)
		}
		if got := OAuthHTTPError(err); got.Status != http.StatusUnauthorized || got.Code != CodeOAuthProfileFailed {
			t.Fatalf("wire error = %+v, want 401 %s", got, CodeOAuthProfileFailed)
		}
	})

	t.Run("a map on a preset replaces its mapping", func(t *testing.T) {
		srv := newFakeUserInfoServer(t, `{"sub":"g-1","email":"g@example.com","custom":{"handle":"gee"}}`, "[]", http.StatusOK)
		p := srv.provider("google")
		p.ProfileMap = map[string]string{"id": "$.custom.handle", "email": "$.email"}
		svc := NewOAuthService(p)
		info, err := svc.ExchangeCode(context.Background(), "google", "code")
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if info.ProviderID != "gee" || info.Provider != "google" {
			t.Fatalf("info = %+v, want the map's id under the google name", info)
		}
	})
}

// MapProfile wins over ProfileMap when a provider carries both; the map is
// still compiled, so a broken one is still reported.
func TestOAuthService_MapProfileWinsOverProfileMap(t *testing.T) {
	srv := newFakeUserInfoServer(t, nestedProfileDoc, "[]", http.StatusOK)
	p := srv.provider("acme")
	p.ProfileMap = map[string]string{"id": "$.data.user.id", "email": "$.data.user.userPrincipalName"}
	p.MapProfile = func(map[string]any) (OAuthUserInfo, error) {
		return OAuthUserInfo{ProviderID: "from-the-function", Email: "function@example.com"}, nil
	}
	svc, err := NewOAuthServiceWithConfig(p)
	if err != nil {
		t.Fatalf("NewOAuthServiceWithConfig: %v", err)
	}
	info, err := svc.ExchangeCode(context.Background(), "acme", "code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if info.ProviderID != "from-the-function" || info.Email != "function@example.com" {
		t.Fatalf("info = %+v, want MapProfile's profile", info)
	}

	t.Run("a broken ProfileMap is still a configuration error", func(t *testing.T) {
		p := srv.provider("acme")
		p.ProfileMap = map[string]string{"id": "$"}
		p.MapProfile = func(map[string]any) (OAuthUserInfo, error) {
			return OAuthUserInfo{ProviderID: "x"}, nil
		}
		if _, err := NewOAuthServiceWithConfig(p); err == nil {
			t.Fatal("NewOAuthServiceWithConfig accepted a ProfileMap that does not compile")
		}
	})
}

// A ProfileMap that does not compile: NewOAuthService does not panic and
// records the error, which the provider's exchanges return before touching the
// network and which the wire renders as a 500 — a configuration error, not a
// client one — while the other providers keep working.
// NewOAuthServiceWithConfig reports every broken provider at once.
func TestOAuthService_ProfileMapCompileError(t *testing.T) {
	untouched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the provider was contacted at %s despite a broken profile map", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(untouched.Close)
	broken := OAuthProvider{
		Name:        "broken",
		ClientID:    "cid",
		TokenURL:    untouched.URL + "/token",
		UserInfoURL: untouched.URL + "/user",
		ProfileMap:  map[string]string{"id": "$.id", "email": "'single'"},
	}
	good := newFakeUserInfoServer(t, `{"id":"g-1","email":"good@example.com"}`, "[]", http.StatusOK).provider("good")

	svc := NewOAuthService(broken, good)
	_, err := svc.ExchangeCode(context.Background(), "broken", "code")
	if err == nil {
		t.Fatal("ExchangeCode succeeded through a provider whose map did not compile")
	}
	want := `auth: oauth provider "broken": profile map: email: single-quoted literal; use double quotes in "'single'"`
	if err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
	if errors.Is(err, errOAuthProfile) {
		t.Fatal("a configuration error must not look like a provider failure")
	}
	if got := OAuthHTTPError(err); got != HTTPErrInternal {
		t.Fatalf("wire error = %+v, want the 500 fallback", got)
	}
	if info, err := svc.ExchangeCode(context.Background(), "good", "code"); err != nil || info.ProviderID != "g-1" {
		t.Fatalf("the unrelated provider failed too: info = %+v, err = %v", info, err)
	}

	t.Run("NewOAuthServiceWithConfig names every broken provider", func(t *testing.T) {
		alsoBroken := broken
		alsoBroken.Name = "also-broken"
		alsoBroken.ProfileMap = map[string]string{"email": "$.email"}
		svc, err := NewOAuthServiceWithConfig(good, broken, alsoBroken)
		if err == nil {
			t.Fatal("NewOAuthServiceWithConfig accepted a broken map")
		}
		if svc != nil {
			t.Fatal("a failed NewOAuthServiceWithConfig returned a service")
		}
		for _, want := range []string{
			`auth: oauth provider "broken": profile map: email: single-quoted literal`,
			`auth: oauth provider "also-broken": profile map: id is required`,
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not contain %q", err, want)
			}
		}
	})

	t.Run("a later provider with the same name replaces the broken one", func(t *testing.T) {
		fixed := good
		fixed.Name = "broken"
		svc, err := NewOAuthServiceWithConfig(broken, fixed)
		if err != nil {
			t.Fatalf("NewOAuthServiceWithConfig: %v", err)
		}
		if info, err := svc.ExchangeCode(context.Background(), "broken", "code"); err != nil || info.ProviderID != "g-1" {
			t.Fatalf("info = %+v, err = %v; want the replacement provider", info, err)
		}
	})

	t.Run("an empty ProfileMap means the default mapping", func(t *testing.T) {
		p := newFakeUserInfoServer(t, `{"id":"d-1","email":"d@example.com"}`, "[]", http.StatusOK).provider("acme")
		p.ProfileMap = map[string]string{}
		svc, err := NewOAuthServiceWithConfig(p)
		if err != nil {
			t.Fatalf("NewOAuthServiceWithConfig: %v", err)
		}
		if info, err := svc.ExchangeCode(context.Background(), "acme", "code"); err != nil || info.ProviderID != "d-1" {
			t.Fatalf("info = %+v, err = %v; want the default mapping", info, err)
		}
	})
}
