package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_And_VerifyPassword(t *testing.T) {
	hash, err := hashPassword("mypassword", testBcryptCost)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if !verifyPassword("mypassword", hash) {
		t.Fatal("password should verify against its hash")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := hashPassword("correctpassword", testBcryptCost)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if verifyPassword("wrongpassword", hash) {
		t.Fatal("wrong password should not verify")
	}
}

func TestVerifyPassword_EmptyPassword(t *testing.T) {
	hash, err := hashPassword("password123", testBcryptCost)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if verifyPassword("", hash) {
		t.Fatal("empty password should not verify")
	}
}

func TestVerifyPassword_EmptyHash(t *testing.T) {
	if verifyPassword("password", "") {
		t.Fatal("empty hash should not verify")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	a := hashToken("mytoken")
	b := hashToken("mytoken")
	if a != b {
		t.Fatal("hashToken must be deterministic")
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	a := hashToken("token1")
	b := hashToken("token2")
	if a == b {
		t.Fatal("different inputs must produce different hashes")
	}
}

func TestHashToken_NonEmpty(t *testing.T) {
	h := hashToken("something")
	if h == "" {
		t.Fatal("hash must not be empty")
	}
}

func TestHashToken_IsHex(t *testing.T) {
	h := hashToken("test")
	for _, ch := range h {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Fatalf("hash should be lowercase hex, got char %q in %q", ch, h)
		}
	}
}

func TestRandomToken_Uniqueness(t *testing.T) {
	a, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	b, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if a == b {
		t.Fatal("random tokens should be unique")
	}
}

func TestRandomToken_NonEmpty(t *testing.T) {
	tok, err := randomToken(16)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestRandomNumericCode_Length(t *testing.T) {
	for _, l := range []int{4, 6, 8} {
		code, err := randomNumericCode(l)
		if err != nil {
			t.Fatalf("randomNumericCode(%d): %v", l, err)
		}
		if len(code) != l {
			t.Fatalf("expected length %d, got %d", l, len(code))
		}
	}
}

func TestRandomNumericCode_OnlyDigits(t *testing.T) {
	code, err := randomNumericCode(6)
	if err != nil {
		t.Fatalf("randomNumericCode: %v", err)
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Fatalf("non-digit character in code: %q", code)
		}
	}
}

func TestRandomNumericCode_ZeroLength(t *testing.T) {
	_, err := randomNumericCode(0)
	if err == nil {
		t.Fatal("expected error for zero length code")
	}
}

func TestRandomNumericCode_NegativeLength(t *testing.T) {
	_, err := randomNumericCode(-1)
	if err == nil {
		t.Fatal("expected error for negative length code")
	}
}

func TestSign_Deterministic(t *testing.T) {
	a := sign("payload", "secret")
	b := sign("payload", "secret")
	if a != b {
		t.Fatal("sign must be deterministic")
	}
}

func TestSign_DifferentSecrets(t *testing.T) {
	a := sign("payload", "secret1")
	b := sign("payload", "secret2")
	if a == b {
		t.Fatal("different secrets must produce different signatures")
	}
}

func TestSign_DifferentPayloads(t *testing.T) {
	a := sign("payload1", "secret")
	b := sign("payload2", "secret")
	if a == b {
		t.Fatal("different payloads must produce different signatures")
	}
}

func TestSign_NonEmpty(t *testing.T) {
	s := sign("data", "key")
	if s == "" {
		t.Fatal("signature must not be empty")
	}
}

func TestSecureEqual_Equal(t *testing.T) {
	if !secureEqual("abc", "abc") {
		t.Fatal("equal strings should return true")
	}
}

func TestSecureEqual_NotEqual(t *testing.T) {
	if secureEqual("abc", "xyz") {
		t.Fatal("different strings should return false")
	}
}

func TestSecureEqual_DifferentLengths(t *testing.T) {
	if secureEqual("short", "longerstring") {
		t.Fatal("different length strings should return false")
	}
}

func TestSecureEqual_Empty(t *testing.T) {
	if !secureEqual("", "") {
		t.Fatal("two empty strings should be equal")
	}
}

func TestSplitToken_Valid(t *testing.T) {
	header, payload, sig, err := splitToken("abc.def.ghi")
	if err != nil {
		t.Fatalf("splitToken: %v", err)
	}
	if header != "abc" || payload != "def" || sig != "ghi" {
		t.Fatalf("unexpected parts: %q %q %q", header, payload, sig)
	}
}

func TestSplitToken_NoSeparator(t *testing.T) {
	_, _, _, err := splitToken("nodot")
	if err == nil {
		t.Fatal("expected error for token without separator")
	}
}

func TestSplitToken_TooFewParts(t *testing.T) {
	_, _, _, err := splitToken("a.b")
	if err == nil {
		t.Fatal("expected error for token with too few parts")
	}
}

func TestSplitToken_TooManyParts(t *testing.T) {
	_, _, _, err := splitToken("a.b.c.d")
	if err == nil {
		t.Fatal("expected error for token with too many parts")
	}
}

func TestSplitToken_Empty(t *testing.T) {
	_, _, _, err := splitToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNewID_Format(t *testing.T) {
	id, err := newID("usr")
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	if !strings.HasPrefix(id, "usr_") {
		t.Fatalf("expected prefix usr_, got %q", id)
	}
	if len(id) < 10 {
		t.Fatalf("id too short: %q", id)
	}
}

func TestNewID_Uniqueness(t *testing.T) {
	id1, _ := newID("x")
	id2, _ := newID("x")
	if id1 == id2 {
		t.Fatal("IDs should be unique")
	}
}

func TestNewID_DifferentPrefixes(t *testing.T) {
	id1, _ := newID("usr")
	id2, _ := newID("ses")
	if id1 == id2 {
		t.Fatal("IDs with different prefixes should be different")
	}
	if !strings.HasPrefix(id1, "usr_") {
		t.Fatalf("expected usr_ prefix, got %q", id1)
	}
	if !strings.HasPrefix(id2, "ses_") {
		t.Fatalf("expected ses_ prefix, got %q", id2)
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"USER@EXAMPLE.COM", "user@example.com"},
		{"  user@example.com  ", "user@example.com"},
		{"User@Example.COM", "user@example.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		got := normalizeEmail(c.input)
		if got != c.expected {
			t.Errorf("normalizeEmail(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}
