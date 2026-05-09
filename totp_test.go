package auth

import (
	"testing"
	"time"
)

func TestGenerateTOTPSecret_NonEmpty(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
}

func TestGenerateTOTPSecret_Uniqueness(t *testing.T) {
	a, _ := generateTOTPSecret()
	b, _ := generateTOTPSecret()
	if a == b {
		t.Fatal("TOTP secrets should be unique")
	}
}

func TestValidateTOTPCode_Valid(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	code, ok := generateTOTPCode(secret, now.Unix()/30)
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	if !validateTOTPCode(secret, code, now) {
		t.Fatal("valid TOTP code should pass validation")
	}
}

func TestValidateTOTPCode_NonNumeric(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "abcdef", time.Now()) {
		t.Fatal("non-numeric code should fail")
	}
}

func TestValidateTOTPCode_WrongLength_Short(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "12345", time.Now()) {
		t.Fatal("5-digit code should fail")
	}
}

func TestValidateTOTPCode_WrongLength_Long(t *testing.T) {
	secret, _ := generateTOTPSecret()
	if validateTOTPCode(secret, "1234567", time.Now()) {
		t.Fatal("7-digit code should fail")
	}
}

func TestValidateTOTPCode_WindowTolerance_Prev(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	step := int64(30)
	prevCode, ok := generateTOTPCode(secret, now.Unix()/step-1)
	if !ok {
		t.Fatal("generateTOTPCode for prev step failed")
	}
	if !validateTOTPCode(secret, prevCode, now) {
		t.Fatal("previous step code should be accepted within tolerance window")
	}
}

func TestValidateTOTPCode_WindowTolerance_Next(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	now := time.Now()
	step := int64(30)
	nextCode, ok := generateTOTPCode(secret, now.Unix()/step+1)
	if !ok {
		t.Fatal("generateTOTPCode for next step failed")
	}
	if !validateTOTPCode(secret, nextCode, now) {
		t.Fatal("next step code should be accepted within tolerance window")
	}
}

func TestGenerateTOTPCode_InvalidSecret(t *testing.T) {
	_, ok := generateTOTPCode("!!!INVALID!!!", 0)
	if ok {
		t.Fatal("expected failure for invalid base32 secret")
	}
}

func TestValidateTOTPCode_InvalidSecret(t *testing.T) {
	if validateTOTPCode("!!!INVALID!!!", "123456", time.Now()) {
		t.Fatal("invalid secret should fail validation")
	}
}

func TestGenerateTOTPCode_SameCounterSameCode(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code1, ok1 := generateTOTPCode(secret, 1000)
	code2, ok2 := generateTOTPCode(secret, 1000)
	if !ok1 || !ok2 {
		t.Fatal("generateTOTPCode failed")
	}
	if code1 != code2 {
		t.Fatal("same counter should produce same code (deterministic)")
	}
}

func TestGenerateTOTPCode_DifferentCountersDifferentCodes(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code1, ok1 := generateTOTPCode(secret, 1000)
	code2, ok2 := generateTOTPCode(secret, 2000)
	if !ok1 || !ok2 {
		t.Fatal("generateTOTPCode failed")
	}
	if code1 == code2 {
		t.Fatal("different counters should (very likely) produce different codes")
	}
}

func TestGenerateTOTPCode_SixDigits(t *testing.T) {
	secret, _ := generateTOTPSecret()
	code, ok := generateTOTPCode(secret, 1234)
	if !ok {
		t.Fatal("generateTOTPCode failed")
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Fatalf("code should contain only digits: %q", code)
		}
	}
}
