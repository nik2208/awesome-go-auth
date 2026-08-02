package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sensitiveUserFields are the User fields that must never reach the wire.
var sensitiveUserFields = []string{
	"PasswordHash",
	"TOTPSecret",
	"ResetTokenHash",
	"MagicLinkTokenHash",
	"SMSCodeHash",
	"EmailVerificationTokenHash",
	"EmailChangeTokenHash",
	"PendingEmail",
}

func fullyPopulatedUser() User {
	expiry := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return User{
		ID:                           "usr_1",
		Email:                        "leak@example.com",
		PasswordHash:                 "secret-bcrypt-hash",
		TenantID:                     "tenant-a",
		PhoneNumber:                  "+390000000",
		FirstName:                    "Ada",
		LastName:                     "Lovelace",
		Role:                         "admin",
		IsEmailVerified:              true,
		Require2FA:                   true,
		IsTOTPEnabled:                true,
		TOTPSecret:                   "secret-totp-seed",
		ResetTokenHash:               "secret-reset-hash",
		ResetTokenExpiresAt:          &expiry,
		MagicLinkTokenHash:           "secret-magic-hash",
		MagicLinkTokenExpiresAt:      &expiry,
		SMSCodeHash:                  "secret-sms-hash",
		SMSCodeExpiresAt:             &expiry,
		EmailVerificationTokenHash:   "secret-verification-hash",
		EmailVerificationTokenExpiry: &expiry,
		PendingEmail:                 "secret-pending@example.com",
		EmailChangeTokenHash:         "secret-change-hash",
		EmailChangeTokenExpiry:       &expiry,
		Metadata:                     map[string]any{"plan": "pro"},
		Roles:                        []string{"admin"},
		Permissions:                  []string{"users:read"},
		Tenants:                      []Tenant{{ID: "tenant-a", Name: "Acme", IsActive: true, Config: map[string]any{"sso_client_secret": "secret-tenant-config"}}},
		CustomClaims:                 map[string]any{"seat": "s1"},
		CreatedAt:                    expiry,
		UpdatedAt:                    expiry,
	}
}

func TestNewPublicUserOmitsCredentialMaterial(t *testing.T) {
	user := fullyPopulatedUser()
	raw, err := json.Marshal(map[string]any{"user": NewPublicUser(user)})
	if err != nil {
		t.Fatalf("marshal public user: %v", err)
	}
	body := strings.ToLower(string(raw))

	for _, field := range sensitiveUserFields {
		if strings.Contains(body, strings.ToLower(field)) {
			t.Errorf("serialised user exposes field %q: %s", field, raw)
		}
	}
	for _, value := range []string{
		user.PasswordHash,
		user.TOTPSecret,
		user.ResetTokenHash,
		user.MagicLinkTokenHash,
		user.SMSCodeHash,
		user.EmailVerificationTokenHash,
		user.EmailChangeTokenHash,
		user.PendingEmail,
		"secret-tenant-config",
	} {
		if strings.Contains(body, strings.ToLower(value)) {
			t.Errorf("serialised user exposes value %q: %s", value, raw)
		}
	}
}

func TestNewPublicUserUsesCamelCaseContract(t *testing.T) {
	raw, err := json.Marshal(NewPublicUser(fullyPopulatedUser()))
	if err != nil {
		t.Fatalf("marshal public user: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal public user: %v", err)
	}

	for _, key := range []string{"id", "email", "tenantId", "firstName", "lastName", "phoneNumber", "isEmailVerified", "isTotpEnabled", "roles", "permissions", "tenants", "metadata", "customClaims", "createdAt"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing camelCase key %q: %s", key, raw)
		}
	}
	if decoded["id"] != "usr_1" || decoded["email"] != "leak@example.com" {
		t.Fatalf("unexpected identity fields: %s", raw)
	}
}

func TestNewPublicUserPreservesEnrichment(t *testing.T) {
	public := NewPublicUser(fullyPopulatedUser())
	if len(public.Roles) != 1 || public.Roles[0] != "admin" {
		t.Errorf("roles not preserved: %v", public.Roles)
	}
	if len(public.Permissions) != 1 || public.Permissions[0] != "users:read" {
		t.Errorf("permissions not preserved: %v", public.Permissions)
	}
	if public.Metadata["plan"] != "pro" {
		t.Errorf("metadata not preserved: %v", public.Metadata)
	}
	if public.CustomClaims["seat"] != "s1" {
		t.Errorf("custom claims not preserved: %v", public.CustomClaims)
	}
	if len(public.Tenants) != 1 {
		t.Fatalf("tenants not preserved: %v", public.Tenants)
	}
	if public.Tenants[0].ID != "tenant-a" || public.Tenants[0].Name != "Acme" || !public.Tenants[0].IsActive {
		t.Errorf("tenant projection lost data: %+v", public.Tenants[0])
	}
}

func TestNewPublicUserEmptyUserOmitsOptionalFields(t *testing.T) {
	raw, err := json.Marshal(NewPublicUser(User{}))
	if err != nil {
		t.Fatalf("marshal public user: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal public user: %v", err)
	}
	for _, key := range []string{"tenantId", "firstName", "lastName", "phoneNumber", "roles", "permissions", "tenants", "metadata", "customClaims"} {
		if _, ok := decoded[key]; ok {
			t.Errorf("expected %q to be omitted when empty: %s", key, raw)
		}
	}
	for _, key := range []string{"id", "email", "isEmailVerified", "isTotpEnabled", "createdAt"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("expected %q to always be present: %s", key, raw)
		}
	}
}
