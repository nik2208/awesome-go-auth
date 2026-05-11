package auth

import (
	"testing"
	"time"
)

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	if cfg.Secret != "12345678901234567890123456789012" {
		t.Errorf("unexpected secret")
	}
	if cfg.Issuer != "awesome-go-auth" {
		t.Errorf("unexpected issuer: %s", cfg.Issuer)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("unexpected access token ttl: %s", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("unexpected refresh token ttl: %s", cfg.RefreshTokenTTL)
	}
	if cfg.MinPasswordLen != 8 {
		t.Errorf("unexpected min password len: %d", cfg.MinPasswordLen)
	}
	if cfg.ResetTokenTTL != 1*time.Hour {
		t.Errorf("unexpected reset token ttl: %s", cfg.ResetTokenTTL)
	}
	if cfg.MagicLinkTTL != 15*time.Minute {
		t.Errorf("unexpected magic link ttl: %s", cfg.MagicLinkTTL)
	}
	if cfg.SMSCodeTTL != 10*time.Minute {
		t.Errorf("unexpected sms code ttl: %s", cfg.SMSCodeTTL)
	}
	if cfg.EmailVerificationTTL != 24*time.Hour {
		t.Errorf("unexpected email verification ttl: %s", cfg.EmailVerificationTTL)
	}
	if cfg.EmailChangeTTL != 1*time.Hour {
		t.Errorf("unexpected email change ttl: %s", cfg.EmailChangeTTL)
	}
	if cfg.TempTokenTTL != 5*time.Minute {
		t.Errorf("unexpected temp token ttl: %s", cfg.TempTokenTTL)
	}
}

func TestConfigValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	if err := cfg.validate(); err != nil {
		t.Fatalf("expected valid config to pass: %v", err)
	}
}

func TestConfigValidate_ShortSecret(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.Secret = "tooshort"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestConfigValidate_EmptySecret(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.Secret = ""
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestConfigValidate_ZeroAccessTokenTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.AccessTokenTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero access token TTL")
	}
}

func TestConfigValidate_NegativeAccessTokenTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.AccessTokenTTL = -1 * time.Minute
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for negative access token TTL")
	}
}

func TestConfigValidate_ZeroRefreshTokenTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.RefreshTokenTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero refresh token TTL")
	}
}

func TestConfigValidate_LowMinPasswordLen(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.MinPasswordLen = 7
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for min password len < 8")
	}
}

func TestConfigValidate_ZeroResetTokenTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.ResetTokenTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero reset token TTL")
	}
}

func TestConfigValidate_ZeroMagicLinkTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.MagicLinkTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero magic link TTL")
	}
}

func TestConfigValidate_ZeroSMSCodeTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.SMSCodeTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero SMS code TTL")
	}
}

func TestConfigValidate_ZeroEmailVerificationTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.EmailVerificationTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero email verification TTL")
	}
}

func TestConfigValidate_ZeroEmailChangeTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.EmailChangeTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero email change TTL")
	}
}

func TestConfigValidate_ZeroTempTokenTTL(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.TempTokenTTL = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero temp token TTL")
	}
}

func TestNewService_NilUserStore(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	_, err := NewService(cfg, nil, NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error for nil user store")
	}
}

func TestNewService_NilSessionStore(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	_, err := NewService(cfg, NewMemoryUserStore(), nil)
	if err == nil {
		t.Fatal("expected error for nil session store")
	}
}

func TestNewService_InvalidConfig(t *testing.T) {
	cfg := DefaultConfig("12345678901234567890123456789012")
	cfg.Secret = "short"
	_, err := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}
