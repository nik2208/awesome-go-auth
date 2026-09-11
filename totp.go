package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// The TOTP parameters. They are stated once, here, and read by both the
// provisioning URI (totpProvisioningURI) and the verifier (validateTOTPCode),
// so that what an authenticator app is told at enrolment cannot drift from what
// the server later checks a code against.
//
// TOTPAlgorithm, TOTPDigits and TOTPPeriod are RFC 6238's defaults and the ones
// the reference runs with: it constructs otplib's TOTP with nothing but the
// crypto and base32 plugins (totp.strategy.ts:5-8), so `totp.verify` (:23)
// takes the library's own algorithm "sha1", digits 6 and period 30 — not knobs
// there (auth-config.model.ts:272-274 has only `twoFactor.appName`), and not
// knobs here. They are exported so that a host rendering its own URI, or a test
// generating codes, reads the same values rather than restating them.
//
// TOTPSkew is the number of whole steps either side of the current one a code
// is accepted for, and is this port's tolerance, not the reference's: otplib's
// `epochTolerance` option defaults to 0 seconds (@otplib/totp 13.4.0, the version the reference's package-lock.json pins; the
// reference pins otplib ^13.3.0 and never sets it), so the reference accepts
// the current step only. One step of skew is the allowance RFC 6238 §5.2
// recommends for clock drift and network delay.
const (
	// TOTPAlgorithm is the HMAC hash, spelled as the otpauth:// `algorithm`
	// parameter spells it. generateTOTPCode's hmac.New(sha1.New, …) is the
	// implementation of this value.
	TOTPAlgorithm = "SHA1"
	// TOTPDigits is the length of a code.
	TOTPDigits = 6
	// TOTPPeriod is the length of one time step.
	TOTPPeriod = 30 * time.Second
	// TOTPSkew is the number of steps either side of now a code is accepted for.
	TOTPSkew = 1
)

func generateTOTPSecret() (string, error) {
	raw, err := randomToken(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(raw)), nil
}

func validateTOTPCode(secret, code string, now time.Time) bool {
	if len(code) != TOTPDigits {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	step := int64(TOTPPeriod / time.Second)
	for offset := int64(-TOTPSkew); offset <= TOTPSkew; offset++ {
		counter := now.Unix()/step + offset
		generated, ok := generateTOTPCode(secret, counter)
		if ok && generated == code {
			return true
		}
	}
	return false
}

func generateTOTPCode(secret string, counter int64) (string, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", false
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	mac := hmac.New(sha1.New, key) // TOTPAlgorithm
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	modulus := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, binCode%modulus), true
}
