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

func generateTOTPSecret() (string, error) {
	raw, err := randomToken(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(raw)), nil
}

func validateTOTPCode(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	step := int64(30)
	for offset := int64(-1); offset <= 1; offset++ {
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
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", binCode%1000000), true
}
