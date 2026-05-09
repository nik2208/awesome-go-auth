package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type tokenClaims struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Tid string `json:"tid,omitempty"`
	Jti string `json:"jti"`
	Typ string `json:"typ"`
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func (s *Service) issueToken(user User, sessionID, tokenType string, ttl time.Duration) (string, time.Time, error) {
	now := s.now()
	expiresAt := now.Add(ttl)
	jti, err := newID("jti")
	if err != nil {
		return "", time.Time{}, err
	}
	claims := tokenClaims{
		Sub: user.ID,
		Sid: sessionID,
		Tid: user.TenantID,
		Jti: jti,
		Typ: tokenType,
		Iss: s.cfg.Issuer,
		Iat: now.Unix(),
		Exp: expiresAt.Unix(),
	}

	raw, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := sign(payload, s.cfg.Secret)
	return payload + "." + sig, expiresAt, nil
}

func (s *Service) parseToken(token, expectedType string) (tokenClaims, error) {
	var claims tokenClaims
	payload, sig, err := splitToken(token)
	if err != nil {
		return claims, ErrInvalidToken
	}
	if !secureEqual(sign(payload, s.cfg.Secret), sig) {
		return claims, ErrInvalidToken
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims, ErrInvalidToken
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return claims, ErrInvalidToken
	}

	now := s.now()
	if claims.Iss != s.cfg.Issuer || claims.Typ != expectedType {
		return claims, ErrInvalidToken
	}
	if now.Add(-s.cfg.ClockSkew).Unix() > claims.Exp {
		return claims, ErrInvalidToken
	}
	return claims, nil
}
