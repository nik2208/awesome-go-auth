package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// tokenAlg is the only JWS algorithm accepted for access and refresh tokens.
// Verification uses it as an explicit allow-list: the alg advertised by an
// incoming token never selects the verification routine, so "none" and any
// asymmetric algorithm are refused before the claims are read.
const tokenAlg = "HS256"

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

// joseHeader is the JWT header of an issued token.
type joseHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (s *Service) issueToken(ctx context.Context, user User, sessionID, tokenType string, ttl time.Duration) (string, time.Time, error) {
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

	payloadClaims := map[string]any{
		"sub":             claims.Sub,
		"sid":             claims.Sid,
		"tid":             claims.Tid,
		"jti":             claims.Jti,
		"typ":             claims.Typ,
		"iss":             claims.Iss,
		"iat":             claims.Iat,
		"exp":             claims.Exp,
		"email":           user.Email,
		"role":            user.Role,
		"isEmailVerified": user.IsEmailVerified,
		"isTotpEnabled":   user.IsTOTPEnabled,
	}
	if s.cfg.BuildTokenClaims != nil {
		customClaims, err := s.cfg.BuildTokenClaims(ctx, user)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("auth: build token claims: %w", err)
		}
		for key, value := range customClaims {
			payloadClaims[key] = value
		}
	}
	token, err := buildHS256JWT(payloadClaims, s.cfg.Secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *Service) parseToken(token, expectedType string) (tokenClaims, error) {
	var claims tokenClaims
	header, payload, sig, err := splitToken(token)
	if err != nil {
		return claims, ErrInvalidToken
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return claims, ErrInvalidToken
	}
	if alg, ok := headerAlg(rawHeader); !ok || alg != tokenAlg {
		return claims, ErrInvalidToken
	}
	if !secureEqual(sign(header+"."+payload, s.cfg.Secret), sig) {
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
	if now.After(time.Unix(claims.Exp, 0).Add(s.cfg.ClockSkew)) {
		return claims, ErrInvalidToken
	}
	return claims, nil
}

// headerAlg returns the alg member of a decoded JOSE header, reporting false
// when the header is not a JSON object, carries no alg member, or carries one
// that is not a JSON string.
//
// The header is decoded into raw members rather than into joseHeader because
// encoding/json matches struct fields case-insensitively: unmarshalling into
// joseHeader accepts a header whose only algorithm member is "ALG", and a
// header reading {"alg":"none","ALG":"HS256"} would have its "none" overwritten
// by the later member and be accepted, while every spec-compliant verifier
// reads that same header as alg "none" and refuses it. joseHeader is still the
// type used to build headers, where the member names are ours to choose.
func headerAlg(rawHeader []byte) (string, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &members); err != nil {
		return "", false
	}
	rawAlg, ok := members["alg"]
	if !ok {
		return "", false
	}
	var alg string
	if err := json.Unmarshal(rawAlg, &alg); err != nil {
		return "", false
	}
	return alg, true
}

// buildHS256JWT creates a signed HS256 JWT using only standard library
// packages, mirroring buildRS256JWT in idp.go.
//
// The JWS signing input is exactly the ASCII string
// base64url(header) + "." + base64url(claims), both segments unpadded, as
// RFC 7515 section 5.1 requires — the header is inside the signed bytes, so it
// cannot be swapped on a token in flight.
func buildHS256JWT(claims map[string]any, secret string) (string, error) {
	headerBytes, err := json.Marshal(joseHeader{Alg: tokenAlg, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshal claims: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sigInput := header + "." + payload
	return sigInput + "." + sign(sigInput, secret), nil
}
