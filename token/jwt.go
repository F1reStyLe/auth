package token

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret []byte
}

type Claims struct {
	UserID int64 `json:"uid"`
	jwt.RegisteredClaims
}

func NewJWTManager(secret string) *JWTManager {
	return &JWTManager{secret: []byte(secret)}
}

func (m *JWTManager) Generate(tokenExperation time.Duration, userID int64) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExperation)),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := t.SignedString(m.secret)

	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return token, nil
}

func (m *JWTManager) Parse(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid jwt claims")
	}

	return claims, nil
}
