package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/thisisthemurph/scudo/internal/repository"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func GenerateJWT(u repository.ScudoUser, ttl time.Duration, secret string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   u.ID.String(),
		"email": u.Email,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	}

	metadata, err := getMetadataMap(u)
	if err == nil {
		claims["metadata"] = metadata
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func GenerateRefreshToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func HashRefreshToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

func getMetadataMap(u repository.ScudoUser) (map[string]any, error) {
	var data map[string]any
	if err := json.Unmarshal(u.Metadata, &data); err != nil {
		return data, err
	}

	if len(data) == 0 {
		return data, errors.New("metadata empty")
	}

	return data, nil
}
