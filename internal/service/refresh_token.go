package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/repository"
	"github.com/thisisthemurph/scudo/internal/token"
	"golang.org/x/crypto/bcrypt"
)

var ErrRefreshTokenNotFound = errors.New("refresh token not found")
var ErrRefreshTokenRevoked = errors.New("refresh token revoked")
var ErrRefreshTokenExpired = errors.New("refresh token expired")

type RefreshTokenService struct {
	queries         *repository.Queries
	refreshTokenTTL time.Duration
}

func NewRefreshTokenService(db *sql.DB, ttl time.Duration) *RefreshTokenService {
	return &RefreshTokenService{
		queries:         repository.New(db),
		refreshTokenTTL: ttl,
	}
}

func (s *RefreshTokenService) GetRefreshToken(ctx context.Context, userID uuid.UUID, token string) (*repository.ScudoRefreshToken, error) {
	tokens, err := s.queries.GetRefreshTokensByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	for _, t := range tokens {
		if err := bcrypt.CompareHashAndPassword([]byte(t.HashedToken), []byte(token)); err == nil {
			if t.Revoked {
				return &t, ErrRefreshTokenRevoked
			}
			if t.Expired() {
				return &t, ErrRefreshTokenExpired
			}
			return &t, nil
		}
	}

	return nil, ErrRefreshTokenNotFound
}

func (s *RefreshTokenService) RegisterRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	refreshToken := token.GenerateRefreshToken()
	hashedRefreshToken, err := token.HashRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	err = s.queries.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		UserID:      userID,
		HashedToken: hashedRefreshToken,
		ExpiresAt:   time.Now().Add(s.refreshTokenTTL),
	})
	return refreshToken, err
}

func (s *RefreshTokenService) RevokeRefreshToken(ctx context.Context, refreshTokenID int32) error {
	return s.queries.RevokeRefreshTokenByID(ctx, refreshTokenID)
}
