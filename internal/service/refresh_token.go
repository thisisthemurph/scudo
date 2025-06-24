package service

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/repository"
	"github.com/thisisthemurph/scudo/internal/token"
	"time"
)

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
