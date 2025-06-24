package service

import (
	"context"
	"database/sql"
	"errors"
	"github.com/thisisthemurph/scudo/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
)

type UserService struct {
	queries *repository.Queries
}

func NewUserService(db *sql.DB) *UserService {
	return &UserService{
		queries: repository.New(db),
	}
}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (repository.ScudoUser, error) {
	return s.GetUserByEmail(ctx, email)
}

func (s *UserService) CreateUser(ctx context.Context, email, password string) (repository.ScudoUser, error) {
	if userExists, err := s.queries.UserWithEmailExists(ctx, email); err != nil {
		return repository.ScudoUser{}, err
	} else if userExists {
		return repository.ScudoUser{}, ErrUserAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return repository.ScudoUser{}, err
	}

	return s.queries.CreateUser(ctx, repository.CreateUserParams{
		Email:          email,
		HashedPassword: string(hash),
	})
}
