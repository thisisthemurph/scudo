package scudo

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"github.com/pressly/goose/v3"
	"github.com/thisisthemurph/scudo/internal/service"
	"github.com/thisisthemurph/scudo/internal/token"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Scudo struct {
	options             Options
	userService         *service.UserService
	refreshTokenService *service.RefreshTokenService
}

type Options struct {
	AccessTokenTTL    time.Duration
	AccessTokenSecret string
	RefreshTokenTTL   time.Duration
}

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

func New(db *sql.DB, options Options) (*Scudo, error) {
	s := &Scudo{
		options:             options,
		userService:         service.NewUserService(db),
		refreshTokenService: service.NewRefreshTokenService(db, options.RefreshTokenTTL),
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := s.migrate(db); err != nil {
		return nil, err
	}

	return s, nil
}

type SignUpResponse struct {
	User User `json:"user"`
}

func (s *Scudo) SignUp(ctx context.Context, email, password string) (*SignUpResponse, error) {
	user, err := s.userService.CreateUser(ctx, email, password)
	if err != nil {
		return nil, err
	}

	return &SignUpResponse{
		User: NewUserDTO(user),
	}, nil
}

type SignInResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func (s *Scudo) SignIn(ctx context.Context, email, password string) (*SignInResponse, error) {
	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := token.GenerateJWT(user, s.options.AccessTokenTTL, s.options.AccessTokenSecret)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.refreshTokenService.RegisterRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return &SignInResponse{
		User:         NewUserDTO(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Scudo) migrate(db *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
