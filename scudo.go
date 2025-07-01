package scudo

import (
	"database/sql"
	"embed"
	"errors"
	"github.com/pressly/goose/v3"
	"github.com/thisisthemurph/scudo/internal/service"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
)

type Scudo struct {
	options Options
	Auth    *auth
	User    *user
}

type Options struct {
	AccessTokenTTL    time.Duration
	AccessTokenSecret string
	RefreshTokenTTL   time.Duration
}

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

func New(db *sql.DB, options Options) (*Scudo, error) {
	userService := service.NewUserService(db)
	refreshTokenService := service.NewRefreshTokenService(db, options.RefreshTokenTTL)

	s := &Scudo{
		options: options,
		Auth:    newAuth(userService, refreshTokenService, options),
		User:    newUser(userService, options),
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := s.migrate(db); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Scudo) migrate(db *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
