package scudo

import (
	"database/sql"
	"embed"
	"errors"
	"github.com/pressly/goose/v3"
	"github.com/thisisthemurph/scudo/internal/service"
	"net/http"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
)

type Scudo struct {
	options *Options
	Auth    *auth
	User    *user
}

type Options struct {
	AccessTokenTTL    time.Duration
	AccessTokenSecret string
	RefreshTokenTTL   time.Duration
	CookieOptions     *CookieOptions
}

type CookieOptions struct {
	Path     string
	Secure   bool
	SameSite http.SameSite
}

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

func New(db *sql.DB, options *Options) (*Scudo, error) {
	err := processOptions(options)
	if err != nil {
		return nil, err
	}

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

func processOptions(options *Options) error {
	if options.AccessTokenSecret == "" {
		return errors.New("access token secret is required")
	}

	if options.AccessTokenTTL == 0 {
		options.AccessTokenTTL = 15 * time.Minute
	}

	if options.RefreshTokenTTL == 0 {
		options.RefreshTokenTTL = 24 * 7 * time.Hour
	}

	if options.CookieOptions == nil {
		options.CookieOptions = &CookieOptions{
			Path:     "/",
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		}
	} else {
		if options.CookieOptions.Path == "" {
			options.CookieOptions.Path = "/"
		}
		if options.CookieOptions.SameSite == 0 {
			options.CookieOptions.SameSite = http.SameSiteLaxMode
		}
	}

	return nil
}

func (s *Scudo) migrate(db *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
