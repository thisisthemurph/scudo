package scudo

import (
	"context"
	"errors"
	"github.com/thisisthemurph/scudo/internal/service"
	"github.com/thisisthemurph/scudo/internal/token"
	"golang.org/x/crypto/bcrypt"
)

type auth struct {
	options             Options
	userService         *service.UserService
	refreshTokenService *service.RefreshTokenService
}

func newAuth(us *service.UserService, rts *service.RefreshTokenService, options Options) *auth {
	return &auth{
		options:             options,
		userService:         us,
		refreshTokenService: rts,
	}
}

type SignUpResponse struct {
	User User `json:"user"`
}

func (a *auth) SignUp(ctx context.Context, email, password string) (*SignUpResponse, error) {
	user, err := a.userService.CreateUser(ctx, email, password)
	if err != nil {
		if errors.Is(err, service.ErrUserAlreadyExists) {
			return nil, ErrUserAlreadyExists
		}
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

func (a *auth) SignIn(ctx context.Context, email, password string) (*SignInResponse, error) {
	user, err := a.userService.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := token.GenerateJWT(user, a.options.AccessTokenTTL, a.options.AccessTokenSecret)
	if err != nil {
		return nil, err
	}

	refreshToken, err := a.refreshTokenService.RegisterRefreshToken(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return &SignInResponse{
		User:         NewUserDTO(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
