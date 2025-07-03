package scudo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/service"
	"github.com/thisisthemurph/scudo/internal/token"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

const (
	AccessTokenCookieKey  = "scudo-access-token"
	RefreshTokenCookieKey = "scudo-refresh-token"
)

type auth struct {
	options             *Options
	userService         *service.UserService
	refreshTokenService *service.RefreshTokenService
}

func newAuth(us *service.UserService, rts *service.RefreshTokenService, options *Options) *auth {
	return &auth{
		options:             options,
		userService:         us,
		refreshTokenService: rts,
	}
}

type SignUpResponse struct {
	User User `json:"user"`
}

type SignUpOptions struct {
	Data any
}

func (a *auth) SignUp(ctx context.Context, email, password string, options *SignUpOptions) (*SignUpResponse, error) {
	var err error
	var jsonData []byte

	if options == nil {
		options = &SignUpOptions{}
	}
	if options.Data == nil {
		options.Data = make(map[string]any)
	}

	jsonData, err = json.Marshal(options.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sign-up data: %w", err)
	}

	user, err := a.userService.CreateUser(ctx, email, password, jsonData)
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

func (a *auth) SignIn(ctx context.Context, w http.ResponseWriter, email, password string) (*SignInResponse, error) {
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

	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieKey,
		Value:    accessToken,
		Path:     a.options.CookieOptions.Path,
		Expires:  time.Now().Add(a.options.AccessTokenTTL),
		HttpOnly: true,
		Secure:   a.options.CookieOptions.Secure,
		SameSite: a.options.CookieOptions.SameSite,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieKey,
		Value:    refreshToken,
		Path:     a.options.CookieOptions.Path,
		Expires:  time.Now().Add(a.options.RefreshTokenTTL),
		HttpOnly: true,
		Secure:   a.options.CookieOptions.Secure,
		SameSite: a.options.CookieOptions.SameSite,
	})

	return &SignInResponse{
		User:         NewUserDTO(user),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *auth) SignOut(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	defer func() {
		// Defer the unsetting of the cookies to ensure they are always unset.
		unsetCookie(w, AccessTokenCookieKey, a.options.CookieOptions)
		unsetCookie(w, RefreshTokenCookieKey, a.options.CookieOptions)
	}()

	accessCookie, err := r.Cookie(AccessTokenCookieKey)
	if err != nil {
		return err
	}

	refreshCookie, err := r.Cookie(RefreshTokenCookieKey)
	if err != nil {
		return err
	}

	accessToken := accessCookie.Value
	refreshToken := refreshCookie.Value
	claims, err := a.parseJWTClaims(accessToken)
	if err != nil {
		return err
	}

	userIDValue, ok := claims["sub"].(string)
	if !ok {
		return errors.New("sub not found in JWT claims")
	}
	userID, err := uuid.Parse(userIDValue)
	if err != nil {
		return err
	}

	rt, err := a.refreshTokenService.GetRefreshToken(ctx, userID, refreshToken)
	if err != nil {
		return err
	}

	return a.refreshTokenService.RevokeRefreshToken(ctx, rt.ID)
}

func (a *auth) parseJWTClaims(jwtValue string) (jwt.MapClaims, error) {
	t, err := jwt.Parse(jwtValue, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.options.AccessTokenSecret), nil
	})
	if err != nil {
		return jwt.MapClaims{}, fmt.Errorf("failed parsing access token: %w", err)
	}

	if !t.Valid {
		return jwt.MapClaims{}, fmt.Errorf("invalid access token")
	}

	mapClaims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return mapClaims, fmt.Errorf("invalid claims")
	}

	return mapClaims, nil
}

func unsetCookie(w http.ResponseWriter, name string, options *CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     options.Path,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   options.Secure,
		SameSite: options.SameSite,
	})
}
