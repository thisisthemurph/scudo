package scudo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/service"
	"net/http"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type user struct {
	options     *Options
	userService *service.UserService
}

func newUser(us *service.UserService, options *Options) *user {
	return &user{
		options:     options,
		userService: us,
	}
}

// GetUserByID returns the user associated with the given id.
func (u *user) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	usr, err := u.userService.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return NewUserDTO(usr), nil
}

// GetCurrentUser returns the current user associated with the JWT present on the http.Request context.
func (u *user) GetCurrentUser(ctx context.Context, r *http.Request) (User, error) {
	userID, err := getCurrentUserID(r, u.options.AccessTokenSecret)
	if err != nil {
		return User{}, err
	}

	return u.GetUserByID(ctx, userID)
}
