package scudo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/service"
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

func (u *user) GetByID(ctx context.Context, id uuid.UUID) (User, error) {
	usr, err := u.userService.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return NewUserDTO(usr), nil
}
