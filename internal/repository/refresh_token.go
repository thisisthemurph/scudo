package repository

import "time"

func (rt *ScudoRefreshToken) Expired() bool {
	return rt.ExpiresAt.Before(time.Now())
}
