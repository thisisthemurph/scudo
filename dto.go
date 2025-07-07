package scudo

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/thisisthemurph/scudo/internal/repository"
	"time"
)

type User struct {
	ID              uuid.UUID       `json:"id"`
	Email           string          `json:"email"`
	Metadata        json.RawMessage `json:"metadata"`
	MetadataMap     map[string]any  `json:"metadataMap"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	IsAuthenticated bool            `json:"isAuthenticated"`
}

func NewUserDTO(u repository.ScudoUser) User {
	var metadata map[string]any
	_ = json.Unmarshal(u.Metadata, &metadata)

	return User{
		ID:              u.ID,
		Email:           u.Email,
		Metadata:        u.Metadata,
		MetadataMap:     metadata,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
		IsAuthenticated: true,
	}
}
