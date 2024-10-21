package models

import (
	"time"

	"github.com/google/uuid"
)

// SSHKey represents an SSH key associated with a user
type SSHKey struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}