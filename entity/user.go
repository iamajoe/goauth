package entity

import (
	"time"

	"github.com/google/uuid"
)

type AuthUser struct {
	ID           uuid.UUID
	Email        string
	PhoneNumber  string
	Password     string
	IsVerified   bool
	IsVerifiedAt time.Time
	Meta         map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
