package entity

import (
	"github.com/google/uuid"
)

type AuthUser struct {
	ID          uuid.UUID
	Email       string
	PhoneNumber string
	Password    string
	IsVerified  bool
}
