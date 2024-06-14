package entity

import (
	"time"

	"github.com/google/uuid"
)

type TokenKind int

const (
	TokenKindAuth TokenKind = iota
	TokenKindRefresh
	TokenKindVerify
	TokenKindResetPassword
)

type Token struct {
	Kind      TokenKind
	Value     string
	UserID    uuid.UUID
	ExpiresAt time.Time
}
