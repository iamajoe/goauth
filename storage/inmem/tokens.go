package inmem

import (
	"context"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
)

type tokens struct {
	tokens []entity.Token
}

func NewTokens(initialTokens []entity.Token) *tokens {
	return &tokens{
		tokens: initialTokens,
	}
}

func (s *tokens) GetAll(ctx context.Context) ([]entity.Token, error) {
	return s.tokens, nil
}

func (s *tokens) CreateTokens(ctx context.Context, tokens []entity.Token) error {
	s.tokens = append(s.tokens, tokens...)

	return nil
}

func (s *tokens) RemoveUserTokens(ctx context.Context, userID uuid.UUID) error {
	newTokens := []entity.Token{}
	for _, t := range s.tokens {
		if t.UserID != userID {
			newTokens = append(newTokens, t)
		}
	}
	s.tokens = newTokens

	return nil
}

func (s *tokens) RemoveUserTokensByKind(
	ctx context.Context,
	userID uuid.UUID,
	kind entity.TokenKind,
) error {
	newTokens := []entity.Token{}
	for _, t := range s.tokens {
		if t.UserID == userID && t.Kind == kind {
			continue
		}

		newTokens = append(newTokens, t)
	}
	s.tokens = newTokens

	return nil
}

func (s *tokens) AreTokensRegistered(ctx context.Context, tokens []string) (bool, error) {
	found := 0
	for _, storageToken := range s.tokens {
		for _, token := range tokens {
			if storageToken.Value == token {
				found += 1
				break
			}
		}
	}

	return len(tokens) == found, nil
}
