package sqlite

import (
	"context"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/storage/sqlite/dbgen"
)

type tokens struct {
	db    dbWithTx
	dbgen func() *dbgen.Queries
}

func NewTokens(db dbWithTx) *tokens {
	return &tokens{
		db: db,
		dbgen: func() *dbgen.Queries {
			return dbgen.New(db)
		},
	}
}

func (s *tokens) CreateTokens(ctx context.Context, tokens []entity.Token) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// TODO: investigate on how to insert multiple through the query
	qtx := s.dbgen().WithTx(tx)
	for _, token := range tokens {
		err := qtx.CreateToken(ctx, dbgen.CreateTokenParams{
			UserID:    token.UserID.String(),
			Kind:      int64(token.Kind),
			Value:     token.Value,
			ExpiresAt: token.ExpiresAt.Format(timestampFormat),
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *tokens) RemoveUserTokens(ctx context.Context, userID uuid.UUID) error {
	return s.dbgen().RemoveUserTokens(ctx, userID.String())
}

func (s *tokens) RemoveUserToken(
	ctx context.Context,
	userID uuid.UUID,
	token string,
) error {
	return s.dbgen().RemoveUserToken(ctx, dbgen.RemoveUserTokenParams{
		UserID: userID.String(),
		Value:  token,
	})
}

func (s *tokens) AreTokensRegistered(ctx context.Context, tokens []string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	// TODO: investigate on how to check multiple through the query
	qtx := s.dbgen().WithTx(tx)
	for _, token := range tokens {
		result, err := qtx.IsTokenRegistered(ctx, token)
		if err != nil {
			return false, err
		}

		// TODO: investigate if this is actually right
		if result != 1 {
			return false, nil
		}
	}

	return true, nil
}
