package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/storage/sqlite/dbgen"
)

type users struct {
	dbgen func() *dbgen.Queries
}

func NewUsers(db dbgen.DBTX) *users {
	return &users{
		dbgen: func() *dbgen.Queries {
			return dbgen.New(db)
		},
	}
}

func (s *users) CreateUser(ctx context.Context, user entity.AuthUser) error {
	err := s.dbgen().CreateUser(ctx, dbgen.CreateUserParams{
		ID:    user.ID.String(),
		Email: user.Email,
		PhoneNumber: sql.NullString{
			String: user.PhoneNumber,
			Valid:  len(user.PhoneNumber) > 0,
		},
		Meta:     user.Meta,
		Password: user.Password,
	})
	return err
}

func (s *users) UpdateUserPassword(
	ctx context.Context,
	userID uuid.UUID,
	password string,
) error {
	err := s.dbgen().UpdateUserPassword(ctx, dbgen.UpdateUserPasswordParams{
		ID:       userID.String(),
		Password: password,
	})
	return err
}

func (s *users) VerifyUser(ctx context.Context, userID uuid.UUID) error {
	err := s.dbgen().UpdateUserIsVerified(ctx, dbgen.UpdateUserIsVerifiedParams{
		ID: userID.String(),
		IsVerified: sql.NullBool{
			Bool:  true,
			Valid: true,
		},
	})
	return err
}

func dbUserToAuthUser(dbUser dbgen.AppAuthUser) (entity.AuthUser, error) {
	userID, err := uuid.Parse(dbUser.ID)
	if err != nil {
		return entity.AuthUser{}, err
	}

	isVerifiedAt, err := time.Parse(timestampFormat, dbUser.IsVerifiedAt.String)
	if err != nil {
		return entity.AuthUser{}, err
	}

	createdAt, err := time.Parse(timestampFormat, dbUser.CreatedAt.String)
	if err != nil {
		return entity.AuthUser{}, err
	}

	updatedAt, err := time.Parse(timestampFormat, dbUser.UpdatedAt.String)
	if err != nil {
		return entity.AuthUser{}, err
	}

	return entity.AuthUser{
		ID:           userID,
		Email:        dbUser.Email,
		PhoneNumber:  dbUser.PhoneNumber.String,
		Password:     dbUser.Password,
		IsVerified:   dbUser.IsVerified.Bool,
		IsVerifiedAt: isVerifiedAt,
		// TODO: how does the meta come in? string? map?
		// Meta:         dbUser.Meta,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil

}

func (s *users) GetUserByID(ctx context.Context, userID uuid.UUID) (entity.AuthUser, error) {
	dbUser, err := s.dbgen().GetUserByID(ctx, userID.String())
	if err != nil {
		return entity.AuthUser{}, err
	}

	return dbUserToAuthUser(dbUser)
}

func (s *users) GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error) {
	dbUser, err := s.dbgen().GetUserByEmail(ctx, email)
	if err != nil {
		return entity.AuthUser{}, err
	}

	return dbUserToAuthUser(dbUser)
}
