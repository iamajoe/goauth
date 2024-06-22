package inmem

import (
	"context"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/storage"
)

type users struct {
	users []entity.AuthUser
}

func NewUsers(initialUsers []entity.AuthUser) *users {
	return &users{
		users: initialUsers,
	}
}

func (s *users) GetAll(ctx context.Context) ([]entity.AuthUser, error) {
	return s.users, nil
}

func (s *users) CreateUser(ctx context.Context, user entity.AuthUser) error {
	s.users = append(s.users, entity.AuthUser{
		ID:       user.ID,
		Email:    user.Email,
		Password: user.Password,
	})

	return nil
}

func (s *users) UpdateUserPassword(
	ctx context.Context,
	userID uuid.UUID,
	password string,
) error {
	newUsers := []entity.AuthUser{}
	for _, u := range s.users {
		if u.ID == userID {
			u.Password = password
		}

		newUsers = append(newUsers, u)
	}
	s.users = newUsers

	return nil
}

func (s *users) VerifyUser(ctx context.Context, userID uuid.UUID) error {
	newUsers := []entity.AuthUser{}
	for _, u := range s.users {
		if u.ID == userID {
			u.IsVerified = true
		}

		newUsers = append(newUsers, u)
	}
	s.users = newUsers

	return nil
}

func (s *users) GetUserByID(ctx context.Context, userID uuid.UUID) (entity.AuthUser, error) {
	for _, u := range s.users {
		if u.ID == userID {
			return u, nil
		}
	}

	return entity.AuthUser{}, storage.ErrUserNotFound
}

func (s *users) GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error) {
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}

	return entity.AuthUser{}, storage.ErrUserNotFound
}
