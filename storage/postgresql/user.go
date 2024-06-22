package postgresql

// TODO:

type users struct {
	// getDBGen func() *dbgen.Queries
}

// func NewUsers(getDBGen func() *dbgen.Queries) *users {
func NewUsers(getDBGen func() any) *users {
	return &users{
		// getDBGen: getDBGen,
	}
}

// func (s *users) CreateUser(ctx context.Context, user entity.AuthUser) error {
// 	err := s.getDBGen().CreateUser(ctx, dbgen.CreateUserParams{
// 		ID:          user.ID,
// 		Email:       user.Email,
// 		PhoneNumber: user.PhoneNumber,
// 		Meta:        user.Meta,
// 		Password:    user.Password,
// 		IsVerified:  user.IsVerified,
// 	})
// 	return err
// }
//
// func (s *users) UpdateUserPassword(
// 	ctx context.Context,
// 	userID uuid.UUID,
// 	password string,
// ) error {
// 	err := s.getDBGen().UpdateUserPassword(ctx, dbgen.CreateUserParams{
// 		ID:          user.ID,
// 		Email:       user.Email,
// 		PhoneNumber: user.PhoneNumber,
// 		Meta:        user.Meta,
// 		Password:    user.Password,
// 		IsVerified:  user.IsVerified,
// 	})
// 	return err
// }
//
// func (s *users) VerifyUser(ctx context.Context, userID uuid.UUID) error {
// 	newUsers := []entity.AuthUser{}
// 	for _, u := range s.users {
// 		if u.ID == userID {
// 			u.IsVerified = true
// 		}
//
// 		newUsers = append(newUsers, u)
// 	}
// 	s.users = newUsers
//
// 	return nil
// }
//
// func (s *users) GetUserByID(ctx context.Context, userID uuid.UUID) (entity.AuthUser, error) {
// 	for _, u := range s.users {
// 		if u.ID == userID {
// 			return u, nil
// 		}
// 	}
//
// 	return entity.AuthUser{}, storage.ErrUserNotFound
// }
//
// func (s *users) GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error) {
// 	for _, u := range s.users {
// 		if u.Email == email {
// 			return u, nil
// 		}
// 	}
//
// 	return entity.AuthUser{}, storage.ErrUserNotFound
// }
