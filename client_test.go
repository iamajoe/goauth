package goauth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/storage/inmem"
)

var signInTests = []struct {
	description string
	inUsers     []entity.AuthUser
	inEmail     string
	inPassword  string
	expectError bool
}{
	{
		"login",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
			{ID: uuid.New(), Email: "foo@bar.com", Password: encryptPassword("1234")},
		},
		"foo@bar.com",
		"1234",
		false,
	}, {
		"wrong email",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
			{ID: uuid.New(), Email: "foo@bar.com", Password: encryptPassword("1234")},
		},
		"foo-wrong@bar.com",
		"1234",
		true,
	}, {
		"wrong password",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
			{ID: uuid.New(), Email: "foo@bar.com", Password: encryptPassword("1234")},
		},
		"foo@bar.com",
		"2345",
		true,
	},
}

func TestSignIn(t *testing.T) {
	for _, testCase := range signInTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers(testCase.inUsers)

			users, _ := userStore.GetAll(context.Background())
			var user entity.AuthUser
			for _, u := range users {
				if u.Email == testCase.inEmail {
					user = u
				}
			}

			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			res, err := auth.SignIn(context.Background(), testCase.inEmail, testCase.inPassword)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			// check if tokens were saved in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			authTokenFound := false
			refreshTokenFound := false
			for _, t := range tokens {
				if t.UserID != user.ID {
					continue
				}

				if t.Kind == entity.TokenKindAuth && t.Value == res.AuthToken {
					authTokenFound = true
				} else if t.Kind == entity.TokenKindRefresh && t.Value == res.RefreshToken {
					refreshTokenFound = true
				}
			}

			if !authTokenFound {
				t.Fatal("expected: an AuthToken")
			}

			if !refreshTokenFound {
				t.Fatal("expected: a RefreshToken")
			}

			// check if right user
			if user.ID != res.UserID {
				t.Fatalf("expected: user=%v\ngot: %v", user.ID, res.UserID)
			}
		})
	}
}

var signOutTests = []struct {
	description string
	inUsers     []entity.AuthUser
	inEmail     string
}{
	{
		"logout",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com"},
			{ID: uuid.New(), Email: "foo@bar.com"},
		},
		"foo@bar.com",
	}, {
		"wrong user",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com"},
			{ID: uuid.New(), Email: "foo@bar.com"},
		},
		"foo-wrong@bar.com",
	},
}

func TestSignOut(t *testing.T) {
	for _, testCase := range signInTests {
		t.Run(testCase.description, func(t *testing.T) {
			userStore := inmem.NewUsers(testCase.inUsers)

			// give tokens to all registered users
			tokens := []entity.Token{}
			users, _ := userStore.GetAll(context.Background())
			tokenTime := time.Now().Add(time.Minute)

			var user entity.AuthUser
			for _, u := range users {
				tok, _ := newToken(entity.TokenKindAuth, u.ID, "1234", tokenTime)
				tokens = append(tokens, tok)

				// find the user subject of the test
				if u.Email == testCase.inEmail {
					user = u
				}
			}
			tokenStore := inmem.NewTokens(tokens)

			auth := New(
				AuthSecrets{TokenAuth: "1234"},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			err := auth.SignOut(context.Background(), user.ID)
			if err != nil {
				t.Fatalf("expected: non error and got %v", err)
			}

			// check if tokens were saved in storage
			tokens, _ = tokenStore.GetAll(context.Background())
			for _, user := range users {
				found := false
				for _, tok := range tokens {
					if tok.UserID == user.ID {
						found = true
						break
					}
				}

				if user.Email == testCase.inEmail && found {
					t.Fatalf("expected: user=%v to have no tokens", user.Email)
				}

				if user.Email != testCase.inEmail && !found {
					t.Fatalf("expected: user=%v to have tokens", user.Email)
				}
			}
		})
	}
}

var signUpTests = []struct {
	description string
	inUsers     []entity.AuthUser
	inEmail     string
	inPassword  string
	expectError bool
}{
	{
		"signs up",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
		},
		"foo@bar.com",
		"12345678",
		false,
	}, {
		"user already registered",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
			{ID: uuid.New(), Email: "foo@bar.com", Password: encryptPassword("1234")},
		},
		"foo@bar.com",
		"12345678",
		true,
	},
	{"invalid password", []entity.AuthUser{}, "foo@bar.com", "1234", true},
	{"invalid email", []entity.AuthUser{}, "foobar.com", "12345678", true},
}

func TestSignUp(t *testing.T) {
	for _, testCase := range signUpTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers(testCase.inUsers)
			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			res, err := auth.SignUp(context.Background(), testCase.inEmail, testCase.inPassword)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			// check if tokens were saved in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			verifyTokenFound := false
			for _, t := range tokens {
				if t.UserID == res && t.Kind == entity.TokenKindVerify {
					verifyTokenFound = true
				}
			}

			if !verifyTokenFound {
				t.Fatal("expected: verify token to be on storage")
			}
		})
	}
}

var signUpVerifyTests = []struct {
	description  string
	inWrongToken bool
	expectError  bool
}{
	{"success", false, false},
	{"wrong token", true, true},
}

func TestSignUpVerify(t *testing.T) {
	for _, testCase := range signUpVerifyTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers([]entity.AuthUser{})
			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			var token string
			userID, _ := auth.SignUp(context.Background(), "foo@bar.com", "12345678")
			if testCase.inWrongToken {
				rawToken, _ := newToken(
					entity.TokenKindAuth, userID,
					auth.secrets.TokenAuth,
					time.Now().Add(time.Hour),
				)
				token = rawToken.Value
			} else {
				tokens, _ := tokenStore.GetAll(context.Background())
				for _, tok := range tokens {
					if tok.UserID == userID && tok.Kind == entity.TokenKindVerify {
						token = tok.Value
						break
					}
				}
			}

			err := auth.SignUpVerify(context.Background(), token)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			// check if user was verified
			user, _ := userStore.GetUserByEmail(context.Background(), "foo@bar.com")
			if !user.IsVerified {
				t.Fatalf("expected: user verified=%v\ngot: %v", true, user.IsVerified)
			}

			// check if tokens were saved in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			for _, tok := range tokens {
				if tok.UserID == user.ID && tok.Kind == entity.TokenKindVerify {
					t.Fatal("expected: verify token to have been removed")
				}
			}
		})
	}
}

var requestResetPasswordTests = []struct {
	description string
	inUsers     []entity.AuthUser
	inEmail     string
	expectError bool
}{
	{
		"success",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "foo@bar.com", Password: encryptPassword("1234")},
		},
		"foo@bar.com",
		false,
	}, {
		"error with not registered email",
		[]entity.AuthUser{
			{ID: uuid.New(), Email: "nofoo@bar.com", Password: encryptPassword("4321")},
		},
		"foo@bar.com",
		true,
	},
}

func TestRequestResetPassword(t *testing.T) {
	for _, testCase := range requestResetPasswordTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers(testCase.inUsers)
			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			var user entity.AuthUser
			for _, storeUser := range testCase.inUsers {
				if storeUser.Email == testCase.inEmail {
					user = storeUser
				}
			}

			err := auth.RequestResetPassword(context.Background(), testCase.inEmail)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			// having an email means that a token was saved
			if user.Email != testCase.inEmail {
				return
			}

			// check if tokens were saved in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			tokenFound := false
			for _, t := range tokens {
				if t.UserID == user.ID && t.Kind == entity.TokenKindResetPassword {
					tokenFound = true
				}
			}

			if !tokenFound {
				t.Fatal("expected: reset password token to be on storage")
			}
		})
	}
}

var resetPasswordTests = []struct {
	description  string
	inWrongToken bool
	expectError  bool
}{
	{"success", false, false},
	{"wrong token", true, true},
}

func TestResetPassword(t *testing.T) {
	for _, testCase := range resetPasswordTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers([]entity.AuthUser{})
			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			var token string
			email := "foo@bar.com"
			oldPassword := "12345678"
			userID, _ := auth.SignUp(context.Background(), email, oldPassword)
			_ = auth.RequestResetPassword(context.Background(), email)

			if testCase.inWrongToken {
				rawToken, _ := newToken(
					entity.TokenKindAuth, userID,
					auth.secrets.TokenAuth,
					time.Now().Add(time.Hour),
				)
				token = rawToken.Value
			} else {
				tokens, _ := tokenStore.GetAll(context.Background())
				for _, tok := range tokens {
					if tok.UserID == userID && tok.Kind == entity.TokenKindResetPassword {
						token = tok.Value
						break
					}
				}
			}

			newPassword := "87654321"
			err := auth.ResetPassword(context.Background(), token, newPassword)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			// check if the password has changed
			res, _ := auth.SignIn(context.Background(), email, newPassword)
			if len(res.AuthToken) == 0 {
				t.Fatal("expected: password to be changed per the new")
			}

			res, _ = auth.SignIn(context.Background(), email, oldPassword)
			if len(res.AuthToken) != 0 {
				t.Fatal("expected: old password to be changed")
			}

			// check if tokens were removed in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			for _, tok := range tokens {
				if tok.UserID == userID && tok.Kind == entity.TokenKindResetPassword {
					t.Fatal("expected: reset password token to have been removed")
				}
			}
		})
	}
}

var refreshTokenTests = []struct {
	description  string
	inWrongToken bool
	expectError  bool
}{
	{"success", false, false},
	{"wrong token", true, true},
}

func TestRefreshToken(t *testing.T) {
	for _, testCase := range refreshTokenTests {
		t.Run(testCase.description, func(t *testing.T) {
			tokenStore := inmem.NewTokens([]entity.Token{})
			userStore := inmem.NewUsers([]entity.AuthUser{})
			auth := New(
				AuthSecrets{
					TokenAuth:          "1234",
					TokenRefresh:       "2345",
					TokenVerify:        "3456",
					TokenResetPassword: "4567",
				},
				WithTokenStorage(tokenStore),
				WithUserStorage(userStore),
			)

			email := "foo@bar.com"
			password := "12345678"
			userID, _ := auth.SignUp(context.Background(), email, password)
			oldTokens, _ := auth.SignIn(context.Background(), email, password)

			if testCase.inWrongToken {
				rawToken, _ := newToken(
					entity.TokenKindAuth, userID,
					auth.secrets.TokenAuth,
					time.Now().Add(time.Hour),
				)
				oldTokens.RefreshToken = rawToken.Value
			}

			newTokens, err := auth.RefreshToken(
				context.Background(),
				oldTokens.AuthToken,
				oldTokens.RefreshToken,
			)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			if newTokens.RefreshToken != oldTokens.RefreshToken {
				t.Fatalf(
					"expected: RefreshToken=%v\ngot: %v",
					oldTokens.RefreshToken,
					newTokens.RefreshToken,
				)
			}

			tokenID, _ := validateTokenUserID(newTokens.AuthToken, auth.secrets.TokenAuth)
			if tokenID != userID {
				t.Fatalf("expected: token user id=%v\ngot: %v", userID, tokenID)
			}

			// check if right tokens are in storage
			tokens, _ := tokenStore.GetAll(context.Background())
			tokenFound := false
			for _, tok := range tokens {
				if tok.Value == oldTokens.AuthToken {
					t.Fatal("expected: old auth token to have been removed")
				}

				if tok.UserID == userID &&
					tok.Kind == entity.TokenKindAuth &&
					tok.Value == newTokens.AuthToken {
					tokenFound = true
				}
			}

			if !tokenFound {
				t.Fatal("expected: the new auth token to be in")
			}
		})
	}
}
