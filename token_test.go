package goauth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
)

var newAndValidateTokenTests = []struct {
	description string
	inSecret    string
	inExpTime   time.Duration
	expectError bool
}{
	{
		"simple secret",
		"1234",
		time.Minute,
		false,
	}, {
		"32 byte secret",
		"oFrwpoI22JNpRa570EEtA9j8ns8DNG27BpNnxGtsAjJfnhd+8I/7TniU7gYZpGWu",
		time.Minute,
		false,
	}, {
		"time expired",
		"1234",
		time.Minute * -1,
		true,
	},
}

func TestNewAndValidateToken(t *testing.T) {
	for _, testCase := range newAndValidateTokenTests {
		t.Run(testCase.description, func(t *testing.T) {
			userID := uuid.New()
			token, err := NewToken(
				entity.TokenKindAccess,
				userID,
				testCase.inSecret,
				testCase.inExpTime,
			)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error on newToken and got %v", err)
			}

			res, err := ValidateTokenUserID(token.Value, testCase.inSecret)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error on validateTokenUserID and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}

			if res != userID {
				t.Fatalf("expected: user=%v\ngot: %v", userID, res)
			}
		})
	}
}

var getRefreshedTokenTests = []struct {
	description string

	inAuthKind      entity.TokenKind
	inAuthUserID    uuid.UUID
	inRefreshKind   entity.TokenKind
	inRefreshTime   time.Duration
	inRefreshUserID uuid.UUID

	expectError bool
}{
	{
		"refresh",
		entity.TokenKindAccess,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Minute,
		uuid.UUID{},
		false,
	},
	{
		"wrong auth kind",
		entity.TokenKindRefresh,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Minute,
		uuid.UUID{},
		true,
	},
	{
		"wrong refresh kind",
		entity.TokenKindAccess,
		uuid.UUID{},
		entity.TokenKindAccess,
		time.Minute,
		uuid.UUID{},
		true,
	},
	{
		"wrong user",
		entity.TokenKindAccess,
		uuid.New(),
		entity.TokenKindRefresh,
		time.Minute,
		uuid.New(),
		true,
	},
	{
		"refresh expired",
		entity.TokenKindAccess,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Minute * -1,
		uuid.UUID{},
		true,
	},
}

func TestGetRefreshedToken(t *testing.T) {
	secrets := struct {
		TokenAuth    string
		TokenRefresh string
	}{TokenAuth: "1234", TokenRefresh: "5678"}

	for _, testCase := range getRefreshedTokenTests {
		t.Run(testCase.description, func(t *testing.T) {
			accessToken, _ := NewToken(
				testCase.inAuthKind,
				testCase.inAuthUserID,
				secrets.TokenAuth,
				time.Millisecond,
			)
			refreshToken, _ := NewToken(
				testCase.inRefreshKind,
				testCase.inRefreshUserID,
				secrets.TokenRefresh,
				testCase.inRefreshTime,
			)

			authSecret := secrets.TokenAuth
			if testCase.inAuthKind != entity.TokenKindAccess {
				authSecret = secrets.TokenRefresh
			}

			refreshSecret := secrets.TokenRefresh
			if testCase.inRefreshKind != entity.TokenKindRefresh {
				refreshSecret = secrets.TokenAuth
			}

			res, err := GetRefreshedToken(GetRefreshedTokenParams{
				AccessToken:   accessToken.Value,
				RefreshToken:  refreshToken.Value,
				AuthSecret:    authSecret,
				RefreshSecret: refreshSecret,
				ExpiringTime:  time.Minute * 10,
			})
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error on getRefreshedToken and got %v", err)
			}

			_, err = ValidateTokenUserID(res.Value, secrets.TokenAuth)
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error on validateTokenUserID and got %v", err)
			}

			if testCase.expectError {
				t.Fatal("expected: error")
			}
		})
	}
}
