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
	inExpTime   time.Time
	expectError bool
}{
	{
		"simple secret",
		"1234",
		time.Now().Add(time.Minute),
		false,
	}, {
		"32 byte secret",
		"oFrwpoI22JNpRa570EEtA9j8ns8DNG27BpNnxGtsAjJfnhd+8I/7TniU7gYZpGWu",
		time.Now().Add(time.Minute),
		false,
	}, {
		"time expired",
		"1234",
		time.Now().Add(time.Minute * -1),
		true,
	},
}

func TestNewAndValidateToken(t *testing.T) {
	for _, testCase := range newAndValidateTokenTests {
		t.Run(testCase.description, func(t *testing.T) {
			userID := uuid.New()
			token, err := newToken(
				entity.TokenKindAuth,
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

			res, err := validateTokenUserID(token.Value, testCase.inSecret)
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
	inRefreshTime   time.Time
	inRefreshUserID uuid.UUID

	expectError bool
}{
	{
		"refresh",
		entity.TokenKindAuth,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Now().Add(time.Minute),
		uuid.UUID{},
		false,
	},
	{
		"wrong auth kind",
		entity.TokenKindRefresh,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Now().Add(time.Minute),
		uuid.UUID{},
		true,
	},
	{
		"wrong refresh kind",
		entity.TokenKindAuth,
		uuid.UUID{},
		entity.TokenKindAuth,
		time.Now().Add(time.Minute),
		uuid.UUID{},
		true,
	},
	{
		"wrong user",
		entity.TokenKindAuth,
		uuid.New(),
		entity.TokenKindRefresh,
		time.Now().Add(time.Minute),
		uuid.New(),
		true,
	},
	{
		"refresh expired",
		entity.TokenKindAuth,
		uuid.UUID{},
		entity.TokenKindRefresh,
		time.Now().Add(time.Minute * -1),
		uuid.UUID{},
		true,
	},
}

func TestGetRefreshedToken(t *testing.T) {
	secrets := AuthSecrets{TokenAuth: "1234", TokenRefresh: "5678"}
	for _, testCase := range getRefreshedTokenTests {
		t.Run(testCase.description, func(t *testing.T) {
			authToken, _ := newToken(
				testCase.inAuthKind,
				testCase.inAuthUserID,
				secrets.TokenAuth,
				time.Now(),
			)
			refreshToken, _ := newToken(
				testCase.inRefreshKind,
				testCase.inRefreshUserID,
				secrets.TokenRefresh,
				testCase.inRefreshTime,
			)

			authSecret := secrets.TokenAuth
			if testCase.inAuthKind != entity.TokenKindAuth {
				authSecret = secrets.TokenRefresh
			}

			refreshSecret := secrets.TokenRefresh
			if testCase.inRefreshKind != entity.TokenKindRefresh {
				refreshSecret = secrets.TokenAuth
			}

			res, err := getRefreshedToken(getRefreshedTokenParams{
				authToken:     authToken.Value,
				refreshToken:  refreshToken.Value,
				authSecret:    authSecret,
				refreshSecret: refreshSecret,
				expiringTime:  time.Now().Add(time.Minute * 10),
			})
			if err != nil {
				if testCase.expectError {
					return
				}
				t.Fatalf("expected: non error on getRefreshedToken and got %v", err)
			}

			_, err = validateTokenUserID(res.Value, secrets.TokenAuth)
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
