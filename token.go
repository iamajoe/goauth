package goauth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
)

const (
	expirationTimeError string = "expiration time has passed"
)

func validateTokenUserID(rawToken string, secret string) (uuid.UUID, error) {
	if len(rawToken) == 0 {
		return uuid.UUID{}, errors.New("token needs length")
	}

	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}

	if !token.Valid {
		return uuid.UUID{}, errors.New("token invalid")
	}

	return uuid.Parse(claims.Issuer)
}

func newToken(
	kind entity.TokenKind,
	userID uuid.UUID,
	secret string,
	expiringTime time.Time,
) (entity.Token, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: expiringTime.Unix(),
		Issuer:    userID.String(),
	})
	value, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		return entity.Token{}, err
	}

	return entity.Token{
		Kind:      kind,
		Value:     value,
		UserID:    userID,
		ExpiresAt: expiringTime,
	}, nil
}

type getRefreshedTokenParams struct {
	authToken     string
	refreshToken  string
	authSecret    string
	refreshSecret string
	expiringTime  time.Time
}

func getRefreshedToken(params getRefreshedTokenParams) (entity.Token, error) {
	authToken := params.authToken
	authSecret := params.authSecret
	refreshToken := params.refreshToken
	refreshSecret := params.refreshSecret
	expiringTime := params.expiringTime

	// check the auth token and retrieve the user id
	authUserID, err := validateTokenUserID(authToken, authSecret)
	if err != nil && err.Error() != expirationTimeError {
		return entity.Token{}, err
	}

	// check the refresh token
	refreshUserID, err := validateTokenUserID(refreshToken, refreshSecret)
	if err != nil {
		return entity.Token{}, err
	}

	// make sure the refresh and parsed are for the same user
	if authUserID != refreshUserID {
		return entity.Token{}, errors.New("wrong user id")
	}

	return newToken(entity.TokenKindAuth, refreshUserID, authSecret, expiringTime)
}

func getTokenKindSecretAndExpire(
	kind entity.TokenKind,
	secrets AuthSecrets,
	expiringTimes AuthTokenExpirationTimes,
) (string, time.Time) {
	secret := ""
	expiringTime := time.Now()

	switch kind {
	case entity.TokenKindAuth:
		secret = secrets.TokenAuth
		expiringTime = expiringTimes.Auth
	case entity.TokenKindRefresh:
		secret = secrets.TokenRefresh
		expiringTime = expiringTimes.Refresh
	case entity.TokenKindVerify:
		secret = secrets.TokenVerify
		expiringTime = expiringTimes.Verify
	case entity.TokenKindResetPassword:
		secret = secrets.TokenResetPassword
		expiringTime = expiringTimes.ResetPassword
	}

	return secret, expiringTime
}
