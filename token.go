package goauth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
)

var (
	ErrExpirationTime   = errors.New("expiration time has passed")
	ErrTokenWrongLength = errors.New("token has wrong length")
	ErrTokenInvalid     = errors.New("token invalid")
	ErrWrongUser        = errors.New("wrong user")
)

func ValidateTokenUserID(rawToken string, secret string) (uuid.UUID, error) {
	if len(rawToken) == 0 {
		return uuid.UUID{}, ErrTokenWrongLength
	}

	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return uuid.UUID{}, ErrExpirationTime
		}

		return uuid.UUID{}, err
	}

	if !token.Valid {
		return uuid.UUID{}, ErrTokenInvalid
	}

	return uuid.Parse(claims.Issuer)
}

func NewToken(
	kind entity.TokenKind,
	userID uuid.UUID,
	secret string,
	expiringTime time.Duration,
) (entity.Token, error) {
	expiringDate := time.Now().Add(expiringTime)
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		ExpiresAt: expiringDate.Unix(),
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
		ExpiresAt: expiringDate,
	}, nil
}

type GetRefreshedTokenParams struct {
	AccessToken   string
	RefreshToken  string
	AuthSecret    string
	RefreshSecret string
	ExpiringTime  time.Duration
}

func GetRefreshedToken(params GetRefreshedTokenParams) (entity.Token, error) {
	accessToken := params.AccessToken
	authSecret := params.AuthSecret
	refreshToken := params.RefreshToken
	refreshSecret := params.RefreshSecret
	expiringTime := params.ExpiringTime

	// check the auth token and retrieve the user id
	authUserID, err := ValidateTokenUserID(accessToken, authSecret)
	if err != nil && err.Error() != ErrExpirationTime.Error() {
		return entity.Token{}, err
	}

	// check the refresh token
	refreshUserID, err := ValidateTokenUserID(refreshToken, refreshSecret)
	if err != nil {
		return entity.Token{}, err
	}

	// make sure the refresh and parsed are for the same user
	if authUserID != refreshUserID {
		return entity.Token{}, ErrWrongUser
	}

	return NewToken(entity.TokenKindAccess, refreshUserID, authSecret, expiringTime)
}
