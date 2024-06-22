package goauth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/sender"
)

var (
	ErrStorageRequired    = errors.New("storage required for sign in")
	ErrWrongCredentials   = errors.New("wrong credentials")
	ErrUserConflict       = errors.New("user conflict")
	ErrTokenNotRegistered = errors.New("token not registered")
)

type signInResult struct {
	UserID       uuid.UUID
	AccessToken  string
	RefreshToken string
}

func mapUsersToNotificationData(
	baseURL string,
	users []entity.AuthUser,
	extra map[string]string,
) []map[string]string {
	data := []map[string]string{}
	for _, user := range users {
		single := map[string]string{
			"baseURL": baseURL,
			"userID":  user.ID.String(),
			"email":   user.Email,
			"phone":   user.PhoneNumber,
		}

		if user.Meta != nil {
			for k, v := range user.Meta {
				single[k] = v
			}
		}

		for k, v := range extra {
			single[k] = v
		}

		data = append(data, single)
	}

	return data
}

func getTokenKindSecretAndExpire(
	kind entity.TokenKind,
	secrets AuthSecrets,
	expiringTimes AuthTokenExpirationTimes,
) (string, time.Duration) {
	var expiringTime time.Duration
	secret := ""

	switch kind {
	case entity.TokenKindAccess:
		secret = secrets.TokenAccess
		expiringTime = expiringTimes.Access
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

// SignIn enters the user credentials and returns the user if succeeded.
func (auth Auth) SignIn(ctx context.Context, email string, password string) (signInResult, error) {
	result := signInResult{}

	if auth.userStorage == nil {
		return result, ErrStorageRequired
	}

	user, err := auth.userStorage.GetUserByEmail(ctx, email)
	if err != nil {
		return result, err
	}

	if ok := comparePassword(user.Password, password); !ok {
		return result, ErrWrongCredentials
	}

	tokens := make([]entity.Token, 2)

	result.UserID = user.ID
	secret, expiringTime := getTokenKindSecretAndExpire(
		entity.TokenKindAccess,
		auth.secrets,
		auth.tokenExpirationTimes,
	)
	tokenValue, err := NewToken(entity.TokenKindAccess, user.ID, secret, expiringTime)
	if err != nil {
		return result, err
	}
	tokens[0] = tokenValue
	result.AccessToken = tokenValue.Value

	secret, expiringTime = getTokenKindSecretAndExpire(
		entity.TokenKindRefresh,
		auth.secrets,
		auth.tokenExpirationTimes,
	)
	tokenValue, err = NewToken(entity.TokenKindRefresh, user.ID, secret, expiringTime)
	if err != nil {
		return result, err
	}
	tokens[1] = tokenValue
	result.RefreshToken = tokenValue.Value

	err = auth.tokenStorage.CreateTokens(ctx, tokens)
	return result, err
}

// SignOut revokes the users token and session.
func (auth Auth) SignOut(ctx context.Context, userID uuid.UUID) error {
	if auth.tokenStorage == nil {
		return ErrStorageRequired
	}

	return auth.tokenStorage.RemoveUserTokens(ctx, userID)
}

// SignUp registers the user's email and password to the database.
func (auth Auth) SignUp(
	ctx context.Context,
	user entity.AuthUser,
) (uuid.UUID, error) {
	if auth.userStorage == nil || auth.tokenStorage == nil {
		return uuid.UUID{}, ErrStorageRequired
	}

	if ok, err := validateEmail(user.Email); !ok {
		return uuid.UUID{}, err
	}

	if ok, err := validatePassword(user.Password); !ok {
		return uuid.UUID{}, err
	}

	registeredUser, _ := auth.userStorage.GetUserByEmail(ctx, user.Email)
	if registeredUser.Email == user.Email {
		return uuid.UUID{}, ErrUserConflict
	}

	user.ID = uuid.New()
	user.Password = encryptPassword(user.Password)

	err := auth.userStorage.CreateUser(ctx, user)
	if err != nil {
		return user.ID, err
	}

	// DEV: in dev mode we might want to circumvent verification when testing
	//      things, as such, we automatically verify the user
	if auth.autoVerifyUser {
		return user.ID, auth.userStorage.VerifyUser(ctx, user.ID)
	}

	secret, expiringTime := getTokenKindSecretAndExpire(
		entity.TokenKindVerify,
		auth.secrets,
		auth.tokenExpirationTimes,
	)
	token, err := NewToken(entity.TokenKindVerify, user.ID, secret, expiringTime)
	if err != nil {
		return user.ID, err
	}

	err = auth.tokenStorage.CreateTokens(ctx, []entity.Token{token})
	if err != nil {
		return user.ID, err
	}

	data := mapUsersToNotificationData(
		auth.baseURL,
		[]entity.AuthUser{user},
		map[string]string{"code": token.Value},
	)
	errs := sender.SendBulk(auth.senders, sender.TemplateSignUp, data)
	if len(errs) == 0 {
		return user.ID, nil
	}

	err = errors.Join(errs...)
	return user.ID, err
}

// SignUpVerify is to be called upon a verification email to complete the signup process
func (auth Auth) SignUpVerify(ctx context.Context, oneTimeToken string) error {
	ok, err := auth.tokenStorage.AreTokensRegistered(ctx, []string{oneTimeToken})
	if err != nil {
		return err
	}
	if !ok {
		return ErrTokenNotRegistered
	}

	userID, err := ValidateTokenUserID(oneTimeToken, auth.secrets.TokenVerify)
	if err != nil {
		return err
	}

	err = auth.tokenStorage.RemoveUserTokens(ctx, userID)
	if err != nil {
		return err
	}

	return auth.userStorage.VerifyUser(ctx, userID)
}

// RequestResetPassword sends an email for the user to perform the reset password
func (auth Auth) RequestResetPassword(ctx context.Context, email string) error {
	if auth.userStorage == nil {
		return ErrStorageRequired
	}

	user, err := auth.userStorage.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}

	secret, expiringTime := getTokenKindSecretAndExpire(
		entity.TokenKindResetPassword,
		auth.secrets,
		auth.tokenExpirationTimes,
	)
	token, err := NewToken(
		entity.TokenKindResetPassword,
		user.ID,
		secret,
		expiringTime,
	)
	if err != nil {
		return err
	}

	err = auth.tokenStorage.CreateTokens(ctx, []entity.Token{token})
	if err != nil {
		return err
	}

	data := mapUsersToNotificationData(
		auth.baseURL,
		[]entity.AuthUser{user},
		map[string]string{"code": token.Value},
	)
	errs := sender.SendBulk(auth.senders, sender.TemplateResetPassword, data)
	if len(errs) == 0 {
		return nil
	}

	return errors.Join(errs...)
}

// ResetPassword will take the token generated by RequestResetPassword and change the password
func (auth Auth) ResetPassword(ctx context.Context, oneTimeToken string, password string) error {
	if auth.userStorage == nil {
		return ErrStorageRequired
	}

	ok, err := auth.tokenStorage.AreTokensRegistered(ctx, []string{oneTimeToken})
	if err != nil {
		return err
	}
	if !ok {
		return ErrTokenNotRegistered
	}

	secret := auth.secrets.TokenResetPassword
	userID, err := ValidateTokenUserID(oneTimeToken, secret)
	if err != nil {
		return err
	}

	err = auth.tokenStorage.RemoveUserTokens(ctx, userID)
	if err != nil {
		return err
	}

	return auth.userStorage.UpdateUserPassword(ctx, userID, encryptPassword(password))
}

// RefreshToken takes auth and refresh tokens and resolves a new auth token
func (auth Auth) RefreshToken(
	ctx context.Context,
	accessToken string,
	refreshToken string,
) (signInResult, error) {
	result := signInResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	if auth.tokenStorage == nil {
		return result, ErrStorageRequired
	}

	ok, err := auth.tokenStorage.AreTokensRegistered(ctx, []string{refreshToken})
	if err != nil {
		return result, err
	}
	if !ok {
		return result, ErrTokenNotRegistered
	}

	authSecret, _ := getTokenKindSecretAndExpire(
		entity.TokenKindAccess,
		auth.secrets,
		auth.tokenExpirationTimes,
	)
	refreshSecret, expiringTime := getTokenKindSecretAndExpire(
		entity.TokenKindRefresh,
		auth.secrets,
		auth.tokenExpirationTimes,
	)

	newToken, err := GetRefreshedToken(GetRefreshedTokenParams{
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		AuthSecret:    authSecret,
		RefreshSecret: refreshSecret,
		ExpiringTime:  expiringTime,
	})
	if err != nil {
		return result, err
	}

	userID, err := ValidateTokenUserID(accessToken, authSecret)
	if err != nil {
		return result, err
	}

	err = auth.tokenStorage.RemoveUserToken(ctx, userID, accessToken)
	if err != nil {
		return result, err
	}

	result.AccessToken = newToken.Value
	err = auth.tokenStorage.CreateTokens(ctx, []entity.Token{newToken})

	return result, err
}
