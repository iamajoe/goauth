package goauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iamajoe/goauth/entity"
	"github.com/iamajoe/goauth/sender"
)

type AuthSecrets struct {
	TokenAccess        string
	TokenRefresh       string
	TokenVerify        string
	TokenResetPassword string
}

type AuthTokenExpirationTimes struct {
	Access        time.Duration
	Refresh       time.Duration
	Verify        time.Duration
	ResetPassword time.Duration
}

// TODO: custom client methods

type Auth struct {
	secrets              AuthSecrets
	tokenExpirationTimes AuthTokenExpirationTimes

	tokenStorage tokenStorage
	userStorage  userStorage
	senders      []sender.Sender

	autoVerifyUser bool
	baseURL        string
}

type tokenStorage interface {
	CreateTokens(ctx context.Context, tokens []entity.Token) error
	RemoveUserTokens(ctx context.Context, userID uuid.UUID) error
	RemoveUserToken(ctx context.Context, userID uuid.UUID, token string) error
	AreTokensRegistered(ctx context.Context, tokens []string) (bool, error)
}

type userStorage interface {
	CreateUser(ctx context.Context, user entity.AuthUser) error
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, password string) error
	VerifyUser(ctx context.Context, userID uuid.UUID) error
	GetUserByID(ctx context.Context, userID uuid.UUID) (entity.AuthUser, error)
	GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error)
}

type optFn func(*Auth) *Auth

func New(secrets AuthSecrets, opts ...optFn) *Auth {
	auth := &Auth{
		secrets: secrets,
		tokenExpirationTimes: AuthTokenExpirationTimes{
			Access:        1 * 24 * time.Hour,
			Refresh:       7 * 24 * time.Hour,
			Verify:        1 * 24 * time.Hour,
			ResetPassword: 1 * 24 * time.Hour,
		},
		baseURL: "http://localhost",
	}

	return auth.SetOpts(opts...)
}

// SetOpts gives a simple way upon creation to change some of the options
func (auth *Auth) SetOpts(opts ...optFn) *Auth {
	for _, opt := range opts {
		auth = opt(auth)
	}

	return auth
}

// WithUserStorage sets the storage to be used to register and list users
func WithUserStorage(storage userStorage) optFn {
	return func(auth *Auth) *Auth {
		auth.userStorage = storage
		return auth
	}
}

// WithTokenStorage sets the storage to be used to register and list tokens
func WithTokenStorage(storage tokenStorage) optFn {
	return func(auth *Auth) *Auth {
		auth.tokenStorage = storage
		return auth
	}
}

// WithTokenExpirationTimes changes the default token expiration times
func WithTokenExpirationTimes(times AuthTokenExpirationTimes) optFn {
	return func(auth *Auth) *Auth {
		auth.tokenExpirationTimes = times
		return auth
	}
}

// WithSender sets a sender provider, for example to send an email upon SignUp
func WithSender(s sender.Sender) optFn {
	return func(auth *Auth) *Auth {
		auth.senders = append(auth.senders, s)
		return auth
	}
}

// WithAutoVerifyUser automatically verifies the user upon signup
// in dev mode we might want to circumvent verification when testing
// things, as such, we automatically verify the user
func WithAutoVerifyUser() optFn {
	return func(auth *Auth) *Auth {
		auth.autoVerifyUser = true
		return auth
	}
}

// WithBaseURL sets the base url ot be used for example on the email links
func WithBaseURL(baseURL string) optFn {
	return func(auth *Auth) *Auth {
		auth.baseURL = baseURL
		return auth
	}
}
