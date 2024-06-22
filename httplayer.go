package goauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type ctxKeyAuth string

const (
	accessTokenKey       ctxKeyAuth = "at"
	refreshTokenKey      ctxKeyAuth = "rt"
	accessTokenExpireKey ctxKeyAuth = "ate"
	UserIDKey            ctxKeyAuth = "user_id"
)

var (
	ErrAuthUserRequired = errors.New("authenticated user is required")
)

// getAccessTokenFromHeader tries to retreive the token string from the header
func getAccessTokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}

	return bearer
}

func getAuthTokenFromCookies(
	r *http.Request,
) (string, string) {
	access := ""
	refresh := ""

	for _, cookie := range r.Cookies() {
		if cookie.Name == string(accessTokenKey) && len(cookie.Value) > 0 {
			access = cookie.Value
		} else if cookie.Name == string(refreshTokenKey) && len(cookie.Value) > 0 {
			refresh = cookie.Value
		}
	}

	return access, refresh
}

func setAuthTokensOnCookies(
	w http.ResponseWriter,
	_ *http.Request,
	accessToken string,
	refreshToken string,
	accessTokenExpiresIn time.Duration,
) {
	accessTokenExpire := time.Now().Add(accessTokenExpiresIn)
	cookies := map[string]string{
		string(accessTokenKey):       accessToken,
		string(accessTokenExpireKey): strconv.FormatInt(accessTokenExpire.Unix(), 10),
		string(refreshTokenKey):      refreshToken,
	}

	if len(accessToken) > 0 {
		expires14Days := time.Now().Add(time.Second * time.Duration(60*60*24*14))
		for key, value := range cookies {
			http.SetCookie(w, &http.Cookie{
				HttpOnly: true,
				Secure:   true,
				Value:    value,
				Expires:  expires14Days,
				Name:     key,
			})
		}
	} else {
		for key := range cookies {
			http.SetCookie(w, &http.Cookie{
				Value:    "",
				HttpOnly: true,
				MaxAge:   -1,
				Expires:  time.Unix(0, 0),
				Name:     key,
			})
		}
	}
}

func GetContextUserID(ctx context.Context) *uuid.UUID {
	userIDRaw, ok := ctx.Value(UserIDKey).(string)
	if !ok || len(userIDRaw) == 0 {
		return nil
	}

	userID, err := uuid.Parse(userIDRaw)
	if err != nil {
		return nil
	}

	return &userID
}

func (auth Auth) WithAuthUserID(
	isUserRequired bool,
	errorHandler func(http.ResponseWriter, *http.Request, error),
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// dont go further if already done, maybe some nesting of middlewares
			userID := GetContextUserID(ctx)
			if userID != nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// find the tokens
			accessToken, refreshToken := getAuthTokenFromCookies(r)
			headerAccessToken := getAccessTokenFromHeader(r)
			if headerAccessToken == "" {
				accessToken = headerAccessToken
			}

			newUserID, err := ValidateTokenUserID(accessToken, auth.secrets.TokenAccess)
			if err != nil {
				if err.Error() != ErrExpirationTime.Error() {
					errorHandler(w, r, err)
					return
				}

				result, err := auth.RefreshToken(ctx, accessToken, refreshToken)
				if err != nil {
					errorHandler(w, r, err)
					return
				}

				setAuthTokensOnCookies(
					w,
					r,
					result.AccessToken,
					result.RefreshToken,
					auth.tokenExpirationTimes.Access,
				)

				if isUserRequired {
					errorHandler(w, r, ErrAuthUserRequired)
					return
				}

				// proceed without an user
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ctx = context.WithValue(ctx, UserIDKey, newUserID.String())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
