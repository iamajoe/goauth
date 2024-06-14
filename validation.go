package goauth

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	passwordMinLen = 8
)

func validateEmail(email string) (bool, error) {
	// NOTE: .international, .finance are valid domains
	re := regexp.MustCompile(`^[\w-\.+]+@([\w-]+\.)+[\w-]{2,14}$`)
	if ok := re.MatchString(email); !ok {
		return false, errors.New("invalid email")
	}

	return true, nil
}

// TODO: should check other rules
func validatePassword(password string) (bool, error) {
	if len(password) < passwordMinLen {
		err := fmt.Errorf("password without the required length: %d", passwordMinLen)
		return false, err
	}

	return true, nil
}
