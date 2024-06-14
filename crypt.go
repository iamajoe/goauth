package goauth

import (
	"golang.org/x/crypto/bcrypt"
)

func encryptPassword(password string) string {
	if len(password) == 0 {
		return password
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed)
}

func comparePassword(hash string, password string) bool {
	if len(hash) == 0 || len(password) == 0 {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
