package goauth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

var encryptPasswordTests = []struct {
	description string
	in          string
}{
	{"simple password", "1234"},
	{"secure password", "abc123!A#."},
}

func TestEncryptPassword(t *testing.T) {
	for _, testCase := range encryptPasswordTests {
		t.Run(testCase.description, func(t *testing.T) {
			res := encryptPassword(testCase.in)
			if err := bcrypt.CompareHashAndPassword([]byte(res), []byte(testCase.in)); err == nil {
				return
			}

			t.Fatalf("expected: password %v comparison to return true", testCase.in)
		})
	}
}

var comparePasswordTests = []struct {
	description    string
	inHashPassword string
	inPassword     string
	expected       bool
}{
	{"true with simple password", "1234", "1234", true},
	{"true with secure password", "abc123!A#.", "abc123!A#.", true},
	{"false with wrong password", "abc123!A#!", "abc123!A#.", false},
	{"false with empty password", "123", "", false},
	{"false with empty hash", "", "123", false},
}

func TestComparePassword(t *testing.T) {
	for _, testCase := range comparePasswordTests {
		t.Run(testCase.description, func(t *testing.T) {
			hashed, _ := bcrypt.GenerateFromPassword(
				[]byte(testCase.inHashPassword),
				bcrypt.DefaultCost,
			)

			res := comparePassword(string(hashed), testCase.inPassword)
			if res == testCase.expected {
				return
			}

			t.Fatalf("expected: result=%v\ngot: %v", testCase.expected, res)
		})
	}
}
