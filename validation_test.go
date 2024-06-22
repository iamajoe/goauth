package goauth

import (
	"testing"
)

var validateEmailTests = []struct {
	description string
	value       string
	expected    bool
}{
	{"success", "foo@gmail.com", true},
	{"missing domain", "foo@gmail", false},
	{"missing user", "@gmail.com", false},
}

func TestValidateEmail(t *testing.T) {
	for _, testCase := range validateEmailTests {
		t.Run(testCase.description, func(t *testing.T) {
			ok, err := validateEmail(testCase.value)
			if ok != testCase.expected {
				t.Fatalf("expected: ok=%v\ngot: %v", testCase.expected, ok)
			}

			if !ok && err == nil {
				t.Fatal("expected: an error")
			}
		})
	}
}

var validatePasswordTests = []struct {
	description string
	value       string
	expected    bool
}{
	{"success", "12345678", true},
	{"too short", "1234567", false},
}

func TestValidatePassword(t *testing.T) {
	for _, testCase := range validatePasswordTests {
		t.Run(testCase.description, func(t *testing.T) {
			ok, err := validatePassword(testCase.value)
			if ok != testCase.expected {
				t.Fatalf("expected: ok=%v\ngot: %v", testCase.expected, ok)
			}

			if !ok && err == nil {
				t.Fatal("expected: an error")
			}
		})
	}
}
