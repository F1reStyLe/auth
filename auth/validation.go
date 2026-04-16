package auth

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,32}$`)

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidInput)
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("%w: email format is invalid", ErrInvalidInput)
	}
	return nil
}

func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("%w: username is required", ErrInvalidInput)
	}
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("%w: username must be 3-32 chars and use letters, digits, dot, underscore or dash", ErrInvalidInput)
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return ErrWeakPassword
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrWeakPassword
	}

	return nil
}

func validateOptionalURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("%w: avatar_url must be a valid URL", ErrInvalidInput)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: avatar_url must use http or https", ErrInvalidInput)
	}
	return nil
}

func validateTimezone(timezone string) error {
	if strings.TrimSpace(timezone) == "" {
		return nil
	}
	if len(timezone) > 64 {
		return fmt.Errorf("%w: timezone is too long", ErrInvalidInput)
	}
	return nil
}
