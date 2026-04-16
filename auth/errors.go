package auth

import "errors"

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrEmailNotVerified   = errors.New("email is not verified")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrAccountBlocked     = errors.New("account is blocked")
	ErrAccountDeactivated = errors.New("account is deactivated")
	ErrForbidden          = errors.New("forbidden")
	ErrOAuthNotConfigured = errors.New("oauth provider is not configured")
	ErrInvalidOAuthState  = errors.New("invalid oauth state")
	ErrInvalidInput       = errors.New("invalid input")
	ErrWeakPassword       = errors.New("password does not meet complexity requirements")
)
