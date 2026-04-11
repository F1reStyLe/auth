package auth

import "time"

type User struct {
	ID              int64
	Username        string
	Email           string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	CreatedAt       time.Time
}

type Session struct {
	ID         int64
	UserID     int64
	TokenHash  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

type OneTimeToken struct {
	ID         int64
	UserID     int64
	Purpose    string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}
