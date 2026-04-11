package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPPort           string
	AppEnv             string
	DatabaseURL        string
	JWTSecret          string
	AppBaseURL         string
	TokenExpiration    time.Duration
	RefreshTokenTTL    time.Duration
	VerifyTokenTTL     time.Duration
	ResetTokenTTL      time.Duration
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	VKClientID         string
	VKClientSecret     string
}

func MustLoad() *Config {
	port := os.Getenv("HTTP_PORT")
	mode := os.Getenv("APP_ENV")
	databaseURL := os.Getenv("DATABASE_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	appBaseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("APP_BASE_URL")), "/")
	tokenExpireENV := strings.TrimSpace(os.Getenv("TOKEN_EXP"))
	refreshTokenTTLENV := strings.TrimSpace(os.Getenv("REFRESH_TOKEN_EXP"))
	verifyTokenTTLENV := strings.TrimSpace(os.Getenv("VERIFY_TOKEN_EXP"))
	resetTokenTTLENV := strings.TrimSpace(os.Getenv("RESET_TOKEN_EXP"))
	googleClientID := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	googleClientSecret := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET"))
	githubClientID := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
	githubClientSecret := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_SECRET"))
	vkClientID := strings.TrimSpace(os.Getenv("VK_CLIENT_ID"))
	vkClientSecret := strings.TrimSpace(os.Getenv("VK_CLIENT_SECRET"))

	if port == "" {
		panic("HTTP_PORT is required")
	}

	if mode == "" {
		panic("APP_ENV is required")
	}

	if databaseURL == "" {
		panic("DATABASE_URL is required")
	}

	if jwtSecret == "" {
		panic("JWT_SECRET is required")
	}
	if appBaseURL == "" {
		panic("APP_BASE_URL is required")
	}

	tokenExpiration, err := time.ParseDuration(tokenExpireENV)

	if err != nil {
		panic(fmt.Sprintf("invalid TOKEN_EXP: %q", tokenExpireENV))
	}

	refreshTokenTTL, err := time.ParseDuration(refreshTokenTTLENV)
	if err != nil {
		panic(fmt.Sprintf("invalid REFRESH_TOKEN_EXP: %q", refreshTokenTTLENV))
	}

	verifyTokenTTL, err := time.ParseDuration(verifyTokenTTLENV)
	if err != nil {
		panic(fmt.Sprintf("invalid VERIFY_TOKEN_EXP: %q", verifyTokenTTLENV))
	}

	resetTokenTTL, err := time.ParseDuration(resetTokenTTLENV)
	if err != nil {
		panic(fmt.Sprintf("invalid RESET_TOKEN_EXP: %q", resetTokenTTLENV))
	}

	return &Config{
		HTTPPort:           port,
		AppEnv:             mode,
		DatabaseURL:        databaseURL,
		JWTSecret:          jwtSecret,
		AppBaseURL:         appBaseURL,
		TokenExpiration:    tokenExpiration,
		RefreshTokenTTL:    refreshTokenTTL,
		VerifyTokenTTL:     verifyTokenTTL,
		ResetTokenTTL:      resetTokenTTL,
		GoogleClientID:     googleClientID,
		GoogleClientSecret: googleClientSecret,
		GitHubClientID:     githubClientID,
		GitHubClientSecret: githubClientSecret,
		VKClientID:         vkClientID,
		VKClientSecret:     vkClientSecret,
	}
}
