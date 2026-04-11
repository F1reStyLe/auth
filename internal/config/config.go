package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPPort        string
	AppEnv          string
	DatabaseURL     string
	JWTSecret       string
	TokenExpiration time.Duration
	RefreshTokenTTL time.Duration
	VerifyTokenTTL  time.Duration
	ResetTokenTTL   time.Duration
}

func MustLoad() *Config {
	port := os.Getenv("HTTP_PORT")
	mode := os.Getenv("APP_ENV")
	databaseURL := os.Getenv("DATABASE_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	tokenExpireENV := strings.TrimSpace(os.Getenv("TOKEN_EXP"))
	refreshTokenTTLENV := strings.TrimSpace(os.Getenv("REFRESH_TOKEN_EXP"))
	verifyTokenTTLENV := strings.TrimSpace(os.Getenv("VERIFY_TOKEN_EXP"))
	resetTokenTTLENV := strings.TrimSpace(os.Getenv("RESET_TOKEN_EXP"))

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
		HTTPPort:        port,
		AppEnv:          mode,
		DatabaseURL:     databaseURL,
		JWTSecret:       jwtSecret,
		TokenExpiration: tokenExpiration,
		RefreshTokenTTL: refreshTokenTTL,
		VerifyTokenTTL:  verifyTokenTTL,
		ResetTokenTTL:   resetTokenTTL,
	}
}
