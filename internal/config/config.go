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
	SMTPHost           string
	SMTPPort           string
	SMTPUsername       string
	SMTPPassword       string
	SMTPFromEmail      string
	SMTPFromName       string
	TokenExpiration    time.Duration
	RefreshTokenTTL    time.Duration
	VerifyTokenTTL     time.Duration
	ResetTokenTTL      time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
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
	smtpHost := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	smtpPort := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	smtpUsername := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	smtpPassword := strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	smtpFromEmail := strings.TrimSpace(os.Getenv("SMTP_FROM_EMAIL"))
	smtpFromName := strings.TrimSpace(os.Getenv("SMTP_FROM_NAME"))
	tokenExpireENV := strings.TrimSpace(os.Getenv("TOKEN_EXP"))
	refreshTokenTTLENV := strings.TrimSpace(os.Getenv("REFRESH_TOKEN_EXP"))
	verifyTokenTTLENV := strings.TrimSpace(os.Getenv("VERIFY_TOKEN_EXP"))
	resetTokenTTLENV := strings.TrimSpace(os.Getenv("RESET_TOKEN_EXP"))
	readTimeoutENV := strings.TrimSpace(os.Getenv("HTTP_READ_TIMEOUT"))
	writeTimeoutENV := strings.TrimSpace(os.Getenv("HTTP_WRITE_TIMEOUT"))
	idleTimeoutENV := strings.TrimSpace(os.Getenv("HTTP_IDLE_TIMEOUT"))
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
	if smtpConfigured(smtpHost, smtpPort, smtpUsername, smtpPassword, smtpFromEmail) && smtpFromName == "" {
		smtpFromName = "Auth Service"
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

	readTimeout, err := parseDurationWithDefault(readTimeoutENV, 10*time.Second)
	if err != nil {
		panic(fmt.Sprintf("invalid HTTP_READ_TIMEOUT: %q", readTimeoutENV))
	}
	writeTimeout, err := parseDurationWithDefault(writeTimeoutENV, 15*time.Second)
	if err != nil {
		panic(fmt.Sprintf("invalid HTTP_WRITE_TIMEOUT: %q", writeTimeoutENV))
	}
	idleTimeout, err := parseDurationWithDefault(idleTimeoutENV, 60*time.Second)
	if err != nil {
		panic(fmt.Sprintf("invalid HTTP_IDLE_TIMEOUT: %q", idleTimeoutENV))
	}

	return &Config{
		HTTPPort:           port,
		AppEnv:             mode,
		DatabaseURL:        databaseURL,
		JWTSecret:          jwtSecret,
		AppBaseURL:         appBaseURL,
		SMTPHost:           smtpHost,
		SMTPPort:           smtpPort,
		SMTPUsername:       smtpUsername,
		SMTPPassword:       smtpPassword,
		SMTPFromEmail:      smtpFromEmail,
		SMTPFromName:       smtpFromName,
		TokenExpiration:    tokenExpiration,
		RefreshTokenTTL:    refreshTokenTTL,
		VerifyTokenTTL:     verifyTokenTTL,
		ResetTokenTTL:      resetTokenTTL,
		ReadTimeout:        readTimeout,
		WriteTimeout:       writeTimeout,
		IdleTimeout:        idleTimeout,
		GoogleClientID:     googleClientID,
		GoogleClientSecret: googleClientSecret,
		GitHubClientID:     githubClientID,
		GitHubClientSecret: githubClientSecret,
		VKClientID:         vkClientID,
		VKClientSecret:     vkClientSecret,
	}
}

func parseDurationWithDefault(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	return time.ParseDuration(value)
}

func smtpConfigured(host, port, username, password, fromEmail string) bool {
	return host != "" || port != "" || username != "" || password != "" || fromEmail != ""
}
