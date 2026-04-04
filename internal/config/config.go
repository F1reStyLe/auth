package config

import "os"

type Config struct {
	HTTPPort string
	AppEnv   string
}

func MustLoad() *Config {
	port := os.Getenv("HTTP_PORT")
	mode := os.Getenv("APP_ENV")

	if port == "" {
		panic("HTTP_PORT is required")
	}

	if mode == "" {
		panic("APP_ENV is required")
	}

	return &Config{
		HTTPPort: port,
		AppEnv:   mode,
	}
}
