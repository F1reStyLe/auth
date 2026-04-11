package main

import (
	"log/slog"
	"os"

	"github.com/F1reStyLe/auth/internal/app"
	"github.com/F1reStyLe/auth/internal/config"
	"github.com/F1reStyLe/auth/internal/logger"
)

func main() {
	cfg := config.MustLoad()

	log := logger.NewLogger(cfg.AppEnv)

	if err := app.Run(cfg, log); err != nil {
		log.Error("application stopped with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
