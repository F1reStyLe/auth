package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/F1reStyLe/auth/auth"
	"github.com/F1reStyLe/auth/internal/config"
	"github.com/F1reStyLe/auth/internal/migrator"
	httpserver "github.com/F1reStyLe/auth/internal/transport/http"
	"github.com/F1reStyLe/auth/platform/postgres"
	"github.com/F1reStyLe/auth/token"
)

func Run(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := postgres.New(cfg.DatabaseURL)

	if err != nil {
		return fmt.Errorf("init postgres: %w", err)
	}

	log.Info("database connected")

	if err := migrator.Up(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	log.Info("migrations applied")

	repo := auth.NewRepository(db)
	jwtManager := token.NewJWTManager(cfg.JWTSecret)
	service := auth.NewService(
		repo,
		jwtManager,
		cfg.TokenExpiration,
		cfg.RefreshTokenTTL,
		cfg.VerifyTokenTTL,
		cfg.ResetTokenTTL,
	)
	authHandler := auth.NewHandler(service)

	server := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           httpserver.NewHandler(log, authHandler),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		log.Info("auth service listening", slog.String("addr", server.Addr))

		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("listen and serve: %w", err)
		}

		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, stopping server")
	case err := <-errCh:
		{
			if err != nil {
				log.Error("server exited with error", slog.String("error", err.Error()))
				return err
			}
			return nil
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", slog.String("error", err.Error()))
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	log.Info("server stopped")
	return nil
}
