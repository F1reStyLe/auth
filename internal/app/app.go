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
	"github.com/F1reStyLe/auth/internal/notify"
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
	defer db.Close()

	log.Info("database connected")

	if err := migrator.Up(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	log.Info("migrations applied")

	repo := auth.NewRepository(db)
	jwtManager := token.NewJWTManager(cfg.JWTSecret)
	var notifier auth.NotificationSender
	if cfg.SMTPHost != "" {
		mailer, err := notify.NewSMTPMailer(notify.SMTPConfig{
			Host:      cfg.SMTPHost,
			Port:      cfg.SMTPPort,
			Username:  cfg.SMTPUsername,
			Password:  cfg.SMTPPassword,
			FromEmail: cfg.SMTPFromEmail,
			FromName:  cfg.SMTPFromName,
		})
		if err != nil {
			return fmt.Errorf("init smtp mailer: %w", err)
		}
		notifier = mailer
	}
	oauthProviders := map[auth.OAuthProvider]auth.OAuthProviderClient{}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		oauthProviders[auth.OAuthProviderGoogle] = auth.NewGoogleOAuthClient(
			httpClient,
			cfg.GoogleClientID,
			cfg.GoogleClientSecret,
			cfg.AppBaseURL+"/api/v1/auth/oauth/google/callback",
		)
	}
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		oauthProviders[auth.OAuthProviderGitHub] = auth.NewGitHubOAuthClient(
			httpClient,
			cfg.GitHubClientID,
			cfg.GitHubClientSecret,
			cfg.AppBaseURL+"/api/v1/auth/oauth/github/callback",
		)
	}
	if cfg.VKClientID != "" && cfg.VKClientSecret != "" {
		oauthProviders[auth.OAuthProviderVK] = auth.NewVKOAuthClient(
			httpClient,
			cfg.VKClientID,
			cfg.VKClientSecret,
			cfg.AppBaseURL+"/api/v1/auth/oauth/vk/callback",
		)
	}
	service := auth.NewService(
		repo,
		jwtManager,
		notifier,
		cfg.TokenExpiration,
		cfg.RefreshTokenTTL,
		cfg.VerifyTokenTTL,
		cfg.ResetTokenTTL,
		cfg.JWTSecret,
		cfg.AppBaseURL,
		oauthProviders,
	)

	server := &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           httpserver.NewHandler(log, service, jwtManager, repo),
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
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
