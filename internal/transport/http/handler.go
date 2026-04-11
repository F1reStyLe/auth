package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/F1reStyLe/auth/auth"
	"github.com/F1reStyLe/auth/internal/logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewHandler(log *slog.Logger, authHandler *auth.Handler) http.Handler {
	r := chi.NewRouter()
	registerLimiter := NewRateLimiter(5, time.Minute)
	loginLimiter := NewRateLimiter(10, time.Minute)

	r.Use(middleware.RequestID)
	r.Use(logger.NewRequestLogger(log))
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(registerLimiter.Middleware()).Post("/register", authHandler.Register)
			r.With(loginLimiter.Middleware()).Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)
			r.Post("/verify-email/request", authHandler.RequestEmailVerification)
			r.Post("/verify-email/confirm", authHandler.VerifyEmail)
			r.Post("/password-reset/request", authHandler.RequestPasswordReset)
			r.Post("/password-reset/confirm", authHandler.ResetPassword)
		})

		r.Get("/users/me", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
		})
	})

	return r
}
