package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/F1reStyLe/auth/internal/logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewHandler(log *slog.Logger) http.Handler {
	r := chi.NewRouter()

	reqLogger := logger.NewRequestLogger(log)

	r.Use(middleware.RequestID)
	r.Use(reqLogger)
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}
