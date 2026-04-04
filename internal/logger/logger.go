package logger

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/F1reStyLe/auth/internal/config"
	"github.com/go-chi/chi/v5/middleware"
)

func NewLogger(cfg *config.Config) *slog.Logger {
	switch cfg.AppEnv {
	case "prod":
		{
			return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))
		}
	default:
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}
}

func NewRequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapWriter := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(wrapWriter, r)

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status_code", wrapWriter.Status()),
				slog.Int("bytes_written", wrapWriter.BytesWritten()),
				slog.String("remote_addr", r.RemoteAddr),
				slog.Duration("duration", time.Since(start)),
			}

			if requestID := middleware.GetReqID(r.Context()); requestID != "" {
				attrs = append(attrs, slog.String("request_id", requestID))
			}

			log.Info("request completed", attrs...)
		})
	}
}
