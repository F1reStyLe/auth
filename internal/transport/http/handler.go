package httpserver

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/F1reStyLe/auth/auth"
	"github.com/F1reStyLe/auth/internal/logger"
	authjwt "github.com/F1reStyLe/auth/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type currentUserAccessor struct{}

func (currentUserAccessor) CurrentUser(r *http.Request) *auth.User {
	return CurrentUser(r.Context())
}

func NewHandler(log *slog.Logger, authService *auth.Service, jwtManager *authjwt.JWTManager, repo *auth.PostgresRepository) http.Handler {
	authHandler := auth.NewHandler(authService, currentUserAccessor{})
	r := chi.NewRouter()
	registerLimiter := NewRateLimiter(5, time.Minute)
	loginLimiter := NewRateLimiter(10, time.Minute)
	refreshLimiter := NewRateLimiter(30, time.Minute)
	passwordResetRequestLimiter := NewRateLimiter(5, 15*time.Minute)
	passwordResetConfirmLimiter := NewRateLimiter(10, 15*time.Minute)
	verifyEmailLimiter := NewRateLimiter(10, 15*time.Minute)

	r.Use(middleware.RequestID)
	r.Use(logger.NewRequestLogger(log))
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/swagger", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
	})
	r.Handle("/swagger/*", http.StripPrefix("/swagger/", swaggerHandler()))

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(registerLimiter.Middleware()).Post("/register", authHandler.Register)
			r.With(loginLimiter.Middleware()).Post("/login", authHandler.Login)
			r.With(refreshLimiter.Middleware()).Post("/refresh", authHandler.Refresh)
			r.Post("/logout", authHandler.Logout)
			r.Get("/oauth/{provider}/start", authHandler.OAuthStart)
			r.Get("/oauth/{provider}/callback", authHandler.OAuthCallback)
			r.With(verifyEmailLimiter.Middleware()).Post("/verify-email/request", authHandler.RequestEmailVerification)
			r.With(verifyEmailLimiter.Middleware()).Post("/verify-email/confirm", authHandler.VerifyEmail)
			r.With(passwordResetRequestLimiter.Middleware()).Post("/password-reset/request", authHandler.RequestPasswordReset)
			r.With(passwordResetConfirmLimiter.Middleware()).Post("/password-reset/confirm", authHandler.ResetPassword)
		})

		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(jwtManager, repo))
			r.Get("/users/me", authHandler.Me)
			r.Put("/users/me/profile", authHandler.UpdateMyProfile)
		})

		r.Route("/admin", func(r chi.Router) {
			r.Use(AuthMiddleware(jwtManager, repo))
			r.Use(RequireRoles(auth.RoleAdmin, auth.RoleModerator))
			r.Patch("/users/{userID}/status", authHandler.UpdateUserStatus)
			r.With(RequireRoles(auth.RoleAdmin)).Patch("/users/{userID}/role", authHandler.UpdateUserRole)
		})
	})

	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
