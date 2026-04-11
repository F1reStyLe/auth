package httpserver

import (
	"context"
	"net/http"
	"strings"

	"github.com/F1reStyLe/auth/auth"
	authjwt "github.com/F1reStyLe/auth/token"
)

type userRepository interface {
	GetUserByID(ctx context.Context, id int64) (*auth.User, error)
}

type tokenClaimsParser interface {
	Parse(tokenString string) (*authjwt.Claims, error)
}

type contextKey string

const currentUserKey contextKey = "current_user"

func AuthMiddleware(parser tokenClaimsParser, users userRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := bearerToken(r.Header.Get("Authorization"))
			if tokenString == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			claims, err := parser.Parse(tokenString)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			user, err := users.GetUserByID(r.Context(), claims.UserID)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if user.AccountStatus != auth.AccountStatusActive {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), currentUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRoles(roles ...auth.Role) func(http.Handler) http.Handler {
	allowed := make(map[auth.Role]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := CurrentUser(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if _, ok := allowed[user.Role]; !ok {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CurrentUser(ctx context.Context) *auth.User {
	user, _ := ctx.Value(currentUserKey).(*auth.User)
	return user
}

func bearerToken(header string) string {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}
