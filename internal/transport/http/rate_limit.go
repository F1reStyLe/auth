package httpserver

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type clientWindow struct {
	count     int
	windowEnd time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]clientWindow
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:   limit,
		window:  window,
		clients: make(map[string]clientWindow),
	}
}

func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.allow(clientKey(r)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) allow(key string) bool {
	now := time.Now().UTC()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	current := rl.clients[key]
	if now.After(current.windowEnd) {
		rl.clients[key] = clientWindow{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if current.count >= rl.limit {
		return false
	}

	current.count++
	rl.clients[key] = current
	return true
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}

	return host
}
