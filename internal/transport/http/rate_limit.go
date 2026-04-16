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
	mu            sync.Mutex
	limit         int
	window        time.Duration
	cleanupWindow time.Duration
	lastCleanup   time.Time
	clients       map[string]clientWindow
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:         limit,
		window:        window,
		cleanupWindow: maxDuration(window, time.Minute),
		clients:       make(map[string]clientWindow),
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

	if rl.lastCleanup.IsZero() || now.Sub(rl.lastCleanup) >= rl.cleanupWindow {
		rl.cleanup(now)
		rl.lastCleanup = now
	}

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
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}

	return host
}

func (rl *RateLimiter) cleanup(now time.Time) {
	for key, window := range rl.clients {
		if now.After(window.windowEnd) {
			delete(rl.clients, key)
		}
	}
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
