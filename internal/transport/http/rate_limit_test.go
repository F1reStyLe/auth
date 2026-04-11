package httpserver

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBlocksAfterLimitAndResetsAfterWindow(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(2, 50*time.Millisecond)

	if !rl.allow("127.0.0.1") {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow("127.0.0.1") {
		t.Fatal("second request should be allowed")
	}
	if rl.allow("127.0.0.1") {
		t.Fatal("third request should be blocked")
	}

	time.Sleep(70 * time.Millisecond)

	if !rl.allow("127.0.0.1") {
		t.Fatal("request should be allowed after window reset")
	}
}

func TestClientKeyUsesHostPart(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "192.168.0.10:54321"

	if got := clientKey(req); got != "192.168.0.10" {
		t.Fatalf("clientKey = %q, want %q", got, "192.168.0.10")
	}
}
