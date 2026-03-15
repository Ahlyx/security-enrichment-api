package ratelimit

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter provides per-IP rate limiting using a token bucket.
type Limiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	r        rate.Limit
	burst    int
}

// New creates a Limiter with the given rate (req/s) and burst size.
// Use rate.Limit(30.0/60.0) for 30 req/min.
func New(r rate.Limit, burst int) *Limiter {
	l := &Limiter{
		limiters: make(map[string]*limiterEntry),
		r:        r,
		burst:    burst,
	}
	go l.cleanupLoop()
	return l
}

func (l *Limiter) getLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.limiters[ip]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(l.r, l.burst)}
		l.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter
}

// Allow checks whether the given IP is within the rate limit.
func (l *Limiter) Allow(ip string) bool {
	return l.getLimiter(ip).Allow()
}

// Middleware returns a chi-compatible middleware that enforces this rate limit.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"detail": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Hour)
		l.mu.Lock()
		for ip, e := range l.limiters {
			if e.lastSeen.Before(cutoff) {
				delete(l.limiters, ip)
			}
		}
		l.mu.Unlock()
	}
}

// clientIP extracts the real client IP, honoring X-Forwarded-For for proxied
// deployments (Render routes traffic through a proxy).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
	}
	return addr
}
