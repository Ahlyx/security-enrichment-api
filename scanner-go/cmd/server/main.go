package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Ahlyx/scanner-go/internal/cache"
	"github.com/Ahlyx/scanner-go/internal/config"
	"github.com/Ahlyx/scanner-go/internal/handlers"
	"github.com/Ahlyx/scanner-go/internal/ratelimit"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/time/rate"
)

func main() {
	cfg := config.Load()
	c := cache.New()

	// 30 req/min for IP, domain, hash  ·  10 req/min for URL
	defaultRL := ratelimit.New(rate.Limit(30.0/60.0), 30)
	urlRL := ratelimit.New(rate.Limit(10.0/60.0), 10)

	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	}).Handler)

	// Health check (no rate limit)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// API v1 — default rate limit (30/min)
	r.Group(func(r chi.Router) {
		r.Use(defaultRL.Middleware)
		r.Get("/api/v1/ip/{address}", handlers.HandleIP(cfg, c))
		r.Get("/api/v1/domain/{name}", handlers.HandleDomain(cfg, c))
		r.Get("/api/v1/hash/{hash_value}", handlers.HandleHash(cfg, c))
	})

	// URL endpoint — stricter rate limit (10/min)
	r.Group(func(r chi.Router) {
		r.Use(urlRL.Middleware)
		r.Get("/api/v1/url", handlers.HandleURL(cfg, c))
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("scanner-go listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
