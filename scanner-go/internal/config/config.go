package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AbuseIPDBKey          string
	VirusTotalKey         string
	IPInfoKey             string
	OTXKey                string
	GoogleSafeBrowsingKey string
	URLScanKey            string
	MalwareBazaarKey      string
	Port                  string
}

func Load() *Config {
	// Try loading from parent directory first (shares .env with Python app),
	// then fall back to local .env.
	_ = godotenv.Load("../.env")
	_ = godotenv.Load(".env")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &Config{
		AbuseIPDBKey:          os.Getenv("ABUSEIPDB_API_KEY"),
		VirusTotalKey:         os.Getenv("VIRUSTOTAL_API_KEY"),
		IPInfoKey:             os.Getenv("IPINFO_API_KEY"),
		OTXKey:                os.Getenv("OTX_API_KEY"),
		GoogleSafeBrowsingKey: os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"),
		URLScanKey:            os.Getenv("URLSCAN_API_KEY"),
		MalwareBazaarKey:      os.Getenv("MALWAREBAZAAR_API_KEY"),
		Port:                  port,
	}
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

// CacheTTLSeconds returns the configured TTL (CACHE_TTL_SECONDS env, default 3600).
// The cache itself applies tiered logic on top of this.
func CacheTTLSeconds() int {
	return envInt("CACHE_TTL_SECONDS", 3600)
}
