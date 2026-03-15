package cache

import (
	"sync"
	"time"

	"github.com/Ahlyx/scanner-go/internal/models"
)

const (
	fullSuccessTTL    = time.Hour
	partialSuccessTTL = 15 * time.Minute
)

type entry struct {
	data      []byte
	expiresAt time.Time
}

// Cache is an in-memory TTL cache safe for concurrent use.
type Cache struct {
	mu    sync.RWMutex
	store map[string]entry
}

func New() *Cache {
	c := &Cache{store: make(map[string]entry)}
	go c.cleanupLoop()
	return c
}

// Get returns the cached bytes and true if the key exists and has not expired.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.store[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.data, true
}

// Set stores data using tiered TTL based on source success counts.
// Full success (all sources): 1 hour. Partial: 15 minutes. None: not cached.
func (c *Cache) Set(key string, data []byte, sources []models.SourceMetadata) {
	ttl := computeTTL(sources)
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	c.store[key] = entry{data: data, expiresAt: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func computeTTL(sources []models.SourceMetadata) time.Duration {
	if len(sources) == 0 {
		return 0
	}
	successCount := 0
	for _, s := range sources {
		if s.Success {
			successCount++
		}
	}
	switch {
	case successCount == 0:
		return 0
	case successCount == len(sources):
		return fullSuccessTTL
	default:
		return partialSuccessTTL
	}
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.store {
			if now.After(e.expiresAt) {
				delete(c.store, k)
			}
		}
		c.mu.Unlock()
	}
}
