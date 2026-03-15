package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Ahlyx/scanner-go/internal/cache"
	"github.com/Ahlyx/scanner-go/internal/config"
	"github.com/Ahlyx/scanner-go/internal/models"
	"github.com/Ahlyx/scanner-go/internal/services"
	"github.com/Ahlyx/scanner-go/internal/validators"
)

func HandleURL(cfg *config.Config, c *cache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")

		if targetURL == "" {
			writeError(w, http.StatusUnprocessableEntity, "url query parameter is required")
			return
		}
		if !validators.IsValidURL(targetURL) {
			writeError(w, http.StatusUnprocessableEntity, "URL must start with http:// or https://")
			return
		}

		cacheKey := "url:" + targetURL
		if cached, ok := c.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(cached)
			return
		}

		var (
			sbData   *models.SafeBrowsingData
			sbMeta   models.SourceMetadata
			usData   *models.URLScanData
			usMeta   models.SourceMetadata
			vtData   *models.URLVTData
			vtMeta   models.SourceMetadata
		)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			sbData, sbMeta = services.FetchSafeBrowsing(cfg.GoogleSafeBrowsingKey, targetURL)
		}()
		go func() {
			defer wg.Done()
			usData, usMeta = services.FetchURLScan(cfg.URLScanKey, targetURL)
		}()
		go func() {
			defer wg.Done()
			vtData, vtMeta = services.FetchVirusTotalURL(cfg.VirusTotalKey, targetURL)
		}()
		wg.Wait()

		// Derive is_malicious from all sources (mirrors Python aggregator logic).
		isMalicious := false
		if sbData != nil && sbData.IsSafe != nil && !*sbData.IsSafe {
			isMalicious = true
		}
		if usData != nil && usData.Malicious != nil && *usData.Malicious {
			isMalicious = true
		}
		if vtData != nil && vtData.MaliciousVotes != nil && *vtData.MaliciousVotes > 0 {
			isMalicious = true
		}

		resp := &models.URLResponse{
			BaseResponse: models.BaseResponse{
				Query:     targetURL,
				QueryType: "url",
				Timestamp: time.Now().UTC(),
				Sources:   []models.SourceMetadata{sbMeta, usMeta, vtMeta},
			},
			URL:          targetURL,
			SafeBrowsing: sbData,
			URLScan:      usData,
			VirusTotal:   vtData,
			IsMalicious:  &isMalicious,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "serialization error")
			return
		}

		c.Set(cacheKey, data, resp.Sources)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}
