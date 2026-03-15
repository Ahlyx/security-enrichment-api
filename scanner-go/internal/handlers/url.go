package handlers

import (
	"encoding/json"
	"net/http"
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

		type sbResult struct {
			data *models.SafeBrowsingData
			meta models.SourceMetadata
		}
		type usResult struct {
			data *models.URLScanData
			meta models.SourceMetadata
		}
		type vtResult struct {
			data *models.URLVTData
			meta models.SourceMetadata
		}

		sbCh := make(chan sbResult, 1)
		usCh := make(chan usResult, 1)
		vtCh := make(chan vtResult, 1)

		go func() {
			d, m := services.FetchSafeBrowsing(cfg.GoogleSafeBrowsingKey, targetURL)
			sbCh <- sbResult{d, m}
		}()
		go func() {
			d, m := services.FetchURLScan(cfg.URLScanKey, targetURL)
			usCh <- usResult{d, m}
		}()
		go func() {
			d, m := services.FetchVirusTotalURL(cfg.VirusTotalKey, targetURL)
			vtCh <- vtResult{d, m}
		}()

		sbRes := <-sbCh
		usRes := <-usCh
		vtRes := <-vtCh

		sbData, sbMeta := sbRes.data, sbRes.meta
		usData, usMeta := usRes.data, usRes.meta
		vtData, vtMeta := vtRes.data, vtRes.meta

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
