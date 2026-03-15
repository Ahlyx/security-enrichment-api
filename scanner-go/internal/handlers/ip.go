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
	"github.com/go-chi/chi/v5"
)

func HandleIP(cfg *config.Config, c *cache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := chi.URLParam(r, "address")

		if !validators.IsValidIP(ip) {
			writeError(w, http.StatusUnprocessableEntity, "Invalid IP address")
			return
		}
		if validators.IsBogonIP(ip) {
			writeError(w, http.StatusUnprocessableEntity, "Private and reserved IP addresses are not supported")
			return
		}

		cacheKey := "ip:" + ip
		if cached, ok := c.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(cached)
			return
		}

		var (
			abuseData *models.AbuseData
			abuseMeta models.SourceMetadata
			geoData   *models.GeoLocation
			geoMeta   models.SourceMetadata
			vtData    *models.VTIPData
			vtMeta    models.SourceMetadata
			otxMeta   models.SourceMetadata
		)

		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); abuseData, abuseMeta = services.FetchAbuseIPDB(cfg.AbuseIPDBKey, ip) }()
		go func() { defer wg.Done(); geoData, geoMeta = services.FetchIPInfo(cfg.IPInfoKey, ip) }()
		go func() { defer wg.Done(); vtData, vtMeta = services.FetchVirusTotalIP(cfg.VirusTotalKey, ip) }()
		go func() { defer wg.Done(); _, otxMeta = services.FetchOTXIP(cfg.OTXKey, ip) }()
		wg.Wait()

		isBogon := validators.IsBogonIP(ip)

		// Derive is_tor directly from the AbuseIPDB result without an
		// intermediate pointer copy that can silently become nil.
		var isTor *bool
		if abuseData != nil && abuseData.IsTor != nil {
			v := *abuseData.IsTor
			isTor = &v
		}

		resp := &models.IPResponse{
			BaseResponse: models.BaseResponse{
				Query:     ip,
				QueryType: "ip",
				Timestamp: time.Now().UTC(),
				Sources:   []models.SourceMetadata{abuseMeta, geoMeta, vtMeta, otxMeta},
			},
			IP:          ip,
			GeoLocation: geoData,
			Abuse:       abuseData,
			VirusTotal:  vtData,
			IsBogon:     &isBogon,
			IsTor:       isTor,
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
