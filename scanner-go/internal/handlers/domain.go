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

func HandleDomain(cfg *config.Config, c *cache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := chi.URLParam(r, "name")

		if !validators.IsValidDomain(domain) {
			writeError(w, http.StatusUnprocessableEntity, "Invalid domain name")
			return
		}

		cacheKey := "domain:" + domain
		if cached, ok := c.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(cached)
			return
		}

		var (
			whoisData *models.WhoisData
			whoisMeta models.SourceMetadata
			dnsData   *models.DNSData
			dnsMeta   models.SourceMetadata
			sslData   *models.SSLData
			sslMeta   models.SourceMetadata
			vtData    *models.DomainVTData
			vtMeta    models.SourceMetadata
			otxMeta   models.SourceMetadata
		)

		var wg sync.WaitGroup
		wg.Add(5)
		go func() { defer wg.Done(); whoisData, whoisMeta = services.FetchWHOIS(domain) }()
		go func() { defer wg.Done(); dnsData, dnsMeta = services.FetchDNS(domain) }()
		go func() { defer wg.Done(); sslData, sslMeta = services.FetchSSL(domain) }()
		go func() {
			defer wg.Done()
			vtData, vtMeta = services.FetchVirusTotalDomain(cfg.VirusTotalKey, domain)
		}()
		go func() { defer wg.Done(); _, otxMeta = services.FetchOTXDomain(cfg.OTXKey, domain) }()
		wg.Wait()

		var isNewlyRegistered *bool
		if whoisData != nil {
			isNewlyRegistered = whoisData.IsNewlyRegistered
		}

		resp := &models.DomainResponse{
			BaseResponse: models.BaseResponse{
				Query:     domain,
				QueryType: "domain",
				Timestamp: time.Now().UTC(),
				Sources:   []models.SourceMetadata{whoisMeta, dnsMeta, sslMeta, vtMeta, otxMeta},
			},
			Domain:            domain,
			Whois:             whoisData,
			DNS:               dnsData,
			SSL:               sslData,
			VirusTotal:        vtData,
			IsNewlyRegistered: isNewlyRegistered,
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
