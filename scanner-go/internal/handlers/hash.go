package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ahlyx/scanner-go/internal/cache"
	"github.com/Ahlyx/scanner-go/internal/config"
	"github.com/Ahlyx/scanner-go/internal/models"
	"github.com/Ahlyx/scanner-go/internal/services"
	"github.com/Ahlyx/scanner-go/internal/validators"
	"github.com/go-chi/chi/v5"
)

func HandleHash(cfg *config.Config, c *cache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hashValue := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "hash_value")))

		if !validators.IsValidHash(hashValue) {
			writeError(w, http.StatusUnprocessableEntity,
				"Invalid hash. Must be MD5 (32), SHA1 (40), or SHA256 (64) hex characters")
			return
		}

		hashType := validators.GetHashType(hashValue)

		cacheKey := "hash:" + hashValue
		if cached, ok := c.Get(cacheKey); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(cached)
			return
		}

		var (
			vtData *models.HashVTData
			vtMeta models.SourceMetadata
			mbData *models.MalwareBazaarData
			mbMeta models.SourceMetadata
			clData *models.CIRCLData
			clMeta models.SourceMetadata
		)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			vtData, vtMeta = services.FetchVirusTotalHash(cfg.VirusTotalKey, hashValue)
		}()
		go func() {
			defer wg.Done()
			mbData, mbMeta = services.FetchMalwareBazaar(cfg.MalwareBazaarKey, hashValue)
		}()
		go func() {
			defer wg.Done()
			clData, clMeta = services.FetchCIRCL(hashValue, hashType)
		}()
		wg.Wait()

		// Derive is_malicious and is_known_good (mirrors Python aggregator).
		isMalicious := false
		if vtData != nil && vtData.MaliciousVotes != nil && *vtData.MaliciousVotes > 0 {
			isMalicious = true
		}
		if mbData != nil && mbData.Signature != nil {
			isMalicious = true
		}

		isKnownGood := false
		if clData != nil && clData.KnownGood != nil && *clData.KnownGood && !isMalicious {
			isKnownGood = true
		}

		var hashTypePtr *string
		if hashType != "" {
			hashTypePtr = &hashType
		}

		resp := &models.HashResponse{
			BaseResponse: models.BaseResponse{
				Query:     hashValue,
				QueryType: "hash",
				Timestamp: time.Now().UTC(),
				Sources:   []models.SourceMetadata{vtMeta, mbMeta, clMeta},
			},
			HashValue:     hashValue,
			HashType:      hashTypePtr,
			VirusTotal:    vtData,
			MalwareBazaar: mbData,
			CIRCL:         clData,
			IsMalicious:   &isMalicious,
			IsKnownGood:   &isKnownGood,
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
