package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Ahlyx/scanner-go/internal/models"
)

const (
	urlscanSubmitURL = "https://urlscan.io/api/v1/scan/"
	urlscanResultURL = "https://urlscan.io/api/v1/result/"
)

func FetchURLScan(apiKey, targetURL string) (*models.URLScanData, models.SourceMetadata) {
	meta := models.SourceMetadata{Source: "urlscan", RetrievedAt: time.Now().UTC()}

	acquireSem()
	defer releaseSem()

	// Submit scan
	payload, _ := json.Marshal(map[string]string{
		"url":        targetURL,
		"visibility": "public",
	})

	submitReq, err := http.NewRequest(http.MethodPost, urlscanSubmitURL, bytes.NewReader(payload))
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	submitReq.Header.Set("API-Key", apiKey)
	submitReq.Header.Set("Content-Type", "application/json")

	submitResp, err := httpClient.Do(submitReq)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer submitResp.Body.Close()

	if submitResp.StatusCode != http.StatusOK && submitResp.StatusCode != 400 {
		// 400 can indicate already-queued scan; treat non-200/400 as errors.
		if submitResp.StatusCode >= 400 {
			meta.Error = ptr(fmt.Sprintf("HTTP %d", submitResp.StatusCode))
			return nil, meta
		}
	}

	submitBody, err := io.ReadAll(submitResp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var submitData struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(submitBody, &submitData); err != nil || submitData.UUID == "" {
		errMsg := "no scan UUID returned"
		if err != nil {
			errMsg = err.Error()
		}
		meta.Error = ptr(errMsg)
		return nil, meta
	}

	// Wait for scan to complete — mirrors Python's asyncio.sleep(15).
	time.Sleep(15 * time.Second)

	// Fetch result
	resultReq, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s%s/", urlscanResultURL, submitData.UUID), nil)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	resultResp, err := httpClient.Do(resultReq)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}
	defer resultResp.Body.Close()

	if resultResp.StatusCode != http.StatusOK {
		meta.Error = ptr(fmt.Sprintf("HTTP %d", resultResp.StatusCode))
		return nil, meta
	}

	resultBody, err := io.ReadAll(resultResp.Body)
	if err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	var raw struct {
		Verdicts struct {
			Overall struct {
				Malicious bool `json:"malicious"`
				Score     int  `json:"score"`
			} `json:"overall"`
			URLScan struct {
				Categories []string `json:"categories"`
			} `json:"urlscan"`
		} `json:"verdicts"`
		Task struct {
			ScreenshotURL *string `json:"screenshotURL"`
		} `json:"task"`
	}
	if err := json.Unmarshal(resultBody, &raw); err != nil {
		meta.Error = ptr(err.Error())
		return nil, meta
	}

	verdict := "clean"
	if raw.Verdicts.Overall.Malicious {
		verdict = "malicious"
	}

	cats := raw.Verdicts.URLScan.Categories
	if cats == nil {
		cats = []string{}
	}

	meta.Success = true
	return &models.URLScanData{
		Verdict:       ptr(verdict),
		Score:         ptr(raw.Verdicts.Overall.Score),
		Malicious:     ptr(raw.Verdicts.Overall.Malicious),
		Categories:    cats,
		ScreenshotURL: raw.Task.ScreenshotURL,
	}, meta
}
