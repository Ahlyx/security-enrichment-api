package models

import "time"

// SourceMetadata mirrors Python's SourceMetadata.
type SourceMetadata struct {
	Source      string    `json:"source"`
	RetrievedAt time.Time `json:"retrieved_at"`
	Success     bool      `json:"success"`
	Error       *string   `json:"error"`
}

// BaseResponse mirrors Python's BaseResponse.
type BaseResponse struct {
	Query     string           `json:"query"`
	QueryType string           `json:"query_type"`
	Timestamp time.Time        `json:"timestamp"`
	Sources   []SourceMetadata `json:"sources"`
}

// ── IP ────────────────────────────────────────────────────────────────────────

type GeoLocation struct {
	Country     *string  `json:"country"`
	CountryCode *string  `json:"country_code"`
	Region      *string  `json:"region"`
	City        *string  `json:"city"`
	Latitude    *float64 `json:"latitude"`
	Longitude   *float64 `json:"longitude"`
}

type AbuseData struct {
	AbuseScore   *int    `json:"abuse_score"`
	TotalReports *int    `json:"total_reports"`
	LastReported *string `json:"last_reported"`
	ISP          *string `json:"isp"`
	UsageType    *string `json:"usage_type"`
	IsTor        *bool   `json:"is_tor"`
}

type VTIPData struct {
	MaliciousVotes    *int     `json:"malicious_votes"`
	HarmlessVotes     *int     `json:"harmless_votes"`
	SuspiciousVotes   *int     `json:"suspicious_votes"`
	LastAnalysisDate  *int64   `json:"last_analysis_date"`
	AssociatedMalware []string `json:"associated_malware"`
}

type IPResponse struct {
	BaseResponse
	IP          string       `json:"ip"`
	GeoLocation *GeoLocation `json:"geolocation"`
	Abuse       *AbuseData   `json:"abuse"`
	VirusTotal  *VTIPData    `json:"virustotal"`
	IsBogon     *bool        `json:"is_bogon"`
	IsTor       *bool        `json:"is_tor"`
}

// ── Domain ────────────────────────────────────────────────────────────────────

type WhoisData struct {
	Registrar         *string `json:"registrar"`
	CreationDate      *string `json:"creation_date"`
	ExpirationDate    *string `json:"expiration_date"`
	LastUpdated       *string `json:"last_updated"`
	DomainAgeDays     *int    `json:"domain_age_days"`
	IsNewlyRegistered *bool   `json:"is_newly_registered"`
}

type DNSData struct {
	ARecords    []string `json:"a_records"`
	AAAARecords []string `json:"aaaa_records"`
	MXRecords   []string `json:"mx_records"`
	NSRecords   []string `json:"ns_records"`
	TXTRecords  []string `json:"txt_records"`
}

type SSLData struct {
	IsValid        *bool   `json:"is_valid"`
	Issuer         *string `json:"issuer"`
	Subject        *string `json:"subject"`
	ExpiresAt      *string `json:"expires_at"`
	DaysUntilExpiry *int   `json:"days_until_expiry"`
	IsExpiringSoon *bool   `json:"is_expiring_soon"`
	TLSVersion     *string `json:"tls_version"`
	IsSelfSigned   *bool   `json:"is_self_signed"`
}

type DomainVTData struct {
	MaliciousVotes   *int     `json:"malicious_votes"`
	HarmlessVotes    *int     `json:"harmless_votes"`
	SuspiciousVotes  *int     `json:"suspicious_votes"`
	LastAnalysisDate *int64   `json:"last_analysis_date"`
	Categories       []string `json:"categories"`
}

type DomainResponse struct {
	BaseResponse
	Domain            string        `json:"domain"`
	Whois             *WhoisData    `json:"whois"`
	DNS               *DNSData      `json:"dns"`
	SSL               *SSLData      `json:"ssl"`
	VirusTotal        *DomainVTData `json:"virustotal"`
	IsNewlyRegistered *bool         `json:"is_newly_registered"`
}

// ── URL ───────────────────────────────────────────────────────────────────────

type SafeBrowsingData struct {
	IsSafe  *bool    `json:"is_safe"`
	Threats []string `json:"threats"`
}

type URLScanData struct {
	Verdict       *string  `json:"verdict"`
	Score         *int     `json:"score"`
	Malicious     *bool    `json:"malicious"`
	Categories    []string `json:"categories"`
	ScreenshotURL *string  `json:"screenshot_url"`
}

type URLVTData struct {
	MaliciousVotes   *int   `json:"malicious_votes"`
	HarmlessVotes    *int   `json:"harmless_votes"`
	SuspiciousVotes  *int   `json:"suspicious_votes"`
	LastAnalysisDate *int64 `json:"last_analysis_date"`
}

type URLResponse struct {
	BaseResponse
	URL          string            `json:"url"`
	SafeBrowsing *SafeBrowsingData `json:"safe_browsing"`
	URLScan      *URLScanData      `json:"urlscan"`
	VirusTotal   *URLVTData        `json:"virustotal"`
	IsMalicious  *bool             `json:"is_malicious"`
}

// ── Hash ──────────────────────────────────────────────────────────────────────

type HashVTData struct {
	MaliciousVotes   *int    `json:"malicious_votes"`
	HarmlessVotes    *int    `json:"harmless_votes"`
	SuspiciousVotes  *int    `json:"suspicious_votes"`
	LastAnalysisDate *int64  `json:"last_analysis_date"`
	FileType         *string `json:"file_type"`
	FileSize         *int64  `json:"file_size"`
	MeaningfulName   *string `json:"meaningful_name"`
	ThreatLabel      *string `json:"threat_label"`
}

type MalwareBazaarData struct {
	FileName  *string  `json:"file_name"`
	FileType  *string  `json:"file_type"`
	FileSize  *int64   `json:"file_size"`
	Signature *string  `json:"signature"`
	Tags      []string `json:"tags"`
	FirstSeen *string  `json:"first_seen"`
	LastSeen  *string  `json:"last_seen"`
}

type CIRCLData struct {
	Found      *bool   `json:"found"`
	FileName   *string `json:"file_name"`
	FileSize   *string `json:"file_size"` // string, matching Python model
	TrustLevel *int    `json:"trust_level"`
	KnownGood  *bool   `json:"known_good"`
}

type HashResponse struct {
	BaseResponse
	HashValue     string             `json:"hash_value"`
	HashType      *string            `json:"hash_type"`
	VirusTotal    *HashVTData        `json:"virustotal"`
	MalwareBazaar *MalwareBazaarData `json:"malwarebazaar"`
	CIRCL         *CIRCLData         `json:"circl"`
	IsMalicious   *bool              `json:"is_malicious"`
	IsKnownGood   *bool              `json:"is_known_good"`
}
