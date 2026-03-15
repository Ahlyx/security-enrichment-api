# Security Enrichment API

A threat intelligence aggregation API that enriches IPs, domains, URLs, and file hashes with data from multiple sources into a single normalized JSON response. Available in two implementations — Python (FastAPI) and Go.

> Built with Claude Code (Sonnet 4.6 + Opus 4.6) — [Ahlyx](https://github.com/Ahlyx)

---

## Repository Structure

```
security-enrichment-api/
├── scanner-python/   # FastAPI implementation
│   ├── app/
│   ├── static/       # Frontend dashboard
│   └── tests/
└── scanner-go/       # Go implementation (6.5 MB static binary)
    ├── cmd/server/
    └── internal/
```

---

## Features

- Aggregates threat intelligence from 8 sources: **AbuseIPDB, VirusTotal, IPinfo, AlienVault OTX, Google Safe Browsing, URLScan.io, MalwareBazaar, and CIRCL HashLookup**
- Parallel requests to all sources for fast response times
- Tiered TTL caching — full success: 1 hour, partial: 15 minutes, total failure: not cached
- Rate limiting per IP address (30/min for IP, domain, hash — 10/min for URL)
- Input validation — private IPs rejected, bogon detection, hash type auto-detection (MD5/SHA1/SHA256)
- Graceful degradation — partial results returned if a source fails
- Frontend dashboard with tabbed search, live color-coded results, and query history
- Identical JSON response schema across both implementations

---

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ip/{address}` | IP reputation, geolocation, and threat intelligence |
| GET | `/api/v1/domain/{name}` | Domain WHOIS, DNS records, SSL/TLS, and reputation |
| GET | `/api/v1/url?url=...` | URL safety check across Safe Browsing, URLScan, and VirusTotal |
| GET | `/api/v1/hash/{hash}` | File hash lookup — MD5, SHA1, or SHA256 |
| GET | `/health` | Health check |

---

## Example Response

```json
{
  "query": "185.220.101.1",
  "query_type": "ip",
  "timestamp": "2026-03-07T09:14:15.013806Z",
  "sources": [
    { "source": "abuseipdb", "success": true },
    { "source": "ipinfo", "success": true },
    { "source": "virustotal", "success": true },
    { "source": "alienvault_otx", "success": false, "error": "Request timed out" }
  ],
  "ip": "185.220.101.1",
  "geolocation": {
    "country": "DE",
    "region": "State of Berlin",
    "city": "Berlin"
  },
  "abuse": {
    "abuse_score": 100,
    "total_reports": 167,
    "isp": "Artikel10 e.V.",
    "is_tor": true
  },
  "virustotal": {
    "malicious_votes": 15,
    "harmless_votes": 47,
    "suspicious_votes": 3
  },
  "is_bogon": false,
  "is_tor": true
}
```

---

## Python Implementation (`scanner-python/`)

### Tech Stack

- **Python 3.12** / **FastAPI**
- **httpx** for async HTTP requests
- **asyncio.gather** for parallel API calls
- **Pydantic** / **pydantic-settings** for response schema validation and config
- **slowapi** for rate limiting
- **SQLite** for caching
- **dnspython** for DNS resolution

### Architecture

```
Request → Validate → Cache Lookup → asyncio.gather() → Normalize → Cache → Return
```

Each external service is isolated in its own module under `app/services/`. The aggregator fires all requests simultaneously using `asyncio.gather()` and merges results into a unified response schema defined by Pydantic models in `app/models/`.

### Setup

**Prerequisites:** Python 3.12+, API keys (see below)

```bash
git clone https://github.com/Ahlyx/security-enrichment-api.git
cd security-enrichment-api/scanner-python

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your API keys

uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000` for the frontend dashboard or `http://127.0.0.1:8000/docs` for interactive API docs.

---

## Go Implementation (`scanner-go/`)

### Tech Stack

- **Go 1.22**
- **chi** router for HTTP handling
- **goroutines + sync.WaitGroup** for parallel external API calls
- **Buffered channel semaphore** to bound concurrent outbound connections (cap: 20)
- **sync.RWMutex + TTL map** for in-memory caching with background cleanup goroutine
- **golang.org/x/time/rate** per-IP token bucket rate limiting
- **godotenv** for .env loading
- **likexian/whois** for WHOIS lookups

### Architecture

```
Request → Validate → Cache Lookup → goroutines (WaitGroup) → Merge → Cache → Return
```

| Concern | Approach |
|---------|----------|
| Concurrency | `sync.WaitGroup` + goroutines per endpoint |
| Semaphore | Buffered channel `make(chan struct{}, 20)` bounds outbound connections |
| Caching | `sync.RWMutex` + TTL map, background cleanup every 10 min |
| Rate limiting | Per-IP token bucket; honors `X-Forwarded-For` for reverse proxies |
| JSON parity | Pointer types for all optional fields — produces `null` not omitted, matching Python/Pydantic |

### Setup

**Prerequisites:** Go 1.22+

```bash
cd security-enrichment-api/scanner-go

# Shares .env with Python implementation automatically
# Or create a local one:
cp ../scanner-python/.env.example .env
# Edit .env and add your API keys

go run ./cmd/server
# or with a custom port:
PORT=8080 go run ./cmd/server
```

### Docker

```bash
cd scanner-go
docker build -t scanner-go .
docker run -p 8080:8080 --env-file .env scanner-go
```

The multi-stage Dockerfile produces a scratch-based image (~10 MB) with only the static binary and CA certificates. Well within Render's 512 MB free tier limit.

---

## Environment Variables

Both implementations share the same `.env` format. Copy `scanner-python/.env.example` to `.env`:

```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
MALWAREBAZAAR_API_KEY=your_key_here

CACHE_TTL_SECONDS=3600    # optional, default 3600
RATE_LIMIT=30/minute      # optional, Python only
```

**CIRCL HashLookup requires no API key.**

---

## Implementation Comparison

| | Python | Go |
|--|--------|-----|
| Binary size | N/A (interpreted) | 6.5 MB static binary |
| Concurrency | `asyncio.gather()` | goroutines + WaitGroup |
| Caching | SQLite (persistent) | In-memory TTL map |
| Rate limiting | slowapi (per IP) | token bucket (per IP) |
| Docker image | ~200 MB | ~10 MB (scratch) |
| Docs endpoint | `/docs` (Swagger) | — |
| Cold start | Slower | Fast |

---

## License

MIT — see [LICENSE](LICENSE)
