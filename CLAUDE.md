# CLAUDE.md
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure
```
security-enrichment-api/
├── scanner-python/   # FastAPI implementation
├── scanner-go/       # Go implementation
└── static/           # Shared frontend dashboard
```

## Commands
```bash
# Python — install dependencies (requires Python 3.12+)
cd scanner-python
pip install -r requirements.txt

# Python — run the application
uvicorn app.main:app --reload

# Python — run all tests
pytest tests/

# Go — run the server
cd scanner-go
go run ./cmd/server

# Go — build binary
cd scanner-go
go build -o scanner ./cmd/server
```

## Architecture
This is a **threat intelligence aggregation API** with two implementations — Python (FastAPI) and Go — that share identical JSON response schemas. It accepts a security indicator (IP, domain, URL, or file hash) and queries multiple external threat intel sources in parallel.

### Request Flow
```
HTTP Request → Input Validation → Cache Lookup → Parallel API Calls → Normalize → Cache Result → JSON Response
```

### Python Implementation (`scanner-python/`)

**Parallel aggregation**: Each endpoint's router calls `app/services/aggregator.py`, which fires all relevant external API calls concurrently using `asyncio.gather()`. Each service module catches its own errors so one failing source never blocks others.

**Tiered caching** (`app/cache.py`): SQLite-backed. Full success → 1 hour TTL. Partial success → 15 minutes TTL. Complete failure → not cached.

**Service isolation**: Each external API has its own module in `app/services/`.

| Layer | Location | Responsibility |
|-------|----------|---------------|
| Routers | `app/routers/` | Validate input, check cache, call aggregator, return response |
| Aggregator | `app/services/aggregator.py` | Orchestrate parallel service calls per query type |
| Services | `app/services/` | Single external API per file |
| Models | `app/models/` | Pydantic response schemas |
| Utils | `app/utils/validators.py` | Input validation |
| Config | `app/config.py` | pydantic-settings Settings class reading from `.env` |

### Go Implementation (`scanner-go/`)

**Concurrency**: `sync.WaitGroup` + goroutines per endpoint, buffered channel semaphore (cap 20) bounds outbound connections.

**Caching**: In-memory `sync.RWMutex` + TTL map with background cleanup goroutine every 10 min.

**Rate limiting**: Per-IP token bucket via `golang.org/x/time/rate`, honors `X-Forwarded-For`.

| Layer | Location | Responsibility |
|-------|----------|---------------|
| Handlers | `internal/handlers/` | Validate input, check cache, fire goroutines, return response |
| Services | `internal/services/` | Single external API per file |
| Models | `internal/models/` | Response structs with pointer types for JSON parity |
| Cache | `internal/cache/` | In-memory TTL cache |
| Config | `internal/config/` | Reads from environment / .env |

### Endpoints

| Endpoint | Sources |
|----------|---------|
| `GET /api/v1/ip/{address}` | AbuseIPDB, IPinfo, VirusTotal, OTX |
| `GET /api/v1/domain/{name}` | WHOIS, DNS, SSL, VirusTotal, OTX |
| `GET /api/v1/url?url=...` | Google Safe Browsing, URLScan.io, VirusTotal |
| `GET /api/v1/hash/{hash_value}` | VirusTotal, MalwareBazaar, CIRCL HashLookup |

### Frontend (`static/`)
Vanilla JS/HTML/CSS dashboard. Shared between both implementations.
- `API_BASE` points to backend URL (localhost in dev, Render URL in production)
- No build step required — deploy directly to Vercel as a static site

### Environment Variables
Shared `.env` format used by both implementations:
```
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
IPINFO_API_KEY
OTX_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
URLSCAN_API_KEY
MALWAREBAZAAR_API_KEY
CACHE_TTL_SECONDS   # optional, default 3600
RATE_LIMIT          # optional, default 30/minute (Python only)
```
CIRCL HashLookup requires no API key.

### Testing
Python tests use `pytest` + `pytest-asyncio`. External HTTP calls are mocked with `respx`. WHOIS, DNS, and SSL services use `unittest.mock`. Each test file covers one router.

## Rules
- Python code lives in `scanner-python/` only
- Go code lives in `scanner-go/` only
- Frontend lives in `static/` only
- Do NOT modify files outside the directory relevant to the current task
- Do not read or modify `.env` files
- Go implementation must maintain JSON parity with the Python implementation