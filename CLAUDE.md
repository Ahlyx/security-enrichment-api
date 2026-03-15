# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies (requires Python 3.12+)
pip install -r requirements.txt

# Run the application
uvicorn app.main:app --reload

# Run all tests
pytest tests/

# Run a single test file
pytest tests/test_ip.py

# Run a single test by name
pytest tests/test_ip.py::test_function_name -v
```

## Architecture

This is a **threat intelligence aggregation API** built with FastAPI. It accepts a security indicator (IP, domain, URL, or file hash) and queries multiple external threat intel sources in parallel, returning a unified enriched response.

### Request Flow

```
HTTP Request → Input Validation → Cache Lookup → Parallel External API Calls → Normalize → Cache Result → JSON Response
```

### Key Design Patterns

**Parallel aggregation**: Each endpoint's router calls `app/services/aggregator.py`, which fires all relevant external API calls concurrently using `asyncio.gather()`. Each service module catches its own errors so one failing source never blocks others.

**Tiered caching** (`app/cache.py`): SQLite-backed. Full success (all sources respond) → 1 hour TTL. Partial success → 15 minutes TTL. Complete failure → not cached.

**Service isolation**: Each external API has its own module in `app/services/`. All services follow the same pattern: make an async HTTP request via `httpx`, normalize the raw response into fields expected by the Pydantic model, and return `None` (or partial data) on any error/timeout.

### Layer Map

| Layer | Location | Responsibility |
|-------|----------|---------------|
| Routers | `app/routers/` | Validate input, check cache, call aggregator, return response |
| Aggregator | `app/services/aggregator.py` | Orchestrate parallel service calls per query type |
| Services | `app/services/` | Single external API per file (abuseipdb, virustotal, ipinfo, otx, safebrowsing, urlscan, malwarebazaar, circl, whois_service, dns_service, ssl_service) |
| Models | `app/models/` | Pydantic response schemas (`ip.py`, `domain.py`, `url.py`, `hash.py`, `shared.py`) |
| Utils | `app/utils/validators.py` | Input validation — rejects private/reserved IPs, enforces hash length/format, etc. |
| Config | `app/config.py` | `pydantic-settings` Settings class reading from `.env` |

### Endpoints

| Endpoint | Sources |
|----------|---------|
| `GET /api/v1/ip/{address}` | AbuseIPDB, IPinfo, VirusTotal, OTX |
| `GET /api/v1/domain/{name}` | WHOIS, DNS, SSL, VirusTotal, OTX |
| `GET /api/v1/url?url=...` | Google Safe Browsing, URLScan.io, VirusTotal |
| `GET /api/v1/hash/{hash_value}` | VirusTotal, MalwareBazaar, CIRCL HashLookup |

Hash type (MD5/SHA1/SHA256) is auto-detected from length (32/40/64 hex chars).

### Environment Variables

Copy `.env.example` to `.env` and populate API keys:

```
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
IPINFO_API_KEY
OTX_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
URLSCAN_API_KEY
MALWAREBAZAAR_API_KEY
CACHE_TTL_SECONDS   # optional, default 3600
RATE_LIMIT          # optional, default 30/minute
```

CIRCL HashLookup requires no API key.

### Testing

Tests use `pytest` + `pytest-asyncio`. External HTTP calls are mocked with `respx`. WHOIS, DNS, and SSL services use `unittest.mock`. Each test file covers one router (happy path, validation errors, cache hits, partial source failures).

## Go Rewrite Rules
- All Go code goes in `/scanner-go/` directory only
- Do NOT modify any existing Python files
- Match the exact same API endpoints and response JSON structure
- Do not read or modify .env files