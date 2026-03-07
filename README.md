# Security Enrichment API

A threat intelligence aggregation API that enriches IP addresses with data from multiple sources into a single normalized JSON response.

## Features

- Aggregates threat intelligence from AbuseIPDB, VirusTotal, IPinfo, and AlienVault OTX
- Parallel requests to all sources for fast response times
- SQLite caching with tiered TTL based on source success rate
- Rate limiting per IP address
- Input validation and private IP rejection
- Graceful degradation — partial results returned if a source fails

## Tech Stack

- **Python** / **FastAPI**
- **httpx** for async HTTP requests
- **asyncio.gather** for parallel API calls
- **Pydantic** for response schema validation
- **slowapi** for rate limiting
- **SQLite** for caching

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ip/{address}` | IP reputation and threat intelligence |
| GET | `/health` | Health check |
| GET | `/docs` | Interactive API documentation |

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

## Setup

### Prerequisites
- Python 3.12+
- API keys for: AbuseIPDB, VirusTotal, IPinfo, AlienVault OTX

### Installation
```bash
git clone https://github.com/Ahlyx/security-enrichment-api.git
cd security-enrichment-api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration
```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
```
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

### Running
```bash
uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000/docs` for interactive API documentation.

## Architecture
```
Request → Validate input → Check cache → Parallel API calls → Normalize → Cache result → Return
```

Each external service is isolated in its own module under `app/services/`. The aggregator fires all requests simultaneously using `asyncio.gather()` and merges results into a unified response schema defined by Pydantic models in `app/models/`.

## Caching

- Full success (all sources) → cached for 1 hour
- Partial success → cached for 15 minutes
- All sources failed → not cached