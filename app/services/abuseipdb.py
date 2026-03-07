import httpx
from datetime import datetime, timezone
from app.config import settings
from app.utils.normalize import normalize_abuseipdb, utc_now
from app.models.shared import SourceMetadata

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

async def fetch_abuseipdb(ip: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="abuseipdb",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                ABUSEIPDB_URL,
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()
            normalized = normalize_abuseipdb(raw)
            source.success = True
            return normalized, source

    except httpx.TimeoutException:
        source.error = "Request timed out"
        return None, source
    except httpx.HTTPStatusError as e:
        source.error = f"HTTP {e.response.status_code}"
        return None, source
    except Exception as e:
        source.error = str(e)
        return None, source