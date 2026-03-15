import httpx
from app.config import settings
from app.utils.normalize import normalize_ipinfo, utc_now
from app.models.shared import SourceMetadata

IPINFO_URL = "https://ipinfo.io"

async def fetch_ipinfo(ip: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="ipinfo",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{IPINFO_URL}/{ip}/json",
                headers={
                    "Authorization": f"Bearer {settings.ipinfo_api_key}",
                    "Accept": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()
            normalized = normalize_ipinfo(raw)
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