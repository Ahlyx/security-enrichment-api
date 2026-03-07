import httpx
from app.config import settings
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"

async def fetch_otx(ip: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="alienvault_otx",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{OTX_URL}/{ip}/general",
                headers={
                    "X-OTX-API-KEY": settings.otx_api_key,
                    "Accept": "application/json"
                },
                timeout=5.0
            )
            response.raise_for_status()
            raw = response.json()

            normalized = {
                "pulse_count": raw.get("pulse_info", {}).get("count", 0),
                "malware_families": [
                    p.get("name") for p in
                    raw.get("pulse_info", {}).get("pulses", [])[:5]
                ],
                "country": raw.get("country_name"),
                "asn": raw.get("asn"),
            }

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