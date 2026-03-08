import httpx
from app.config import settings
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

async def fetch_safe_browsing(url: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="google_safe_browsing",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        payload = {
            "client": {
                "clientId": "security-enrichment-api",
                "clientVersion": "0.1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SAFE_BROWSING_URL}?key={settings.google_safe_browsing_api_key}",
                json=payload,
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()

            matches = raw.get("matches", [])
            threats = [m.get("threatType") for m in matches if m.get("threatType")]

            normalized = {
                "is_safe": len(threats) == 0,
                "threats": threats,
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