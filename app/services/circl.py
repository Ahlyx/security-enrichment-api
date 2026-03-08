import httpx
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

CIRCL_URL = "https://hashlookup.circl.lu/lookup"

async def fetch_circl(hash_value: str, hash_type: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="circl_hashlookup",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{CIRCL_URL}/{hash_type}/{hash_value}",
                headers={
                    "User-Agent": "security-enrichment-api/0.1.0"
                },
                timeout=10.0
            )

            if response.status_code == 404:
                normalized = {
                    "found": False,
                    "file_name": None,
                    "file_size": None,
                    "trust_level": None,
                    "known_good": False,
                }
                source.success = True
                return normalized, source

            response.raise_for_status()
            raw = response.json()

            normalized = {
                "found": True,
                "file_name": raw.get("FileName") or raw.get("file_name"),
                "file_size": raw.get("FileSize") or raw.get("file_size"),
                "trust_level": raw.get("hashlookup:trust"),
                "known_good": raw.get("hashlookup:trust", 0) >= 75,
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