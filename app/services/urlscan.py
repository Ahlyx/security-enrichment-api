import httpx
import asyncio
from app.config import settings
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/"

async def fetch_urlscan(url: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="urlscan",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            submit_response = await client.post(
                URLSCAN_SUBMIT_URL,
                headers={
                    "API-Key": settings.urlscan_api_key,
                    "Content-Type": "application/json"
                },
                json={"url": url, "visibility": "public"},
                timeout=10.0
            )
            submit_response.raise_for_status()
            submit_data = submit_response.json()

            scan_uuid = submit_data.get("uuid")
            if not scan_uuid:
                source.error = "No scan UUID returned"
                return None, source

            await asyncio.sleep(15)

            result_response = await client.get(
                f"{URLSCAN_RESULT_URL}{scan_uuid}/",
                timeout=10.0
            )
            result_response.raise_for_status()
            raw = result_response.json()

            verdicts = raw.get("verdicts", {}).get("overall", {})
            categories = raw.get("verdicts", {}).get("urlscan", {}).get("categories", [])
            screenshot = raw.get("task", {}).get("screenshotURL")

            normalized = {
                "verdict": "malicious" if verdicts.get("malicious") else "clean",
                "score": verdicts.get("score", 0),
                "malicious": verdicts.get("malicious", False),
                "categories": categories,
                "screenshot_url": screenshot,
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