import httpx
import base64
from app.config import settings
from app.utils.normalize import normalize_virustotal, utc_now
from app.models.shared import SourceMetadata

VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"

async def fetch_virustotal(ip: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="virustotal",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{VIRUSTOTAL_IP_URL}/{ip}",
                headers={
                    "x-apikey": settings.virustotal_api_key,
                    "Accept": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()
            normalized = normalize_virustotal(raw)
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

async def fetch_virustotal_domain(domain: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="virustotal",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{VIRUSTOTAL_DOMAIN_URL}/{domain}",
                headers={
                    "x-apikey": settings.virustotal_api_key,
                    "Accept": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()

            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            categories = raw.get("data", {}).get("attributes", {}).get("categories", {})

            normalized = {
                "malicious_votes": stats.get("malicious"),
                "harmless_votes": stats.get("harmless"),
                "suspicious_votes": stats.get("suspicious"),
                "last_analysis_date": raw.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                "categories": list(categories.values()) if categories else [],
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

async def fetch_virustotal_url(url: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="virustotal",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{VIRUSTOTAL_URL_URL}/{url_id}",
                headers={
                    "x-apikey": settings.virustotal_api_key,
                    "Accept": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()

            stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            normalized = {
                "malicious_votes": stats.get("malicious"),
                "harmless_votes": stats.get("harmless"),
                "suspicious_votes": stats.get("suspicious"),
                "last_analysis_date": raw.get("data", {}).get("attributes", {}).get("last_analysis_date"),
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

async def fetch_virustotal_hash(hash_value: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="virustotal",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{VIRUSTOTAL_FILE_URL}/{hash_value}",
                headers={
                    "x-apikey": settings.virustotal_api_key,
                    "Accept": "application/json"
                },
                timeout=10.0
            )
            response.raise_for_status()
            raw = response.json()

            attrs = raw.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            threat = attrs.get("popular_threat_classification", {})

            normalized = {
                "malicious_votes": stats.get("malicious"),
                "harmless_votes": stats.get("harmless"),
                "suspicious_votes": stats.get("suspicious"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "file_type": attrs.get("type_description"),
                "file_size": attrs.get("size"),
                "meaningful_name": attrs.get("meaningful_name"),
                "threat_label": threat.get("suggested_threat_label"),
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