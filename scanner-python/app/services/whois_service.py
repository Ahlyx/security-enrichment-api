import whois
from datetime import datetime, timezone
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

def parse_date(date_val) -> str | None:
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    return str(date_val)

def calculate_age_days(creation_date_str: str | None) -> int | None:
    if not creation_date_str:
        return None
    try:
        creation = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - creation
        return delta.days
    except Exception:
        return None

async def fetch_whois(domain: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="whois",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        w = whois.whois(domain)

        creation_date = parse_date(w.creation_date)
        expiration_date = parse_date(w.expiration_date)
        last_updated = parse_date(w.updated_date)
        age_days = calculate_age_days(creation_date)

        normalized = {
            "registrar": w.registrar if isinstance(w.registrar, str) else None,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "last_updated": last_updated,
            "domain_age_days": age_days,
            "is_newly_registered": age_days is not None and age_days < 30,
        }

        source.success = True
        return normalized, source

    except Exception as e:
        source.error = str(e)
        return None, source