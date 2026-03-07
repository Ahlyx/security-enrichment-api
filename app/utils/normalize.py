from datetime import datetime, timezone

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def safe_get(data: dict, *keys, default=None):
    """Safely traverse nested dicts without KeyError"""
    try:
        for key in keys:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default

def normalize_abuseipdb(raw: dict) -> dict:
    data = raw.get("data", {})
    return {
        "abuse_score": safe_get(data, "abuseConfidenceScore"),
        "total_reports": safe_get(data, "totalReports"),
        "last_reported": safe_get(data, "lastReportedAt"),
        "isp": safe_get(data, "isp"),
        "usage_type": safe_get(data, "usageType"),
        "is_tor": safe_get(data, "isTor"),
    }

def normalize_ipinfo(raw: dict) -> dict:
    loc = raw.get("loc", ",").split(",")
    return {
        "country": safe_get(raw, "country"),
        "country_code": safe_get(raw, "country"),
        "region": safe_get(raw, "region"),
        "city": safe_get(raw, "city"),
        "latitude": float(loc[0]) if len(loc) == 2 else None,
        "longitude": float(loc[1]) if len(loc) == 2 else None,
    }

def normalize_virustotal(raw: dict) -> dict:
    stats = safe_get(raw, "data", "attributes", "last_analysis_stats") or {}
    malware = safe_get(raw, "data", "attributes", "popular_threat_classification", "suggested_threat_label")
    return {
        "malicious_votes": stats.get("malicious"),
        "harmless_votes": stats.get("harmless"),
        "suspicious_votes": stats.get("suspicious"),
        "last_analysis_date": safe_get(raw, "data", "attributes", "last_analysis_date"),
        "associated_malware": [malware] if malware else [],
    }