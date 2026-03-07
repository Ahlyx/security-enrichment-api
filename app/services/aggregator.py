import asyncio
from datetime import datetime, timezone
from app.services.abuseipdb import fetch_abuseipdb
from app.services.ipinfo import fetch_ipinfo
from app.services.virustotal import fetch_virustotal
from app.services.otx import fetch_otx
from app.models.ip import IPResponse, GeoLocation, AbuseData, VirusTotalData
from app.utils.validators import is_bogon_ip
from app.utils.normalize import utc_now

async def aggregate_ip(ip: str) -> IPResponse:
    abuse_data, abuse_meta = None, None
    ipinfo_data, ipinfo_meta = None, None
    vt_data, vt_meta = None, None
    otx_data, otx_meta = None, None

    (
        (abuse_data, abuse_meta),
        (ipinfo_data, ipinfo_meta),
        (vt_data, vt_meta),
        (otx_data, otx_meta),
    ) = await asyncio.gather(
        fetch_abuseipdb(ip),
        fetch_ipinfo(ip),
        fetch_virustotal(ip),
        fetch_otx(ip),
        return_exceptions=False
    )

    sources = [abuse_meta, ipinfo_meta, vt_meta, otx_meta]

    geolocation = GeoLocation(**ipinfo_data) if ipinfo_data else None

    abuse = AbuseData(**abuse_data) if abuse_data else None

    virustotal = VirusTotalData(**vt_data) if vt_data else None

    return IPResponse(
        query=ip,
        query_type="ip",
        timestamp=utc_now(),
        sources=sources,
        ip=ip,
        geolocation=geolocation,
        abuse=abuse,
        virustotal=virustotal,
        is_bogon=is_bogon_ip(ip),
        is_tor=abuse_data.get("is_tor") if abuse_data else None,
    )