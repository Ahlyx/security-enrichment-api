import asyncio
from app.services.abuseipdb import fetch_abuseipdb
from app.services.ipinfo import fetch_ipinfo
from app.services.virustotal import fetch_virustotal, fetch_virustotal_domain
from app.services.otx import fetch_otx, fetch_otx_domain
from app.services.whois_service import fetch_whois
from app.services.dns_service import fetch_dns
from app.models.ip import IPResponse, GeoLocation, AbuseData, VirusTotalData
from app.models.domain import DomainResponse, WhoisData, DNSData, DomainVirusTotalData
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

async def aggregate_domain(domain: str) -> DomainResponse:
    whois_data, whois_meta = None, None
    dns_data, dns_meta = None, None
    vt_data, vt_meta = None, None
    otx_data, otx_meta = None, None

    (
        (whois_data, whois_meta),
        (dns_data, dns_meta),
        (vt_data, vt_meta),
        (otx_data, otx_meta),
    ) = await asyncio.gather(
        fetch_whois(domain),
        fetch_dns(domain),
        fetch_virustotal_domain(domain),
        fetch_otx_domain(domain),
        return_exceptions=False
    )

    sources = [whois_meta, dns_meta, vt_meta, otx_meta]
    whois = WhoisData(**whois_data) if whois_data else None
    dns = DNSData(**dns_data) if dns_data else None
    virustotal = DomainVirusTotalData(**vt_data) if vt_data else None

    is_newly_registered = whois_data.get("is_newly_registered") if whois_data else None

    return DomainResponse(
        query=domain,
        query_type="domain",
        timestamp=utc_now(),
        sources=sources,
        domain=domain,
        whois=whois,
        dns=dns,
        virustotal=virustotal,
        is_newly_registered=is_newly_registered,
    )