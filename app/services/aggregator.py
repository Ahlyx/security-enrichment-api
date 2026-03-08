import asyncio
from app.services.abuseipdb import fetch_abuseipdb
from app.services.ipinfo import fetch_ipinfo
from app.services.virustotal import fetch_virustotal, fetch_virustotal_domain, fetch_virustotal_url
from app.services.otx import fetch_otx, fetch_otx_domain
from app.services.whois_service import fetch_whois
from app.services.dns_service import fetch_dns
from app.services.ssl_service import fetch_ssl
from app.services.safebrowsing import fetch_safe_browsing
from app.services.urlscan import fetch_urlscan
from app.models.ip import IPResponse, GeoLocation, AbuseData, VirusTotalData
from app.models.domain import DomainResponse, WhoisData, DNSData, SSLData, DomainVirusTotalData
from app.models.url import URLResponse, SafeBrowsingData, URLScanData, URLVirusTotalData
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
    ssl_data, ssl_meta = None, None
    vt_data, vt_meta = None, None
    otx_data, otx_meta = None, None

    (
        (whois_data, whois_meta),
        (dns_data, dns_meta),
        (ssl_data, ssl_meta),
        (vt_data, vt_meta),
        (otx_data, otx_meta),
    ) = await asyncio.gather(
        fetch_whois(domain),
        fetch_dns(domain),
        fetch_ssl(domain),
        fetch_virustotal_domain(domain),
        fetch_otx_domain(domain),
        return_exceptions=False
    )

    sources = [whois_meta, dns_meta, ssl_meta, vt_meta, otx_meta]
    whois = WhoisData(**whois_data) if whois_data else None
    dns = DNSData(**dns_data) if dns_data else None
    ssl = SSLData(**ssl_data) if ssl_data else None
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
        ssl=ssl,
        virustotal=virustotal,
        is_newly_registered=is_newly_registered,
    )

async def aggregate_url(url: str) -> URLResponse:
    sb_data, sb_meta = None, None
    urlscan_data, urlscan_meta = None, None
    vt_data, vt_meta = None, None

    (
        (sb_data, sb_meta),
        (urlscan_data, urlscan_meta),
        (vt_data, vt_meta),
    ) = await asyncio.gather(
        fetch_safe_browsing(url),
        fetch_urlscan(url),
        fetch_virustotal_url(url),
        return_exceptions=False
    )

    sources = [sb_meta, urlscan_meta, vt_meta]
    safe_browsing = SafeBrowsingData(**sb_data) if sb_data else None
    urlscan = URLScanData(**urlscan_data) if urlscan_data else None
    virustotal = URLVirusTotalData(**vt_data) if vt_data else None

    is_malicious = any([
        safe_browsing and not safe_browsing.is_safe,
        urlscan and urlscan.malicious,
        virustotal and virustotal.malicious_votes and virustotal.malicious_votes > 0,
    ])

    return URLResponse(
        query=url,
        query_type="url",
        timestamp=utc_now(),
        sources=sources,
        url=url,
        safe_browsing=safe_browsing,
        urlscan=urlscan,
        virustotal=virustotal,
        is_malicious=is_malicious,
    )