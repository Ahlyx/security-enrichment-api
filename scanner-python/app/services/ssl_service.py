import ssl
import socket
from datetime import datetime, timezone
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

def parse_cert_date(date_str: str) -> datetime | None:
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None

async def fetch_ssl(domain: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="ssl",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(10.0)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        tls_version = conn.version()
        conn.close()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        expires_at_str = cert.get("notAfter")
        expires_at = parse_cert_date(expires_at_str)
        
        days_until_expiry = None
        is_expiring_soon = None
        if expires_at:
            delta = expires_at - datetime.now(timezone.utc)
            days_until_expiry = delta.days
            is_expiring_soon = delta.days <= 30

        issuer_org = issuer.get("organizationName", "Unknown")
        subject_org = subject.get("commonName", domain)
        is_self_signed = issuer_org == subject.get("organizationName")

        normalized = {
            "is_valid": True,
            "issuer": issuer_org,
            "subject": subject_org,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "days_until_expiry": days_until_expiry,
            "is_expiring_soon": is_expiring_soon,
            "tls_version": tls_version,
            "is_self_signed": is_self_signed,
        }

        source.success = True
        return normalized, source

    except ssl.SSLCertVerificationError:
        normalized = {
            "is_valid": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "is_expiring_soon": None,
            "tls_version": None,
            "is_self_signed": None,
        }
        source.success = True
        return normalized, source

    except Exception as e:
        source.error = str(e)
        return None, source