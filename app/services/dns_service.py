import dns.resolver
from app.utils.normalize import utc_now
from app.models.shared import SourceMetadata

async def fetch_dns(domain: str) -> tuple[dict | None, SourceMetadata]:
    source = SourceMetadata(
        source="dns",
        retrieved_at=utc_now(),
        success=False
    )
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        a_records = []
        mx_records = []
        ns_records = []
        txt_records = []

        try:
            answers = resolver.resolve(domain, "A")
            a_records = [str(r) for r in answers]
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "MX")
            mx_records = [str(r.exchange) for r in answers]
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "NS")
            ns_records = [str(r) for r in answers]
        except Exception:
            pass

        try:
            answers = resolver.resolve(domain, "TXT")
            txt_records = [str(r) for r in answers]
        except Exception:
            pass

        normalized = {
            "a_records": a_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
        }

        source.success = True
        return normalized, source

    except Exception as e:
        source.error = str(e)
        return None, source