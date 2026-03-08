import pytest
import respx
from httpx import Response
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_cache():
    from app.cache import clear_all_cache
    clear_all_cache()

@respx.mock
def test_domain_returns_200():
    respx.get("https://www.virustotal.com/api/v3/domains/google.com").mock(return_value=Response(200, json={
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "harmless": 80,
                    "suspicious": 0
                },
                "last_analysis_date": 1700000000,
                "categories": {}
            }
        }
    }))
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/google.com/general").mock(return_value=Response(200, json={
        "pulse_info": {"count": 0, "pulses": []},
        "alexa": "1"
    }))

    mock_whois = MagicMock()
    mock_whois.registrar = "MarkMonitor Inc."
    mock_whois.creation_date = "1997-09-15T00:00:00"
    mock_whois.expiration_date = "2028-09-14T00:00:00"
    mock_whois.updated_date = "2019-09-09T00:00:00"

    with patch("app.services.whois_service.whois.whois", return_value=mock_whois):
        with patch("app.services.dns_service.dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = Exception("no record")
            mock_resolver_class.return_value = mock_resolver
            with patch("app.services.ssl_service.ssl.create_default_context", side_effect=Exception("no ssl in test")):
                response = client.get("/api/v1/domain/google.com")

    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "google.com"
    assert data["query_type"] == "domain"
    assert data["whois"]["registrar"] == "MarkMonitor Inc."

def test_domain_rejects_invalid():
    response = client.get("/api/v1/domain/notadomain")
    assert response.status_code == 422