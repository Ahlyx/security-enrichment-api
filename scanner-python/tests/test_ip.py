import pytest
import respx
import httpx
from httpx import Response
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_cache():
    from app.cache import clear_all_cache
    clear_all_cache()

@respx.mock
def test_ip_returns_200():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=Response(200, json={
        "data": {
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "lastReportedAt": None,
            "isp": "Google LLC",
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": False
        }
    }))
    respx.get("https://ipinfo.io/8.8.8.8/json").mock(return_value=Response(200, json={
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "loc": "37.4056,-122.0775"
    }))
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(return_value=Response(200, json={
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "harmless": 80,
                    "suspicious": 0
                },
                "last_analysis_date": 1700000000
            }
        }
    }))
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").mock(return_value=Response(200, json={
        "pulse_info": {"count": 0, "pulses": []},
        "country_name": "United States",
        "asn": "AS15169"
    }))

    response = client.get("/api/v1/ip/8.8.8.8")
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "8.8.8.8"
    assert data["query_type"] == "ip"
    assert data["abuse"]["abuse_score"] == 0
    assert data["geolocation"]["city"] == "Mountain View"

@respx.mock
def test_ip_rejects_private():
    response = client.get("/api/v1/ip/192.168.1.1")
    assert response.status_code == 400

def test_ip_rejects_invalid():
    response = client.get("/api/v1/ip/notanip")
    assert response.status_code == 422