import pytest
import respx
from httpx import Response
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

WANNACRY_MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"

@pytest.fixture(autouse=True)
def clear_cache():
    from app.cache import clear_all_cache
    clear_all_cache()

@respx.mock
def test_hash_returns_200():
    respx.get(f"https://www.virustotal.com/api/v3/files/{WANNACRY_MD5}").mock(return_value=Response(200, json={
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 70,
                    "harmless": 0,
                    "suspicious": 0
                },
                "last_analysis_date": 1700000000,
                "type_description": "Win32 EXE",
                "size": 3723264,
                "meaningful_name": "WannaCry",
                "popular_threat_classification": {
                    "suggested_threat_label": "ransom.wannacry/wcry"
                }
            }
        }
    }))
    respx.post("https://mb-api.abuse.ch/api/v1/").mock(return_value=Response(200, json={
        "query_status": "ok",
        "data": [{
            "file_name": "wannacry.exe",
            "file_type": "exe",
            "file_size": 3723264,
            "signature": "WannaCry",
            "tags": ["ransomware", "wannacry"],
            "first_seen": "2017-05-12 00:00:00",
            "last_seen": "2023-01-01 00:00:00"
        }]
    }))
    respx.get(f"https://hashlookup.circl.lu/lookup/md5/{WANNACRY_MD5}").mock(return_value=Response(200, json={
        "FileName": "wannacry.exe",
        "FileSize": "3723264",
        "hashlookup:trust": 30
    }))

    response = client.get(f"/api/v1/hash/{WANNACRY_MD5}")
    assert response.status_code == 200
    data = response.json()
    assert data["hash_type"] == "md5"
    assert data["is_malicious"] == True
    assert data["is_known_good"] == False
    assert data["virustotal"]["malicious_votes"] == 70
    assert data["malwarebazaar"]["signature"] == "WannaCry"
    assert data["circl"]["trust_level"] == 30

def test_hash_rejects_invalid():
    response = client.get("/api/v1/hash/notahash")
    assert response.status_code == 422