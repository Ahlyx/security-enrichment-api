import pytest
import base64
import respx
from httpx import Response
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_cache():
    from app.cache import clear_all_cache
    clear_all_cache()

@respx.mock
def test_url_returns_200():
    url = "https://google.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
        return_value=Response(200, json={})
    )
    respx.post("https://urlscan.io/api/v1/scan/").mock(
        return_value=Response(200, json={"uuid": "test-uuid-1234"})
    )
    respx.get("https://urlscan.io/api/v1/result/test-uuid-1234/").mock(
        return_value=Response(200, json={
            "verdicts": {
                "overall": {"malicious": False, "score": 0},
                "urlscan": {"categories": []}
            },
            "task": {"screenshotURL": None}
        })
    )
    respx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}").mock(
        return_value=Response(200, json={
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
        })
    )

    with patch("asyncio.sleep", return_value=None):
        response = client.get("/api/v1/url", params={"url": url})

    assert response.status_code == 200
    data = response.json()
    assert data["url"] == url
    assert data["query_type"] == "url"
    assert data["is_malicious"] == False

def test_url_rejects_invalid():
    response = client.get("/api/v1/url", params={"url": "notaurl"})
    assert response.status_code == 422