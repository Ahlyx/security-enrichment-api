from pydantic import BaseModel
from typing import Optional
from app.models.shared import BaseResponse

class SafeBrowsingData(BaseModel):
    is_safe: Optional[bool] = None
    threats: list[str] = []

class URLScanData(BaseModel):
    verdict: Optional[str] = None
    score: Optional[int] = None
    malicious: Optional[bool] = None
    categories: list[str] = []
    screenshot_url: Optional[str] = None

class URLVirusTotalData(BaseModel):
    malicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    last_analysis_date: Optional[int] = None

class URLResponse(BaseResponse):
    url: str
    safe_browsing: Optional[SafeBrowsingData] = None
    urlscan: Optional[URLScanData] = None
    virustotal: Optional[URLVirusTotalData] = None
    is_malicious: Optional[bool] = None