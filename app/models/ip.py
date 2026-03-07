from pydantic import BaseModel
from typing import Optional
from app.models.shared import BaseResponse

class GeoLocation(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class AbuseData(BaseModel):
    abuse_score: Optional[int] = None
    total_reports: Optional[int] = None
    last_reported: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    is_tor: Optional[bool] = None

class VirusTotalData(BaseModel):
    malicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    last_analysis_date: Optional[str] = None
    associated_malware: list[str] = []

class IPResponse(BaseResponse):
    ip: str
    geolocation: Optional[GeoLocation] = None
    abuse: Optional[AbuseData] = None
    virustotal: Optional[VirusTotalData] = None
    is_bogon: Optional[bool] = None
    is_tor: Optional[bool] = None