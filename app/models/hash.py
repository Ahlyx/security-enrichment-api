from pydantic import BaseModel
from typing import Optional
from app.models.shared import BaseResponse

class HashVirusTotalData(BaseModel):
    malicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    last_analysis_date: Optional[int] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    meaningful_name: Optional[str] = None
    threat_label: Optional[str] = None

class MalwareBazaarData(BaseModel):
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    signature: Optional[str] = None
    tags: list[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

class HashResponse(BaseResponse):
    hash_value: str
    hash_type: Optional[str] = None
    virustotal: Optional[HashVirusTotalData] = None
    malwarebazaar: Optional[MalwareBazaarData] = None
    is_malicious: Optional[bool] = None