from pydantic import BaseModel
from typing import Optional
from app.models.shared import BaseResponse

class WhoisData(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_updated: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_newly_registered: Optional[bool] = None

class DNSData(BaseModel):
    a_records: list[str] = []
    mx_records: list[str] = []
    ns_records: list[str] = []
    txt_records: list[str] = []

class DomainVirusTotalData(BaseModel):
    malicious_votes: Optional[int] = None
    harmless_votes: Optional[int] = None
    suspicious_votes: Optional[int] = None
    last_analysis_date: Optional[int] = None
    categories: list[str] = []

class DomainResponse(BaseResponse):
    domain: str
    whois: Optional[WhoisData] = None
    dns: Optional[DNSData] = None
    virustotal: Optional[DomainVirusTotalData] = None
    is_newly_registered: Optional[bool] = None