from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class SourceMetadata(BaseModel):
    source: str
    retrieved_at: datetime
    success: bool
    error: Optional[str] = None

class BaseResponse(BaseModel):
    query: str
    query_type: str
    timestamp: datetime
    sources: list[SourceMetadata] = []