from pydantic import BaseModel, Field
from datetime import datetime, date
from typing import Optional, Literal, Any, Dict

IOCType = Literal["ip", "domain", "hash"]

class IOCCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)
    type: IOCType
    source: str = Field(..., min_length=1, max_length=200)
    confidence: int = Field(50, ge=0, le=100)


class IOCOut(BaseModel):
    id: int
    value: str
    type: IOCType
    source: str
    confidence: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True

class CVEOut(BaseModel):
    id: int
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[date] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[date] = None
    known_ransomware_campaign_use: Optional[str] = None
    notes: Optional[str] = None
    source: str

    class Config:
        from_attributes = True

class IOCEnrichmentOut(BaseModel):
    id: int
    ioc_id: int
    provider: str
    score: Optional[int] = None
    total_reports: Optional[int] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    usage_type: Optional[str] = None
    last_reported_at: Optional[datetime] = None
    raw_json: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True