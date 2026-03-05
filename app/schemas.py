# app/schemas.py

from datetime import datetime
from typing import Any, Dict, Optional, Literal

from pydantic import BaseModel, ConfigDict, computed_field


# -----------------------------
# IOC Schemas (needed by iocs.py)
# -----------------------------

class IOCCreate(BaseModel):
    value: str
    type: str
    source: Optional[str] = "manual"


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    type: str
    source: Optional[str] = None
    confidence: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None

class CVEOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


# -------------------------------------
# Enrichment Schemas (SOC/Analyst polish)
# -------------------------------------

Verdict = Literal["benign", "suspicious", "malicious"]
Severity = Literal["low", "medium", "high"]


class IOCEnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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

    # ---------- SOC-friendly computed fields ----------

    @computed_field
    @property
    def is_whitelisted(self) -> bool:
        if not self.raw_json:
            return False
        return bool(self.raw_json.get("isWhitelisted", False))

    @computed_field
    @property
    def verdict(self) -> Verdict:
        score = int(self.score or 0)

        if self.is_whitelisted and score <= 10:
            return "benign"
        if score >= 75:
            return "malicious"
        if score >= 25:
            return "suspicious"
        return "benign"

    @computed_field
    @property
    def severity(self) -> Severity:
        v = self.verdict
        if v == "malicious":
            return "high"
        if v == "suspicious":
            return "medium"
        return "low"

    @computed_field
    @property
    def summary(self) -> str:
        score = int(self.score or 0)
        reports = int(self.total_reports or 0)

        subject = "IOC"
        if self.raw_json:
            subject = self.raw_json.get("ipAddress") or self.raw_json.get("domain") or subject

        if self.is_whitelisted:
            return (
                f"{subject} is marked whitelisted by provider; "
                f"score {score}, reports {reports}. Treat as benign unless incident context indicates otherwise."
            )

        if self.verdict == "malicious":
            return f"{subject} appears malicious (score {score}, reports {reports}). Investigate activity and block if confirmed."
        if self.verdict == "suspicious":
            return f"{subject} appears suspicious (score {score}, reports {reports}). Correlate with logs before action."
        return f"{subject} appears benign (score {score}, reports {reports}). Monitor if seen in suspicious context."