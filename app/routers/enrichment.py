from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IOC, IOCEnrichment
from app.schemas import IOCEnrichmentOut
from app.feeds.abuseipdb import check_ip

router = APIRouter()

PROVIDER = "abuseipdb"


def _parse_iso_dt(s: str | None):
    """Parse an ISO8601 datetime string safely (handles trailing Z)."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


@router.post("/iocs/{ioc_id}/enrich", response_model=IOCEnrichmentOut)
def enrich_ioc(ioc_id: int, db: Session = Depends(get_db)):
    # 1) Confirm IOC exists
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # 2) Confirm type is supported
    if (ioc.type or "").lower() != "ip":
        raise HTTPException(
            status_code=400,
            detail=f"{PROVIDER} enrichment only supports IP-type IOCs"
        )

    # 3) Call AbuseIPDB
    try:
        data = check_ip(ioc.value)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"{PROVIDER} lookup failed: {str(e)}")

    # 4) Upsert one row per IOC + provider
    row = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id, IOCEnrichment.provider == PROVIDER)
        .first()
    )

    if row is None:
        row = IOCEnrichment(ioc_id=ioc_id, provider=PROVIDER)
        db.add(row)

    # 5) Map fields from provider response
    row.score = data.get("abuseConfidenceScore")
    row.total_reports = data.get("totalReports")
    row.country_code = data.get("countryCode")
    row.isp = data.get("isp")
    row.domain = data.get("domain")
    row.usage_type = data.get("usageType")
    row.last_reported_at = _parse_iso_dt(data.get("lastReportedAt"))
    row.raw_json = data

    db.commit()
    db.refresh(row)
    return row


@router.get("/iocs/{ioc_id}/enrichment", response_model=IOCEnrichmentOut)
def get_ioc_enrichment(ioc_id: int, db: Session = Depends(get_db)):
    # SOC-friendly: distinguish "bad IOC id" vs "not enriched yet"
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    row = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id, IOCEnrichment.provider == PROVIDER)
        .first()
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"IOC exists but has no {PROVIDER} enrichment yet. Run POST /api/iocs/{ioc_id}/enrich"
        )

    return row