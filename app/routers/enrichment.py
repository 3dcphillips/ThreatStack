from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import IOC, IOCEnrichment
from app.schemas import IOCEnrichmentOut
from app.feeds.abuseipdb import check_ip

router = APIRouter()


def _parse_iso_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


@router.post("/iocs/{ioc_id}/enrich", response_model=IOCEnrichmentOut)
def enrich_ioc(ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    if ioc.type != "ip":
        raise HTTPException(status_code=400, detail="AbuseIPDB enrichment only supports IP-type IOCs")

    #call AbuseIPDB INSIDE the function
    try:
        data = check_ip(ioc.value)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AbuseIPDB lookup failed: {str(e)}")

    provider = "abuseipdb"

    # Upsert one row per IOC + provider
    row = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id, IOCEnrichment.provider == provider)
        .first()
    )

    if row is None:
        row = IOCEnrichment(ioc_id=ioc_id, provider=provider)
        db.add(row)

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
    row = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id, IOCEnrichment.provider == "abuseipdb")
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="No enrichment found for this IOC")
    return row