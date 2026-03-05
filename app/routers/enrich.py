from fastapi import APIRouter, Query
from app.feeds.abuseipdb import check_ip

router = APIRouter()


@router.get("/enrich/ip")
def enrich_ip(
    ip: str = Query(..., min_length=7, max_length=45, description="IPv4/IPv6 address to enrich"),
    max_age_days: int = Query(90, ge=1, le=365, description="How far back to consider reports"),
):
    data = check_ip(ip, max_age_days=max_age_days)

    # Return a clean, UI-friendly subset
    return {
        "ip": data.get("ipAddress"),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "is_public": data.get("isPublic"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
    }