from datetime import datetime
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import CVE
from app.feeds.cisa_kev import fetch_kev

def parse_date(s):
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%d").date()

def upsert(db: Session, item: dict):
    cve_id = item.get("cveID")
    if not cve_id:
        return False

    row = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if row:
        row.vendor_project = item.get("vendorProject")
        row.product = item.get("product")
        row.vulnerability_name = item.get("vulnerabilityName")
        row.date_added = parse_date(item.get("dateAdded"))
        row.short_description = item.get("shortDescription")
        row.required_action = item.get("requiredAction")
        row.due_date = parse_date(item.get("dueDate"))
        row.known_ransomware_campaign_use = item.get("knownRansomwareCampaignUse")
        row.notes = item.get("notes")
        return True

    db.add(CVE(
        cve_id=cve_id,
        vendor_project=item.get("vendorProject"),
        product=item.get("product"),
        vulnerability_name=item.get("vulnerabilityName"),
        date_added=parse_date(item.get("dateAdded")),
        short_description=item.get("shortDescription"),
        required_action=item.get("requiredAction"),
        due_date=parse_date(item.get("dueDate")),
        known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse"),
        notes=item.get("notes"),
        source="cisa_kev",
    ))
    return True

def main():
    db = SessionLocal()
    try:
        kev = fetch_kev()
        count = 0
        for item in kev:
            if upsert(db, item):
                count += 1
        db.commit()
        print(f"KEV ingested/updated: {count}")
    finally:
        db.close()

if __name__ == "__main__":
    main()