import re
from sqlalchemy.orm import Session
from app.models import IOC, LogEvent, Alert

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def correlate_logs(db: Session) -> int:
    iocs = db.query(IOC).all()
    logs = db.query(LogEvent).all()

    ioc_map = {str(i.value).strip(): i for i in iocs if i.value}
    alerts_created = 0

    for log in logs:
        candidates = set()

        # Best signal: parsed_ip from your ingest pipeline
        if getattr(log, "parsed_ip", None):
            candidates.add(str(log.parsed_ip).strip())

        # Fallback: scan the message
        msg = getattr(log, "message", "") or ""
        candidates.update(IP_RE.findall(msg))

        for val in candidates:
            ioc = ioc_map.get(val)
            if not ioc:
                continue

            # prevent duplicates
            exists = (
                db.query(Alert)
                .filter(Alert.log_id == log.id, Alert.ioc_id == ioc.id)
                .first()
            )
            if exists:
                continue

            db.add(Alert(
                log_id=log.id,
                ioc_id=ioc.id,
                alert_type="IOC_MATCH",
                severity="high",
            ))
            alerts_created += 1

    db.commit()
    return alerts_created