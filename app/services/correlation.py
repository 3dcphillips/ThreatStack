import re
from sqlalchemy.orm import Session
from app.models import IOC, LogEvent, Alert

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def correlate_log_ids(db: Session, log_ids: list[int]) -> int:
    if not log_ids:
        return 0

    iocs = db.query(IOC).all()
    ioc_map = {str(i.value).strip(): i for i in iocs if i.value}

    logs = db.query(LogEvent).filter(LogEvent.id.in_(log_ids)).all()

    alerts_created = 0
    for log in logs:
        candidates = set()

        if log.parsed_ip:
            candidates.add(str(log.parsed_ip).strip())

        if log.message:
            candidates.update(IP_RE.findall(log.message))

        for val in candidates:
            ioc = ioc_map.get(val)
            if not ioc:
                continue

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

def correlate_logs(db: Session) -> int:
    """
    Backwards-compatible correlation:
    correlate across ALL logs by reusing correlate_log_ids.
    """
    log_ids = [row[0] for row in db.query(LogEvent.id).all()]
    return correlate_log_ids(db, log_ids)