from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert

router = APIRouter()

@router.get("/alerts")
def list_alerts(limit: int = 100, offset: int = 0, db: Session = Depends(get_db)):
    q = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    items = q.all()

    return {
        "count": len(items),
        "items": [
            {
                "id": a.id,
                "alert_type": getattr(a, "alert_type", None),
                "severity": a.severity,
                "log_id": a.log_id,
                "ioc_id": a.ioc_id,
                "created_at": a.created_at,
            }
            for a in items
        ],
    }

@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    a = db.query(Alert).filter(Alert.id == alert_id).first()
    if not a:
        return {"error": "not found"}

    return {
        "id": a.id,
        "alert_type": getattr(a, "alert_type", None),
        "severity": a.severity,
        "log_id": a.log_id,
        "ioc_id": a.ioc_id,
        "created_at": a.created_at,
    }