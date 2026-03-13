from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertOut, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=list[AlertOut])
def list_alerts(
    status: str | None = Query(default=None),
    assigned_to: str | None = Query(default=None),
    db: Session = Depends(get_db)):
    
    query = db.query(Alert)

    if status:
        query = query.filter(Alert.status == status)

    if assigned_to:
        query = query.filter(Alert.assigned_to == assigned_to)

    return query.order_by(Alert.created_at.desc()).all()


@router.get("/open", response_model=list[AlertOut])
def open_alerts_queue(db: Session = Depends(get_db)):
    return (
        db.query(Alert)
        .filter(Alert.status.in_(["open", "in_progress"]))
        .order_by(Alert.created_at.desc())
        .all()
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert_triage(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    updates = payload.model_dump(exclude_unset=True)

    for field, value in updates.items():
        setattr(alert, field, value)

    db.commit()
    db.refresh(alert)
    return alert