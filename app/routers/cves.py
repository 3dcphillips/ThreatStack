from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List

from app.database import get_db
from app.models import CVE
from app.schemas import CVEOut

router = APIRouter()

@router.get("/cves/kev", response_model=List[CVEOut])
def list_kev(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return db.query(CVE).order_by(desc(CVE.date_added)).limit(limit).all()