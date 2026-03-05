from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import IOCCreate, IOCOut
from app import crud

router = APIRouter()


@router.post("/iocs", response_model=IOCOut)
def add_ioc(payload: IOCCreate, db: Session = Depends(get_db)):
    return crud.create_ioc(db, payload)


@router.get("/iocs", response_model=List[IOCOut])
def get_iocs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return crud.list_iocs(db, limit=limit, offset=offset)


@router.get("/iocs/search", response_model=List[IOCOut])
def find_iocs(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    return crud.search_iocs(db, q=q, limit=limit)