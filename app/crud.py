from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models import IOC
from app.schemas import IOCCreate


def create_ioc(db: Session, ioc: IOCCreate) -> IOC:
    obj = IOC(
        value=ioc.value.strip(),
        type=ioc.type,
        source=ioc.source.strip(),
        confidence=ioc.confidence,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


def list_iocs(db: Session, limit: int = 100, offset: int = 0):
    stmt = select(IOC).order_by(IOC.id.desc()).limit(limit).offset(offset)
    return db.execute(stmt).scalars().all()


def search_iocs(db: Session, q: str, limit: int = 50):
    q = q.strip()
    stmt = (
        select(IOC)
        .where(IOC.value.ilike(f"%{q}%"))
        .order_by(IOC.last_seen.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()
