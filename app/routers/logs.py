# app/routers/logs.py
from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models import LogEvent
from app.schemas import LogIngest, LogOut
from app.siem.log_parser import parse_line

router = APIRouter()


@router.post("/logs/ingest", response_model=dict)
def ingest_logs(payload: LogIngest, db: Session = Depends(get_db)):
    """
    Fastest MVP:
    - Accepts { source: "apache", lines: ["...", "..."] }
    - Parses each line
    - Inserts into logs table
    - Returns counts + parse errors
    """
    if not payload.lines:
        raise HTTPException(status_code=400, detail="No lines provided")

    inserted = 0
    errors = []

    for idx, line in enumerate(payload.lines):
        if not line or not line.strip():
            continue

        parsed, err = parse_line(payload.source, line)

        if parsed is None:
            errors.append({"line_index": idx, "reason": err or "parse_failed"})
            continue

        evt = LogEvent(
            source=payload.source,
            message=parsed["message"],
            parsed_ip=parsed.get("parsed_ip"),
            event_type=parsed.get("event_type"),
        )

        # If parser returned a timestamp, use it; else DB default applies.
        if parsed.get("timestamp") is not None:
            evt.timestamp = parsed["timestamp"]

        db.add(evt)
        inserted += 1

    db.commit()

    return {
        "source": payload.source,
        "received": len(payload.lines),
        "inserted": inserted,
        "errors": errors,
    }


@router.get("/logs", response_model=dict)
def list_logs(
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    parsed_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
):
    """
    List logs with lightweight filters.
    """
    stmt = select(LogEvent).order_by(LogEvent.id.desc()).limit(limit).offset(offset)

    if parsed_ip:
        stmt = stmt.where(LogEvent.parsed_ip == parsed_ip.strip())
    if event_type:
        stmt = stmt.where(LogEvent.event_type == event_type.strip())
    if source:
        stmt = stmt.where(LogEvent.source == source.strip())

    items: List[LogEvent] = db.execute(stmt).scalars().all()

    # Return a SOC-friendly wrapper
    return {
        "count": len(items),
        "items": [LogOut.model_validate(x).model_dump() for x in items],
        "limit": limit,
        "offset": offset,
    }