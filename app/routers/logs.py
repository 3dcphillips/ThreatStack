from fastapi import APIRouter

router = APIRouter()

@router.get("/logs")
def list_logs():
    # placeholder until ingestion is wired in
    return {"count": 0, "items": []}