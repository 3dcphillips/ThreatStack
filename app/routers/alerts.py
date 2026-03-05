from fastapi import APIRouter

router = APIRouter()

@router.get("/alerts")
def list_alerts():
    # placeholder until correlation engine is wired in
    return {"count": 0, "items": []}