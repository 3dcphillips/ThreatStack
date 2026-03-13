from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
import app.models

from app.database import get_db
from app.services.correlation import correlate_logs
from app.routers import iocs, logs, alerts, cves, enrich
from app.routers.alerts import router as alerts_router

app = FastAPI(
    title="ThreatStack",
    version="0.1.0",
    description="Threat Intel Aggregator + Mini-SIEM (portfolio build)"
)

# Routers
app.include_router(iocs.router, prefix="/api", tags=["iocs"])
app.include_router(logs.router, prefix="/api", tags=["logs"])
app.include_router(alerts.router, prefix="/api", tags=["alerts"])
app.include_router(cves.router, prefix="/api", tags=["cves"])
app.include_router(enrich.router, prefix="/api", tags=["enrichment"])

@app.get("/")
def root():
    return {"status": "ThreatStack API running"}

@app.post("/api/correlate", tags=["correlation"])
def run_correlation(db: Session = Depends(get_db)):
    alerts = correlate_logs(db)
    return {"alerts_created": alerts}