from fastapi import FastAPI
from app.routers import iocs, logs, alerts, cves

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

@app.get("/")
def root():
    return {"status": "ThreatStack API running"}