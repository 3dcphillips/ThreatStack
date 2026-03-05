from sqlalchemy import Column, Integer, String, Text, DateTime, Date, ForeignKey, func
from app.database import Base
from sqlalchemy.dialects.postgresql import JSONB


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(Text, nullable=False, index=True)          # IP / domain / hash
    type = Column(String(20), nullable=False, index=True)     # ip / domain / hash
    source = Column(Text, nullable=False)                     # abuseipdb / otx / manual
    confidence = Column(Integer, default=50)                  # 0-100
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class LogEvent(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source = Column(Text, nullable=True)
    message = Column(Text, nullable=False)
    parsed_ip = Column(Text, nullable=True, index=True)
    event_type = Column(Text, nullable=True, index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_name = Column(Text, nullable=False)
    severity = Column(String(10), nullable=False)             # low/medium/high
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Text, unique=True, nullable=False, index=True)
    vendor_project = Column(Text, nullable=True)
    product = Column(Text, nullable=True)
    vulnerability_name = Column(Text, nullable=True)
    date_added = Column(Date, nullable=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(Text, nullable=True)
    due_date = Column(Date, nullable=True)
    known_ransomware_campaign_use = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    source = Column(Text, nullable=False, default="cisa_kev")

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichment"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)

    provider = Column(Text, nullable=False)  # "abuseipdb"

    score = Column(Integer, nullable=True)
    total_reports = Column(Integer, nullable=True)

    country_code = Column(Text, nullable=True)
    isp = Column(Text, nullable=True)
    domain = Column(Text, nullable=True)
    usage_type = Column(Text, nullable=True)

    last_reported_at = Column(DateTime(timezone=True), nullable=True)

    raw_json = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())