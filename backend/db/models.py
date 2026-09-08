"""
SQLAlchemy ORM Models for Sentinel
Persists Hosts, Flows, Alerts, Campaigns, and Real-Time Telemetry.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, Text, Index
from .database import Base


class HostRecord(Base):
    __tablename__ = "hosts"

    ip = Column(String(64), primary_key=True, index=True)
    role = Column(String(128), default="Internal Host")
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    risk_score = Column(Integer, default=0)
    baseline_profile_json = Column(Text, default="{}")


class FlowRecord(Base):
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    flow_id = Column(String(128), index=True)
    timestamp = Column(Float, nullable=False, index=True)
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False, index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String(16), default="TCP")
    packets = Column(Integer, default=1)
    bytes = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    tcp_flags = Column(String(32), nullable=True)
    dns_query = Column(String(256), nullable=True)
    tls_sni = Column(String(256), nullable=True)
    tls_ja3 = Column(String(64), nullable=True)



class AlertRecord(Base):
    __tablename__ = "alerts"

    alert_id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(String(64), nullable=False, index=True)
    host_ip = Column(String(64), nullable=False, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False)
    confidence = Column(Float, default=0.0)
    novelty = Column(Float, default=0.0)
    risk = Column(Integer, default=0)
    hypotheses_json = Column(Text, default="[]")
    evidence_json = Column(Text, default="[]")
    related_entities_json = Column(Text, default="[]")
    acknowledged = Column(Boolean, default=False)
    explanation = Column(Text, nullable=True)
    explanation_details_json = Column(Text, nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=True)



class CampaignRecord(Base):
    __tablename__ = "campaigns"

    campaign_id = Column(String(64), primary_key=True, index=True)
    host_ip = Column(String(64), nullable=False, index=True)
    stages_json = Column(Text, default="[]")
    severity = Column(String(32), default="HIGH")
    risk = Column(Integer, default=75)
    correlated_alerts_json = Column(Text, default="[]")
    narrative = Column(Text, nullable=True)


class TelemetrySample(Base):
    __tablename__ = "telemetry_samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    packets_per_sec = Column(Float, default=0.0)
    bytes_per_sec = Column(Float, default=0.0)
    flows_count = Column(Integer, default=0)
    active_hosts_count = Column(Integer, default=0)
    ewma_baseline = Column(Float, default=0.0)
    cusum_score = Column(Float, default=0.0)
