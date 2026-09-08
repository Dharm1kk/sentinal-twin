"""
Standardized Data Models and Alert JSON Schema
Strictly compliant with Sentinel Specification.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class Hypothesis(BaseModel):
    type: str = Field(..., description="Threat type (e.g., DNS_TUNNEL, DGA, C2, DDOS)")
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence score for this hypothesis")


class EvidenceItem(BaseModel):
    feature: str = Field(..., description="Feature identifier (e.g. dns_entropy, query_rate_deviation)")
    value: float = Field(..., description="Observed feature value or deviation magnitude")
    impact: float = Field(..., description="Signed or positive impact weight in the fused decision")


class Alert(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier (e.g., ARG-00017)")
    timestamp: str = Field(..., description="ISO 8601 timestamp string")
    host: str = Field(..., description="Target or victim host IP address")
    type: str = Field(..., description="Primary detected threat family or NOVEL_BEHAVIOUR")
    severity: str = Field(..., description="Severity tier: LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Temporal calibrated confidence")
    novelty: float = Field(..., ge=0.0, le=1.0, description="Isolation Forest novelty score")
    risk: int = Field(..., ge=0, le=100, description="Composite risk score 0-100")
    hypotheses: List[Hypothesis] = Field(default_factory=list, description="Top competing threat hypotheses")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Feature evidence and impact values")
    related_entities: List[str] = Field(default_factory=list, description="Associated hosts, domains, IPs, ports")
    acknowledged: bool = Field(default=False, description="Whether analyst acknowledged this alert")
    explanation: Optional[str] = Field(None, description="Grounded natural language incident narrative")
    explanation_details: Optional[Dict[str, Any]] = Field(default=None, description="Structured root-cause diagnosis, baseline deviations, differential reasoning, and containment recommendations")
    sha256_hash: Optional[str] = Field(None, description="Cryptographic SHA-256 integrity hash")
    prev_hash: Optional[str] = Field(None, description="Previous block hash in the tamper-evident ledger")



class NormalizedFlow(BaseModel):
    flow_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP
    packets: int
    bytes: int
    duration: float
    tcp_flags: Optional[str] = None
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_version: Optional[int] = None


class GraphNode(BaseModel):
    id: str
    label: str
    category: str  # host, ip, domain, port, service
    risk: int = 0
    details: Dict[str, Any] = Field(default_factory=dict)


class GraphLink(BaseModel):
    source: str
    target: str
    label: str
    timestamp: float
    weight: float = 1.0
    threat_type: Optional[str] = None


class EvidenceGraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    links: List[GraphLink] = Field(default_factory=list)


class ThroughputMetrics(BaseModel):
    timestamp: float
    packets_per_sec: float
    flows_per_sec: float
    mbps: float
    latency_ms: float
    total_packets: int
    total_flows: int
    active_hosts: int
