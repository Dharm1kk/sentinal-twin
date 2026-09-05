"""
SentinelTwin standardized alert schema.

Design rule from the project brief: confidence is an *evidence-strength*
score (how much signal supports this being a real threat), and severity is
a separate *operational urgency* score (how bad it would be if true). We
never conflate the two, and we never print a confidence number that looks
like a calibrated probability unless it actually came from a calibrated
model trained on labeled data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ThreatClass(str, Enum):
    VOLUMETRIC_DDOS = "volumetric_ddos"
    C2_BEACONING = "c2_beaconing"
    DNS_TUNNELING = "dns_tunneling"
    ENCRYPTED_MALWARE = "encrypted_malware"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    BENIGN = "benign"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Static severity ceiling per threat class. A single flow-level detection of
# a DDoS is more urgent than a single low-confidence port-scan hit, even at
# equal confidence. Confidence still modulates within this ceiling.
_SEVERITY_CEILING: dict[ThreatClass, Severity] = {
    ThreatClass.VOLUMETRIC_DDOS: Severity.CRITICAL,
    ThreatClass.C2_BEACONING: Severity.HIGH,
    ThreatClass.DNS_TUNNELING: Severity.HIGH,
    ThreatClass.ENCRYPTED_MALWARE: Severity.HIGH,
    ThreatClass.PORT_SCAN: Severity.MEDIUM,
    ThreatClass.DATA_EXFILTRATION: Severity.CRITICAL,
    ThreatClass.BENIGN: Severity.LOW,
}

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def derive_severity(threat_class: ThreatClass, confidence: float) -> Severity:
    """Severity = min(class ceiling, confidence-scaled level).

    This keeps severity honest: a barely-there detection of even a
    critical-class threat doesn't scream CRITICAL at the analyst.
    """
    ceiling = _SEVERITY_CEILING[threat_class]
    ceiling_idx = _SEVERITY_ORDER.index(ceiling)

    if confidence >= 0.85:
        scaled_idx = 3
    elif confidence >= 0.65:
        scaled_idx = 2
    elif confidence >= 0.4:
        scaled_idx = 1
    else:
        scaled_idx = 0

    return _SEVERITY_ORDER[min(ceiling_idx, scaled_idx)]


@dataclass
class Alert:
    flow_id: str
    threat_class: ThreatClass
    confidence: float  # evidence-strength score in [0, 1], NOT a calibrated probability
    supporting_evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    severity: Severity = field(init=False)
    src_ip: str | None = None
    dst_ip: str | None = None
    detector_source: str = "unspecified"  # "rule", "isolation_forest", "correlated"
    incident_id: str | None = None  # set by graph correlation if this alert is merged

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.severity = derive_severity(self.threat_class, self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "threat_class": self.threat_class.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "detector_source": self.detector_source,
            "incident_id": self.incident_id,
            "supporting_evidence": self.supporting_evidence,
        }
