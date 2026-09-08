"""
Sentinel Cryptographic SHA-256 Alert Ledger (Tamper-Evident Hash Chain)
Strictly implements SIH 2026 Slide 2 & 3 innovation:
- "Alerts are converted to hash using SHA-256 to preserve alert integrity and to verify whether it is being faked or not"
- "Blockchain Integration: Blockchain provides tamper-evident integrity for security alerts and score history"
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional


class AlertBlock:
    def __init__(
        self,
        index: int,
        alert_id: str,
        timestamp: str,
        host: str,
        threat_type: str,
        risk_score: int,
        prev_hash: str,
        details_summary: Optional[str] = None
    ):
        self.index = index
        self.alert_id = alert_id
        self.timestamp = timestamp
        self.host = host
        self.threat_type = threat_type
        self.risk_score = risk_score
        self.prev_hash = prev_hash
        self.details_summary = details_summary or ""
        self.alert_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "host": self.host,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "prev_hash": self.prev_hash,
            "details_summary": self.details_summary
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "host": self.host,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "prev_hash": self.prev_hash,
            "alert_hash": self.alert_hash,
            "details_summary": self.details_summary
        }


class BlockchainAlertLedger:
    GENESIS_PREV_HASH = "0" * 64

    def __init__(self):
        self.chain: List[AlertBlock] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = AlertBlock(
            index=0,
            alert_id="GENESIS-00000",
            timestamp="2026-01-01T00:00:00Z",
            host="0.0.0.0",
            threat_type="GENESIS_ROOT",
            risk_score=0,
            prev_hash=self.GENESIS_PREV_HASH,
            details_summary="Sentinel Immutable Trust Anchor"
        )
        self.chain.append(genesis)

    def clear(self):
        self.chain = []
        self._create_genesis_block()

    @property
    def latest_block(self) -> AlertBlock:
        return self.chain[-1]

    def record_alert(
        self,
        alert_id: str,
        timestamp: str,
        host: str,
        threat_type: str,
        risk_score: int,
        details_summary: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Appends a new alert block to the cryptographic chain.
        Returns the SHA-256 hash and previous block hash.
        """
        prev_hash = self.latest_block.alert_hash
        new_index = len(self.chain)
        block = AlertBlock(
            index=new_index,
            alert_id=alert_id,
            timestamp=timestamp,
            host=host,
            threat_type=threat_type,
            risk_score=risk_score,
            prev_hash=prev_hash,
            details_summary=details_summary
        )
        self.chain.append(block)
        return {
            "index": block.index,
            "alert_id": block.alert_id,
            "alert_hash": block.alert_hash,
            "prev_hash": block.prev_hash,
            "verified": True
        }

    def verify_chain(self) -> Dict[str, Any]:
        """
        Cryptographically validates every link in the ledger from Genesis to Tip.
        Ensures no historical alert has been altered, injected, or removed.
        """
        if not self.chain:
            return {"valid": False, "error": "Empty chain", "total_blocks": 0}

        if self.chain[0].prev_hash != self.GENESIS_PREV_HASH:
            return {"valid": False, "broken_at_index": 0, "reason": "Invalid genesis block"}

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Verify previous hash pointer
            if current.prev_hash != prev.alert_hash:
                return {
                    "valid": False,
                    "broken_at_index": i,
                    "alert_id": current.alert_id,
                    "reason": f"Hash pointer mismatch: block {i} points to {current.prev_hash[:12]}..., but block {i-1} hash is {prev.alert_hash[:12]}..."
                }

            # 2. Recompute current hash to detect data tampering
            recomputed = current.compute_hash()
            if current.alert_hash != recomputed:
                return {
                    "valid": False,
                    "broken_at_index": i,
                    "alert_id": current.alert_id,
                    "reason": f"Data integrity violation: block {i} payload modified. Recorded: {current.alert_hash[:12]}..., recomputed: {recomputed[:12]}..."
                }

        return {
            "valid": True,
            "total_blocks": len(self.chain),
            "alerts_protected": len(self.chain) - 1,
            "ledger_head": self.latest_block.alert_hash,
            "verified_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        }

    def verify_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Locates a specific alert in the ledger, verifies its cryptographic hash,
        and returns its proof of inclusion and integrity.
        """
        for block in self.chain:
            if block.alert_id == alert_id:
                recomputed = block.compute_hash()
                is_valid = (block.alert_hash == recomputed)
                return {
                    "alert_id": alert_id,
                    "block_index": block.index,
                    "alert_hash": block.alert_hash,
                    "prev_hash": block.prev_hash,
                    "timestamp": block.timestamp,
                    "is_tamper_free": is_valid,
                    "chain_length": len(self.chain),
                    "status": "CRYPTOGRAPHICALLY_VERIFIED" if is_valid else "TAMPER_DETECTED"
                }

        return {
            "alert_id": alert_id,
            "is_tamper_free": False,
            "status": "ALERT_NOT_FOUND_IN_LEDGER"
        }

    def get_ledger(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.chain]
