import unittest
from backend.security.blockchain_ledger import BlockchainAlertLedger


class TestBlockchainAlertLedger(unittest.TestCase):
    def setUp(self):
        self.ledger = BlockchainAlertLedger()

    def test_genesis_block(self):
        self.assertEqual(len(self.ledger.chain), 1)
        res = self.ledger.verify_chain()
        self.assertTrue(res["valid"])

    def test_record_and_verify(self):
        b1 = self.ledger.record_alert(
            alert_id="SNT-00001",
            timestamp="2026-09-08T12:00:00Z",
            host="10.0.1.15",
            threat_type="DDOS",
            risk_score=78
        )
        self.assertEqual(b1["index"], 1)
        self.assertTrue(len(b1["alert_hash"]) == 64)

        b2 = self.ledger.record_alert(
            alert_id="SNT-00002",
            timestamp="2026-09-08T12:01:00Z",
            host="10.0.2.99",
            threat_type="C2",
            risk_score=85
        )
        self.assertEqual(b2["prev_hash"], b1["alert_hash"])

        res = self.ledger.verify_chain()
        self.assertTrue(res["valid"])
        self.assertEqual(res["total_blocks"], 3)

        v1 = self.ledger.verify_alert("SNT-00001")
        self.assertTrue(v1["is_tamper_free"])
        self.assertEqual(v1["status"], "CRYPTOGRAPHICALLY_VERIFIED")

    def test_tamper_detection(self):
        self.ledger.record_alert("SNT-00001", "2026-09-08T12:00:00Z", "10.0.1.15", "DDOS", 78)
        self.ledger.record_alert("SNT-00002", "2026-09-08T12:01:00Z", "10.0.2.99", "C2", 85)

        # Tamper with block 1
        self.ledger.chain[1].risk_score = 10  # altered risk

        res = self.ledger.verify_chain()
        self.assertFalse(res["valid"])
        self.assertEqual(res["broken_at_index"], 1)

        v1 = self.ledger.verify_alert("SNT-00001")
        self.assertFalse(v1["is_tamper_free"])
        self.assertEqual(v1["status"], "TAMPER_DETECTED")


if __name__ == "__main__":
    unittest.main()
