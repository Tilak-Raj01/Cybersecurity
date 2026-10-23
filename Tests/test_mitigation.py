"""Unit tests for firewall mitigation behavior."""

import unittest
from Backend.firewall_mitigation import ActiveMitigationEngine
from Backend.signature_engine import SignatureDetectionEngine

class TestMitigation(unittest.TestCase):
    """Tests for IP blocking and mitigation state tracking."""

    def test_dry_run_blocking(self):
        """Verify dry-run blocking records the IP without a firewall change."""
        engine = ActiveMitigationEngine(dry_run=True)
        res = engine.block_ip("10.0.0.99")
        self.assertTrue(res)
        self.assertIn("10.0.0.99", engine.blocked_ips)

    def test_extract_and_block_all_ips_from_signature_matches(self):
        """Signature matches should yield all relevant IPs and automatically block them."""
        engine = ActiveMitigationEngine(dry_run=True)
        matches = [
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"},
            {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.77"},
            {"src_ip": "198.51.100.24"},
        ]

        ips = engine.extract_ips(matches)
        self.assertEqual(ips, ["10.0.0.5", "10.0.0.1", "203.0.113.77", "198.51.100.24"])

        blocked = engine.block_signature_ips(matches)
        self.assertEqual(blocked, ips)
        self.assertTrue(all(ip in engine.blocked_ips for ip in ips))

    def test_auto_block_at_least_ten_signature_matched_sources(self):
        """Batch inspection should automatically block ten matching source IPs."""
        mitigator = ActiveMitigationEngine(dry_run=True)
        signatures = SignatureDetectionEngine()
        packets = [
            {
                "protocol": "tcp",
                "src_port": 23,
                "src_ip": f"192.0.2.{index}",
                "dst_ip": "198.51.100.20",
            }
            for index in range(1, 11)
        ]

        blocked = mitigator.auto_block_packets(packets, signatures)

        self.assertEqual(len(blocked), 10)
        self.assertEqual(mitigator.blocked_ips, {packet["src_ip"] for packet in packets})
        self.assertNotIn("198.51.100.20", mitigator.blocked_ips)

if __name__ == '__main__':
    unittest.main()
