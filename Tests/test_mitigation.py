"""Unit tests for firewall mitigation behavior."""

import unittest
from Backend.firewall_mitigation import ActiveMitigationEngine

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

if __name__ == '__main__':
    unittest.main()
