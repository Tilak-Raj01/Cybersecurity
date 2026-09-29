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

if __name__ == '__main__':
    unittest.main()
