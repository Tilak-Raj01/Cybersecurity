"""Tests for the hybrid detection pipeline.

These tests skip when the `hybrid_pipeline` package isn't available
to keep developer setups and CI robust against missing optional
components.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'Backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    from hybrid_pipeline import HybridNIDSPipeline
    _HYBRID_MISSING = None
except ImportError as _err:
    HybridNIDSPipeline = None
    _HYBRID_MISSING = str(_err)


class TestHybridPipeline(unittest.TestCase):
    """Unit tests for the `HybridNIDSPipeline` class."""

    @unittest.skipIf(_HYBRID_MISSING, f"hybrid_pipeline missing: {_HYBRID_MISSING}")
    def test_pipeline_execution(self):
        """Ensure the hybrid pipeline processes a telnet packet as signature."""
        pipeline = HybridNIDSPipeline()
        pkt = {'protocol': 'tcp', 'src_port': 23, 'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2'}
        res = pipeline.process_packet(pkt)
        self.assertIsNotNone(res)
        self.assertEqual(res['detection_type'], 'Signature')


if __name__ == '__main__':
    unittest.main()
