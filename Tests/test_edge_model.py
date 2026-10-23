"""Tests for the ONNX export pipeline used by the edge model."""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'Backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from onnx_exporter import export_to_onnx


class TestEdgeModel(unittest.TestCase):
    """Verify that the edge model can be exported to an ONNX file."""

    def test_onnx_export_file_creation(self):
        """Ensure the export creates a file and removes the temporary artifact."""
        file_path = "test_iot_model.onnx"
        try:
            export_to_onnx(file_path)
            self.assertTrue(os.path.exists(file_path))
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)

if __name__ == '__main__':
    unittest.main()
