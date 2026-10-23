"""Tests for the ML anomaly detection engine.

These tests skip cleanly when the `ml_anomaly_engine` package is not
installed in the current environment to avoid import-time failures.
"""

import os
import sys
import unittest
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'Backend')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    from ml_anomaly_engine import AnomalyDetector
    _ML_ENGINE_MISSING = None
except ImportError as _err:
    AnomalyDetector = None
    _ML_ENGINE_MISSING = str(_err)


class TestMLEngine(unittest.TestCase):
    """Unit tests for `AnomalyDetector` training and inference."""

    @unittest.skipIf(_ML_ENGINE_MISSING, f"ml_anomaly_engine missing: {_ML_ENGINE_MISSING}")
    def test_model_training_and_inference(self):
        """Train a baseline and run a prediction, validating output keys."""
        data = np.random.rand(50, 6)
        detector = AnomalyDetector()
        detector.train_baseline(data)

        res = detector.predict(data[0:1])
        self.assertIn('is_anomaly', res)
        self.assertIn('anomaly_score', res)

    @unittest.skipIf(_ML_ENGINE_MISSING, f"ml_anomaly_engine missing: {_ML_ENGINE_MISSING}")
    def test_training_from_dataframe(self):
        """A prepared dataset frame should be usable for model training."""
        detector = AnomalyDetector()
        dataset = np.array([
            [1, 64, 80, 5000, 0.2, 2.0],
            [1, 128, 443, 7000, 0.3, 2.5],
            [2, 96, 53, 2000, 0.1, 1.5],
            [1, 74, 22, 1200, 0.2, 1.8],
            [2, 80, 161, 1800, 0.1, 1.7],
        ], dtype=np.float32)

        detector.train_from_dataframe(dataset)
        res = detector.predict(dataset[0:1])
        self.assertIn('is_anomaly', res)
        self.assertIn('anomaly_score', res)


if __name__ == '__main__':
    unittest.main()
