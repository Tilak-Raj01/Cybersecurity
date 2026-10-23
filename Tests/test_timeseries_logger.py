import unittest

from Backend.timeseries_logger import IncidentLogger


class TestLogger(unittest.TestCase):
    def setUp(self):
        self.logger = IncidentLogger()
        self.addCleanup(self.logger.conn.close)

    def test_log_insertion_and_retrieval(self):
        self.logger.log_event("SIG-01", "High", "192.168.1.5", "Test event")
        logs = self.logger.fetch_recent(1)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0][2], "SIG-01")

    def test_fetch_recent_zero_limit_returns_no_events(self):
        self.logger.log_event("SIG-01", "High", "192.168.1.5", "Test event")
        self.assertEqual(self.logger.fetch_recent(0), [])

    def test_fetch_recent_rejects_negative_limit(self):
        with self.assertRaises(ValueError):
            self.logger.fetch_recent(-1)

    def test_fetch_recent_rejects_non_integer_limit(self):
        for limit in (1.5, "1", True):
            with self.subTest(limit=limit):
                with self.assertRaises(TypeError):
                    self.logger.fetch_recent(limit)


if __name__ == "__main__":
    unittest.main()
