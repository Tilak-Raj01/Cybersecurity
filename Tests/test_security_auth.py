import os
import unittest
from unittest.mock import patch

from Backend.security_auth import generate_auth_token, verify_token


class TestSecurityAuth(unittest.TestCase):
    def test_token_round_trip(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "test-secret-key-that-is-at-least-32-bytes"}):
            token = generate_auth_token("user-1", "analyst")
            self.assertEqual(verify_token(token)["sub"], "user-1")

    def test_invalid_token_returns_none(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "test-secret-key-that-is-at-least-32-bytes"}):
            self.assertIsNone(verify_token("invalid"))

    def test_missing_secret_raises_clear_error(self):
        with patch.dict(os.environ):
            os.environ.pop("JWT_SECRET_KEY", None)
            with self.assertRaisesRegex(RuntimeError, "JWT_SECRET_KEY must be set"):
                generate_auth_token("user-1", "analyst")

    def test_short_secret_is_rejected(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": "short"}):
            with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
                generate_auth_token("user-1", "analyst")


if __name__ == "__main__":
    unittest.main()
