import datetime
import os
from typing import Any

import jwt


def _get_secret_key() -> str:
    """Load the signing key from configuration and reject unsafe short keys."""
    secret_key = os.environ.get("JWT_SECRET_KEY")
    if secret_key is None or not secret_key.strip():
        raise RuntimeError("JWT_SECRET_KEY must be set in the environment")
    if len(secret_key.encode("utf-8")) < 32:
        raise ValueError("JWT_SECRET_KEY must be at least 32 bytes")
    return secret_key

def generate_auth_token(user_id: str, role: str) -> str:
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, _get_secret_key(), algorithm='HS256')

def verify_token(token: str) -> dict[str, Any] | None:
    try:
        decoded = jwt.decode(token, _get_secret_key(), algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
