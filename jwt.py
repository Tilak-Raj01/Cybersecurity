import base64
import datetime
import hashlib
import hmac
import json
import time


class JWTError(Exception):
    pass


class ExpiredSignatureError(JWTError):
    pass


class InvalidTokenError(JWTError):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _json_default(value):
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.timestamp()
    raise TypeError(f"Object of type {value.__class__.__name__} is not JSON serializable")


def encode(payload, key: str, algorithm: str | None = None) -> str:
    if algorithm not in (None, "HS256"):
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url_encode(
        json.dumps(payload, default=_json_default, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"


def decode(token: str, key: str, algorithms: list[str] | None = None):
    if not isinstance(token, str) or token.count(".") != 2:
        raise InvalidTokenError("Invalid token")

    encoded_header, encoded_payload, signature = token.split(".")
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    expected = _b64url_encode(hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise InvalidTokenError("Invalid signature")

    try:
        header = json.loads(_b64url_decode(encoded_header))
        payload = json.loads(_b64url_decode(encoded_payload))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise InvalidTokenError("Malformed token")

    if algorithms is not None and header.get("alg") not in algorithms:
        raise InvalidTokenError("Unsupported algorithm")

    exp = payload.get("exp")
    if exp is not None:
        try:
            if time.time() >= float(exp):
                raise ExpiredSignatureError("Token expired")
        except (TypeError, ValueError):
            raise InvalidTokenError("Malformed expiration claim")

    return payload
