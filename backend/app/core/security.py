"""Password hashing, JWT issuance/verification and API-key handling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import AuthenticationError

_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

API_KEY_PREFIX = "ad_live_"


class Role(StrEnum):
    """Coarse RBAC tiers, ordered from least to most privileged."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]


_ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.RESPONDER: 2,
    Role.ADMIN: 3,
}


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


# --------------------------------------------------------------------- passwords
def hash_password(raw: str) -> str:
    return _pwd_context.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return _pwd_context.verify(raw, hashed)
    except ValueError:
        return False


def password_issues(raw: str) -> list[str]:
    """Return human-readable reasons a password is unacceptable (empty == ok)."""
    problems: list[str] = []
    if len(raw) < settings.PASSWORD_MIN_LENGTH:
        problems.append(f"must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    if raw.islower() or raw.isupper():
        problems.append("must mix upper and lower case letters")
    if not any(c.isdigit() for c in raw):
        problems.append("must contain a digit")
    if not any(not c.isalnum() for c in raw):
        problems.append("must contain a symbol")
    return problems


# ------------------------------------------------------------------------ tokens
def _create_token(
    subject: str,
    token_type: TokenType,
    expires: timedelta,
    extra: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "typ": token_type.value,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + expires).timestamp()),
        "jti": uuid.uuid4().hex,
        "iss": settings.PROJECT_NAME,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: str, *, role: Role, email: str) -> str:
    return _create_token(
        subject,
        TokenType.ACCESS,
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        {"role": role.value, "email": email},
    )


def create_refresh_token(subject: str) -> str:
    return _create_token(subject, TokenType.REFRESH, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str, *, expected: TokenType | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.PROJECT_NAME,
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Token has expired.", code="token_expired") from exc
    except jwt.PyJWTError as exc:
        raise AuthenticationError("Token is malformed or has an invalid signature.") from exc

    if expected and payload.get("typ") != expected.value:
        raise AuthenticationError(f"Expected a {expected.value} token.", code="wrong_token_type")
    return payload


# ---------------------------------------------------------------------- API keys
def generate_api_key() -> tuple[str, str, str]:
    """Return ``(plaintext, sha256_hash, display_prefix)``.

    Only the hash is persisted; the plaintext is shown to the operator exactly once.
    """
    raw = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    return raw, hash_api_key(raw), raw[: len(API_KEY_PREFIX) + 6]


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_api_key(raw: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw), stored_hash)
