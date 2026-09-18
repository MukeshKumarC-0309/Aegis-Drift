"""Shared FastAPI dependencies: database sessions, authentication and RBAC."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.core.logging import actor_ctx
from app.core.security import Role, TokenType, decode_token, hash_api_key
from app.db.base import utcnow
from app.db.models import ApiKey, User
from app.db.session import get_db
from app.schemas.common import PageParams

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

DbSession = Annotated[AsyncSession, Depends(get_db)]


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db():
        yield session


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbSession,
) -> User:
    """Resolve the bearer token to an active user."""
    if credentials is None:
        raise AuthenticationError("An Authorization: Bearer <token> header is required.")

    payload = decode_token(credentials.credentials, expected=TokenType.ACCESS)
    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Token is missing a subject claim.")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise AuthenticationError("The account on this token no longer exists.")
    if not user.is_active:
        raise PermissionDeniedError("This account has been deactivated.")

    actor_ctx.set(user.email)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(minimum: Role):
    """Dependency factory enforcing a minimum RBAC tier."""

    async def _guard(user: CurrentUser) -> User:
        if user.role.rank < minimum.rank:
            raise PermissionDeniedError(
                f"This operation requires the '{minimum.value}' role or higher; "
                f"your role is '{user.role.value}'."
            )
        return user

    return _guard


RequireAnalyst = Annotated[User, Depends(require_role(Role.ANALYST))]
RequireResponder = Annotated[User, Depends(require_role(Role.RESPONDER))]
RequireAdmin = Annotated[User, Depends(require_role(Role.ADMIN))]


async def get_api_key_principal(request: Request, db: DbSession) -> ApiKey:
    """Authenticate a machine client via the ``X-API-Key`` header."""
    raw = request.headers.get("X-API-Key")
    if not raw:
        raise AuthenticationError("An X-API-Key header is required for this endpoint.")

    key = (await db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw)))).scalar_one_or_none()
    if key is None or not key.is_active:
        raise AuthenticationError("The supplied API key is not valid.")
    if key.expires_at and key.expires_at < utcnow():
        raise AuthenticationError("The supplied API key has expired.")

    key.last_used_at = utcnow()
    key.call_count += 1
    actor_ctx.set(f"apikey:{key.prefix}")
    return key


async def get_ingest_principal(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User | ApiKey:
    """Ingest accepts either a user JWT or a machine API key."""
    if request.headers.get("X-API-Key"):
        return await get_api_key_principal(request, db)
    if credentials is None:
        raise AuthenticationError("Telemetry ingest requires either an X-API-Key header or a bearer token.")
    return await get_current_user(credentials, db)


def pagination(
    page: Annotated[int, Query(ge=1, description="1-indexed page number.")] = 1,
    page_size: Annotated[int, Query(ge=1, le=200, description="Items per page.")] = 25,
    sort_by: Annotated[str | None, Query(description="Column to sort by.")] = None,
    sort_dir: Annotated[str, Query(pattern="^(asc|desc)$")] = "desc",
) -> PageParams:
    return PageParams(page=page, page_size=page_size, sort_by=sort_by, sort_dir=sort_dir)


Pagination = Annotated[PageParams, Depends(pagination)]


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
