"""Authentication, session lifecycle and API-key management."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession, RequireAdmin, client_ip
from app.core.config import settings
from app.core.exceptions import AuthenticationError, ConflictError, NotFoundError
from app.core.security import (
    Role,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    hash_password,
    verify_password,
)
from app.db.base import utcnow
from app.db.models import ApiKey, User
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRead,
    LoginRequest,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserRead,
    UserUpdate,
)
from app.schemas.common import Message
from app.services import audit

router = APIRouter()

#: Consecutive failures before an account is temporarily locked.
MAX_FAILED_LOGINS = 6
LOCKOUT_DURATION = timedelta(minutes=15)


@router.post("/login", response_model=TokenPair, summary="Exchange credentials for tokens")
async def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenPair:
    user = (await db.execute(select(User).where(User.email == payload.email.lower()))).scalar_one_or_none()

    # Uniform failure message: never reveal whether the address is registered.
    invalid = AuthenticationError("Email or password is incorrect.")

    if user is None:
        raise invalid
    if user.locked_until and user.locked_until > utcnow():
        raise AuthenticationError(
            "This account is temporarily locked after repeated failed sign-ins.",
            code="account_locked",
        )
    if not user.is_active:
        raise AuthenticationError("This account has been deactivated.", code="account_disabled")

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = utcnow() + LOCKOUT_DURATION
        await audit.record(
            db,
            action="auth.login_failed",
            target_type="user",
            target_id=user.id,
            actor_email=payload.email,
            outcome="FAILURE",
            ip_address=client_ip(request),
            payload={"attempt": user.failed_login_count},
        )
        raise invalid

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()

    await audit.record(
        db,
        action="auth.login",
        target_type="user",
        target_id=user.id,
        actor=user,
        ip_address=client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return TokenPair(
        access_token=create_access_token(user.id, role=user.role, email=user.email),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenPair, summary="Exchange a refresh token")
async def refresh(payload: RefreshRequest, db: DbSession) -> TokenPair:
    claims = decode_token(payload.refresh_token, expected=TokenType.REFRESH)
    user = (await db.execute(select(User).where(User.id == claims["sub"]))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthenticationError("This refresh token is no longer valid.")

    return TokenPair(
        access_token=create_access_token(user.id, role=user.role, email=user.email),
        refresh_token=create_refresh_token(user.id),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserRead, summary="Current operator profile")
async def me(user: CurrentUser) -> User:
    return user


@router.patch("/me", response_model=UserRead, summary="Update your own profile")
async def update_me(payload: UserUpdate, user: CurrentUser, db: DbSession) -> User:
    # Role and activation are administrative; a user cannot grant them to themselves.
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.preferences is not None:
        user.preferences = payload.preferences
    await audit.record(db, action="user.self_updated", target_type="user", target_id=user.id, actor=user)
    return user


@router.post("/me/password", response_model=Message, summary="Change your password")
async def change_password(payload: PasswordChange, user: CurrentUser, db: DbSession) -> Message:
    if not verify_password(payload.current_password, user.hashed_password):
        raise AuthenticationError("The current password is incorrect.")
    user.hashed_password = hash_password(payload.new_password)
    await audit.record(db, action="user.password_changed", target_type="user", target_id=user.id, actor=user)
    return Message(message="Password updated.")


# ------------------------------------------------------------------ user admin
@router.get("/users", response_model=list[UserRead], summary="List operators")
async def list_users(_: RequireAdmin, db: DbSession) -> list[User]:
    return list((await db.execute(select(User).order_by(User.created_at))).scalars().all())


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an operator",
)
async def create_user(payload: UserCreate, admin: RequireAdmin, db: DbSession) -> User:
    exists = (
        await db.execute(select(User.id).where(User.email == payload.email.lower()))
    ).scalar_one_or_none()
    if exists:
        raise ConflictError(f"An account already exists for {payload.email}.")

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    await db.flush()
    await audit.record(
        db,
        action="user.created",
        target_type="user",
        target_id=user.id,
        actor=admin,
        payload={"email": user.email, "role": user.role.value},
    )
    return user


@router.patch("/users/{user_id}", response_model=UserRead, summary="Update an operator")
async def update_user(user_id: str, payload: UserUpdate, admin: RequireAdmin, db: DbSession) -> User:
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise NotFoundError(f"No operator with id '{user_id}'.")

    if payload.role is Role.VIEWER and user.id == admin.id:
        raise ConflictError("You cannot demote your own administrator account.")
    if payload.is_active is False and user.id == admin.id:
        raise ConflictError("You cannot deactivate your own account.")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    await audit.record(
        db,
        action="user.updated",
        target_type="user",
        target_id=user.id,
        actor=admin,
        payload=payload.model_dump(exclude_unset=True),
    )
    return user


# -------------------------------------------------------------------- api keys
@router.get("/api-keys", response_model=list[ApiKeyRead], summary="List your API keys")
async def list_api_keys(user: CurrentUser, db: DbSession) -> list[ApiKey]:
    rows = (
        (
            await db.execute(
                select(ApiKey).where(ApiKey.owner_id == user.id).order_by(ApiKey.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Issue an ingest API key",
)
async def create_api_key(payload: ApiKeyCreate, user: CurrentUser, db: DbSession) -> ApiKeyCreated:
    raw, hashed, prefix = generate_api_key()
    key = ApiKey(
        name=payload.name,
        key_hash=hashed,
        prefix=prefix,
        owner_id=user.id,
        scopes=payload.scopes,
        expires_at=(utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None),
    )
    db.add(key)
    await db.flush()
    await audit.record(
        db,
        action="apikey.created",
        target_type="api_key",
        target_id=key.id,
        actor=user,
        payload={"name": key.name, "scopes": key.scopes},
    )
    # The plaintext is returned exactly once and never persisted.
    return ApiKeyCreated(**ApiKeyRead.model_validate(key).model_dump(), key=raw)


@router.delete("/api-keys/{key_id}", response_model=Message, summary="Revoke an API key")
async def revoke_api_key(key_id: str, user: CurrentUser, db: DbSession) -> Message:
    key = (
        await db.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.owner_id == user.id))
    ).scalar_one_or_none()
    if key is None:
        raise NotFoundError(f"No API key with id '{key_id}' belongs to you.")
    key.is_active = False
    await audit.record(db, action="apikey.revoked", target_type="api_key", target_id=key.id, actor=user)
    return Message(message=f"API key '{key.name}' revoked.")
