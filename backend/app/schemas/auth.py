"""Authentication and account-management payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.security import Role, password_issues
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=256)]


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: Annotated[str, Field(min_length=2, max_length=160)]
    password: str
    role: Role = Role.ANALYST

    @field_validator("password")
    @classmethod
    def _strong_enough(cls, v: str) -> str:
        if issues := password_issues(v):
            raise ValueError("Password " + "; ".join(issues))
        return v


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: Role | None = None
    is_active: bool | None = None
    preferences: dict | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _strong_enough(cls, v: str) -> str:
        if issues := password_issues(v):
            raise ValueError("Password " + "; ".join(issues))
        return v


class UserRead(ORMModel):
    id: str
    email: EmailStr
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None
    preferences: dict
    created_at: datetime


class ApiKeyCreate(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    scopes: list[str] = Field(default_factory=lambda: ["ingest:write"])
    expires_in_days: Annotated[int, Field(ge=1, le=730)] | None = None


class ApiKeyRead(ORMModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    call_count: int
    created_at: datetime


class ApiKeyCreated(ApiKeyRead):
    """Returned once on creation — ``key`` is never retrievable again."""

    key: str
