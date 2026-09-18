"""Password hashing, JWT handling and API-key primitives."""

from __future__ import annotations

import time

import pytest

from app.core.exceptions import AuthenticationError
from app.core.security import (
    Role,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
    hash_password,
    password_issues,
    verify_api_key,
    verify_password,
)

pytestmark = pytest.mark.unit


class TestPasswords:
    def test_hash_is_salted_and_verifiable(self):
        first = hash_password("CorrectHorse_1!")
        second = hash_password("CorrectHorse_1!")

        assert first != second  # unique salts
        assert verify_password("CorrectHorse_1!", first)
        assert verify_password("CorrectHorse_1!", second)

    def test_wrong_password_fails(self):
        assert not verify_password("wrong", hash_password("CorrectHorse_1!"))

    def test_malformed_hash_returns_false_rather_than_raising(self):
        assert verify_password("anything", "not-a-real-hash") is False

    @pytest.mark.parametrize(
        ("password", "expected_issue"),
        [
            ("short1!A", "at least"),
            ("alllowercase1!", "upper and lower"),
            ("NoDigitsHere!!", "digit"),
            ("NoSymbols12345", "symbol"),
        ],
    )
    def test_weak_passwords_are_reported(self, password, expected_issue):
        issues = password_issues(password)
        assert any(expected_issue in issue for issue in issues)

    def test_strong_password_has_no_issues(self):
        assert password_issues("Str0ng&Passphrase") == []


class TestTokens:
    def test_access_token_round_trip(self):
        token = create_access_token("usr_1", role=Role.ANALYST, email="a@b.c")
        claims = decode_token(token, expected=TokenType.ACCESS)

        assert claims["sub"] == "usr_1"
        assert claims["role"] == "analyst"
        assert claims["email"] == "a@b.c"
        assert claims["typ"] == "access"

    def test_refresh_token_round_trip(self):
        claims = decode_token(create_refresh_token("usr_1"), expected=TokenType.REFRESH)
        assert claims["sub"] == "usr_1"

    def test_token_type_confusion_is_rejected(self):
        """A refresh token must never be usable as an access token."""
        refresh = create_refresh_token("usr_1")
        with pytest.raises(AuthenticationError, match="Expected a access token"):
            decode_token(refresh, expected=TokenType.ACCESS)

    def test_tampered_signature_is_rejected(self):
        token = create_access_token("usr_1", role=Role.ADMIN, email="a@b.c")
        head, payload, _ = token.split(".")
        with pytest.raises(AuthenticationError):
            decode_token(f"{head}.{payload}.deadbeef", expected=TokenType.ACCESS)

    def test_garbage_is_rejected(self):
        with pytest.raises(AuthenticationError):
            decode_token("not-a-token")

    def test_each_token_has_a_unique_id(self):
        a = decode_token(create_access_token("u", role=Role.VIEWER, email="e@x.y"))
        time.sleep(0.001)
        b = decode_token(create_access_token("u", role=Role.VIEWER, email="e@x.y"))
        assert a["jti"] != b["jti"]


class TestRoles:
    def test_rank_ordering(self):
        assert Role.VIEWER.rank < Role.ANALYST.rank < Role.RESPONDER.rank < Role.ADMIN.rank


class TestApiKeys:
    def test_generated_key_verifies_against_its_hash(self):
        raw, hashed, prefix = generate_api_key()

        assert raw.startswith("ss_live_")
        assert prefix == raw[: len(prefix)]
        assert raw != hashed
        assert verify_api_key(raw, hashed)

    def test_wrong_key_does_not_verify(self):
        _, hashed, _ = generate_api_key()
        other, _, _ = generate_api_key()
        assert not verify_api_key(other, hashed)

    def test_keys_are_unique(self):
        keys = {generate_api_key()[0] for _ in range(50)}
        assert len(keys) == 50
