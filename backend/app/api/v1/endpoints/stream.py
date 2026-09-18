"""WebSocket live feed.

Authentication uses a query-string token because browsers cannot set headers on a
WebSocket handshake. The token is a normal short-lived access JWT, so the exposure
window is the same as any other request — but it will appear in proxy access logs,
which is why the endpoint accepts nothing else and grants read-only streaming.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.core.exceptions import SilentShiftError
from app.core.logging import get_logger
from app.core.metrics import WEBSOCKET_CLIENTS
from app.core.security import TokenType, decode_token
from app.db.models import User
from app.db.session import SessionLocal
from app.services.events import event_bus

logger = get_logger(__name__)
router = APIRouter()

#: Keepalive cadence; also detects half-open connections behind proxies.
HEARTBEAT_SECONDS = 25


@router.websocket("/live")
async def live_feed(
    websocket: WebSocket,
    token: str = Query(..., description="A valid access token."),
) -> None:
    try:
        claims = decode_token(token, expected=TokenType.ACCESS)
    except SilentShiftError:
        await websocket.close(code=4401, reason="Invalid or expired token")
        return

    async with SessionLocal() as db:
        user = (await db.execute(select(User).where(User.id == claims.get("sub")))).scalar_one_or_none()
    if user is None or not user.is_active:
        await websocket.close(code=4403, reason="Account is not active")
        return

    await websocket.accept()
    WEBSOCKET_CLIENTS.inc()
    logger.info("stream.connected", user=user.email)

    await websocket.send_text(
        json.dumps(
            {
                "type": "connected",
                "payload": {"user": user.email, "role": user.role.value},
            }
        )
    )

    try:
        async with event_bus.subscribe() as queue:
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except TimeoutError:
                    await websocket.send_text(json.dumps({"type": "heartbeat"}))
                    continue
                await websocket.send_text(message)
    except WebSocketDisconnect:
        logger.info("stream.disconnected", user=user.email)
    except Exception as exc:  # pragma: no cover - transport level
        logger.warning("stream.error", user=user.email, error=str(exc))
        with contextlib.suppress(Exception):
            await websocket.close(code=1011)
    finally:
        WEBSOCKET_CLIENTS.dec()
