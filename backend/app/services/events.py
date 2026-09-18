"""In-process publish/subscribe bus backing the live WebSocket feed.

Redis-free by design: a single process broadcasts to its own subscribers. When
``REDIS_URL`` is configured the bus additionally fans out across replicas.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

CHANNEL = "aegisdrift:events"

#: Slow consumers are dropped rather than allowed to stall the publisher.
SUBSCRIBER_QUEUE_SIZE = 256


class EventBus:
    """Fan-out of domain events to connected WebSocket clients."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._redis: Any | None = None
        self._relay_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if not settings.REDIS_URL:
            return
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await self._redis.ping()
            self._relay_task = asyncio.create_task(self._relay())
            logger.info("eventbus.redis_connected")
        except Exception as exc:  # pragma: no cover - depends on deployment
            logger.warning("eventbus.redis_unavailable", error=str(exc))
            self._redis = None

    async def stop(self) -> None:
        if self._relay_task:
            self._relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._relay_task
        if self._redis:
            await self._redis.aclose()

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = json.dumps(
            {
                "type": event_type,
                "payload": payload,
                "at": datetime.utcnow().isoformat() + "Z",
            },
            default=str,
        )
        if self._redis:
            try:
                await self._redis.publish(CHANNEL, message)
                return  # the relay loop delivers it back to local subscribers
            except Exception as exc:  # pragma: no cover
                logger.warning("eventbus.publish_failed", error=str(exc))
        self._deliver(message)

    def _deliver(self, message: str) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                logger.warning("eventbus.subscriber_lagging_dropped")
                self._subscribers.discard(queue)

    async def _relay(self) -> None:  # pragma: no cover - requires Redis
        assert self._redis is not None
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(CHANNEL)
        try:
            async for message in pubsub.listen():
                if message.get("type") == "message":
                    self._deliver(message["data"])
        except asyncio.CancelledError:
            await pubsub.unsubscribe(CHANNEL)
            raise

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[str]]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


event_bus = EventBus()
