"""In-process event delivery with thread-safe subscriber management."""

from __future__ import annotations

from collections.abc import Callable
import threading

from src.core.event_models import SecurityEvent


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[Callable[[SecurityEvent], None]] = []
        self._lock = threading.RLock()

    def subscribe(self, subscriber: Callable[[SecurityEvent], None]) -> Callable[[], None]:
        if not callable(subscriber):
            raise TypeError("Event subscriber must be callable.")
        with self._lock:
            self._subscribers.append(subscriber)

        def unsubscribe() -> None:
            with self._lock:
                if subscriber in self._subscribers:
                    self._subscribers.remove(subscriber)

        return unsubscribe

    def publish(self, event: SecurityEvent) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            subscriber(event)