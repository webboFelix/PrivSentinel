"""Small bounded-window event correlation with explainable grouping."""

from collections import defaultdict, deque
from datetime import timedelta

from src.core.event_models import SecurityEvent


class CorrelationEngine:
    def __init__(self, window_seconds: int = 300, maximum_events: int = 10000) -> None:
        if window_seconds < 1 or maximum_events < 1:
            raise ValueError("Correlation window and event cap must be positive.")
        self.window = timedelta(seconds=window_seconds)
        self.events: deque[SecurityEvent] = deque(maxlen=maximum_events)

    def add(self, event: SecurityEvent) -> list[tuple[str, tuple[SecurityEvent, ...]]]:
        self.events.append(event)
        cutoff = event.occurred_at - self.window
        while self.events and self.events[0].occurred_at < cutoff:
            self.events.popleft()
        groups: dict[str, list[SecurityEvent]] = defaultdict(list)
        for item in self.events:
            key = item.correlation_id or f"source:{item.source}"
            groups[key].append(item)
        return [
            (key, tuple(items))
            for key, items in groups.items()
            if len(items) > 1 and event in items
        ]