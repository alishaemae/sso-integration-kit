from __future__ import annotations

import threading
import time
from typing import Protocol


class ReplayStore(Protocol):
    def consume(self, key: str, expires_at: float) -> bool: ...


class InMemoryReplayStore:
    def __init__(self, clock=time.time, max_entries: int = 100_000):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._max_entries = max_entries

    def consume(self, key: str, expires_at: float) -> bool:
        now = self._clock()
        with self._lock:
            if len(self._seen) > self._max_entries // 2:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            existing = self._seen.get(key)
            if existing is not None and existing > now:
                return False
            self._seen[key] = expires_at
            return True

    def __len__(self) -> int:
        return len(self._seen)
