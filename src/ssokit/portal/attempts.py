from __future__ import annotations

import secrets
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"


def new_ref() -> str:
    return "LMN-" + "".join(secrets.choice(_ALPHABET) for _ in range(6))


@dataclass
class Attempt:
    ref: str
    ts: float
    tenant_id: str
    ok: bool
    code: str | None
    title: str
    subject: str | None
    method: str
    ip: str
    user_agent: str
    latency_ms: float
    report: dict[str, Any]
    token_preview: str = ""
    segments: list[str] = field(default_factory=list)


@dataclass
class Event:
    ts: float
    tenant_id: str
    kind: str
    detail: str = ""


class AttemptLog:
    def __init__(self, maxlen: int = 1000):
        self._attempts: deque[Attempt] = deque(maxlen=maxlen)
        self._events: deque[Event] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, attempt: Attempt) -> None:
        with self._lock:
            self._attempts.appendleft(attempt)

    def event(self, tenant_id: str, kind: str, detail: str = "") -> None:
        with self._lock:
            self._events.appendleft(Event(time.time(), tenant_id, kind, detail))

    def get(self, ref: str) -> Attempt | None:
        return next((a for a in self._attempts if a.ref == ref), None)

    def recent(self, *, tenant: str | None = None, status: str | None = None, limit: int = 50) -> list[Attempt]:
        items = list(self._attempts)
        if tenant:
            items = [a for a in items if a.tenant_id == tenant]
        if status == "ok":
            items = [a for a in items if a.ok]
        elif status == "failed":
            items = [a for a in items if not a.ok]
        return items[:limit]

    def events(self, tenant: str, kind: str | None = None) -> list[Event]:
        return [e for e in self._events if e.tenant_id == tenant and (kind is None or e.kind == kind)]

    def stats(self, tenant: str, window: float = 86400) -> dict[str, Any]:
        cutoff = time.time() - window
        items = [a for a in self._attempts if a.tenant_id == tenant and a.ts >= cutoff]
        ok = [a for a in items if a.ok]
        failed = [a for a in items if not a.ok]
        codes = Counter(a.code for a in failed if a.code)
        return {
            "total": len(items),
            "ok": len(ok),
            "failed": len(failed),
            "rate": (len(ok) / len(items) * 100) if items else None,
            "last_ok": ok[0].ts if ok else None,
            "last_failure": failed[0] if failed else None,
            "top_codes": codes.most_common(3),
            "codes_seen": set(codes),
            "p50_latency": sorted(a.latency_ms for a in items)[len(items) // 2] if items else None,
        }

    def __len__(self) -> int:
        return len(self._attempts)
