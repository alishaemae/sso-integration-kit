from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class Instrument:
    symbol: str
    name: str
    base: float
    decimals: int
    volatility: float


INSTRUMENTS: dict[str, Instrument] = {
    i.symbol: i
    for i in (
        Instrument("EURUSD", "Euro / US Dollar", 1.0842, 5, 0.00042),
        Instrument("GBPUSD", "Pound / US Dollar", 1.2671, 5, 0.00048),
        Instrument("USDJPY", "US Dollar / Yen", 149.82, 3, 0.0005),
        Instrument("XAUUSD", "Gold / US Dollar", 2648.30, 2, 0.0008),
        Instrument("US500", "US 500 Index", 5841.2, 1, 0.0007),
        Instrument("BTCUSD", "Bitcoin / US Dollar", 67250.0, 0, 0.0019),
    )
}

POINTS = 96


@dataclass
class Snapshot:
    instrument: Instrument
    series: list[float]
    long_pct: int
    rsi: float
    sma_fast: float
    sma_slow: float
    signal: str
    times: list[datetime] = field(default_factory=list)

    @property
    def last(self) -> float:
        return self.series[-1]

    @property
    def change(self) -> float:
        return self.series[-1] - self.series[0]

    @property
    def change_pct(self) -> float:
        return self.change / self.series[0] * 100

    @property
    def high(self) -> float:
        return max(self.series)

    @property
    def low(self) -> float:
        return min(self.series)

    def fmt(self, value: float) -> str:
        return f"{value:,.{self.instrument.decimals}f}"


def _rng(*parts: str) -> random.Random:
    digest = hashlib.sha256("|".join(parts).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _rsi(series: list[float], period: int = 14) -> float:
    gains = losses = 0.0
    for prev, cur in zip(series[-period - 1 : -1], series[-period:], strict=True):
        delta = cur - prev
        gains += max(delta, 0)
        losses += max(-delta, 0)
    if losses == 0:
        return 100.0
    rs = (gains / period) / (losses / period)
    return 100 - 100 / (1 + rs)


def snapshot(symbol: str, *, day: str | None = None) -> Snapshot:
    inst = INSTRUMENTS[symbol]
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    now = now - timedelta(minutes=now.minute % 15)
    day = day or now.strftime("%Y-%m-%d")
    rng = _rng(symbol, day)
    drift = rng.uniform(-0.09, 0.09) * inst.volatility
    price = inst.base * (1 + rng.uniform(-0.01, 0.01))
    series = []
    for i in range(POINTS):
        shock = rng.gauss(0, inst.volatility)
        wave = math.sin(i / 9) * inst.volatility * 0.12
        price *= 1 + drift + shock + wave
        series.append(round(price, inst.decimals + 1))
    fast = sum(series[-8:]) / 8
    slow = sum(series[-32:]) / 32
    rsi = _rsi(series)
    if fast > slow and rsi < 70:
        signal = "Buy"
    elif fast < slow and rsi > 30:
        signal = "Sell"
    else:
        signal = "Neutral"
    times = [now - timedelta(minutes=15 * (POINTS - 1 - i)) for i in range(POINTS)]
    return Snapshot(inst, series, rng.randint(28, 74), rsi, fast, slow, signal, times)


def chart_paths(series: list[float], width: float, height: float, pad_y: float = 12) -> dict:
    lo, hi = min(series), max(series)
    span = (hi - lo) or 1
    step = width / (len(series) - 1)
    pts = [(i * step, pad_y + (hi - v) / span * (height - 2 * pad_y)) for i, v in enumerate(series)]
    line = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{line} L{width:.1f},{height:.1f} L0,{height:.1f} Z"
    grid = []
    for k in range(4):
        value = hi - span * k / 3
        y = pad_y + (hi - value) / span * (height - 2 * pad_y)
        grid.append({"y": round(y, 1), "value": value})
    return {"line": line, "area": area, "last": pts[-1], "grid": grid}


def calendar(today: datetime | None = None) -> list[dict]:
    today = (today or datetime.now(UTC)).replace(minute=0, second=0, microsecond=0)
    rng = _rng("calendar", today.strftime("%Y-%m-%d"))
    events = [
        ("EUR", "German Ifo business climate", 2, "86.4", "85.7"),
        ("GBP", "CPI y/y", 3, "2.1%", "2.2%"),
        ("USD", "Initial jobless claims", 2, "228K", "241K"),
        ("USD", "Existing home sales", 1, "3.88M", "3.86M"),
        ("EUR", "ECB President speaks", 3, "", ""),
        ("JPY", "Tokyo core CPI y/y", 2, "1.8%", "2.0%"),
        ("USD", "Crude oil inventories", 1, "-0.9M", "-2.2M"),
    ]
    rng.shuffle(events)
    out = []
    for i, (ccy, title, impact, forecast, previous) in enumerate(sorted(events[:6], key=lambda e: e[0])):
        when = today.replace(hour=7) + timedelta(hours=2 * i + rng.randint(0, 1), minutes=30 * rng.randint(0, 1))
        out.append(
            {
                "time": when,
                "currency": ccy,
                "title": title,
                "impact": impact,
                "forecast": forecast,
                "previous": previous,
            }
        )
    return sorted(out, key=lambda e: e["time"])
