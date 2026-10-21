from __future__ import annotations

import base64
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class TokenBuild:
    claims: dict[str, Any]
    headers: dict[str, Any]
    algorithm: str
    key: Any
    public_pem: bytes | None = None
    prefix: str = ""
    reuse_last: bool = False


@dataclass(frozen=True)
class Scenario:
    id: str
    group: str
    label: str
    description: str
    expect: str | None
    apply: Callable[[TokenBuild, float], None] = field(default=lambda b, now: None)
    algs: frozenset[str] = frozenset({"RS256", "HS256"})


def _shift(hours: float = 0, seconds: int = 0) -> Callable[[TokenBuild, float], None]:
    def apply(b: TokenBuild, now: float) -> None:
        delta = int(hours * 3600) + seconds
        b.claims["iat"] += delta
        b.claims["exp"] += delta

    return apply


def _set(**values: Any) -> Callable[[TokenBuild, float], None]:
    def apply(b: TokenBuild, now: float) -> None:
        for key, value in values.items():
            if value is None:
                b.claims.pop(key, None)
            else:
                b.claims[key] = value

    return apply


def _expired(b: TokenBuild, now: float) -> None:
    b.claims["iat"] = int(now) - 420
    b.claims["exp"] = int(now) - 360


def _millis(b: TokenBuild, now: float) -> None:
    b.claims["exp"] = b.claims["exp"] * 1000


def _cached(b: TokenBuild, now: float) -> None:
    b.claims["iat"] = int(now) - 600
    b.claims["exp"] = int(now) + 60


def _long(b: TokenBuild, now: float) -> None:
    b.claims["exp"] = b.claims["iat"] + 86400


def _numeric_sub(b: TokenBuild, now: float) -> None:
    b.claims["sub"] = int(b.claims["sub"])


def _iss_slash(b: TokenBuild, now: float) -> None:
    b.claims["iss"] = b.claims["iss"] + "/"


def _wrong_key(b: TokenBuild, now: float) -> None:
    if b.algorithm.startswith("HS"):
        b.key = b"staging-secret-that-was-never-rotated-to-prod"
    else:
        b.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _secret_encoding(b: TokenBuild, now: float) -> None:
    b.key = base64.b64decode(b.key)


def _unknown_kid(b: TokenBuild, now: float) -> None:
    b.headers["kid"] = "orbis-2025-04"


def _alg_none(b: TokenBuild, now: float) -> None:
    b.algorithm = "none"
    b.key = None
    b.headers.pop("kid", None)


def _confusion(b: TokenBuild, now: float) -> None:
    b.algorithm = "HS256"
    b.key = b.public_pem
    b.headers.pop("kid", None)


def _bearer(b: TokenBuild, now: float) -> None:
    b.prefix = "Bearer "


def _replay(b: TokenBuild, now: float) -> None:
    b.reuse_last = True


SCENARIOS: list[Scenario] = [
    Scenario("healthy", "Working", "Correct token", "A fresh, correctly signed token.", None),
    Scenario(
        "expired",
        "Timing",
        "Expired token",
        "exp was six minutes ago, like a token generated when the page loaded.",
        "SSO-130",
        _expired,
    ),
    Scenario(
        "timezone",
        "Timing",
        "Local time instead of UTC",
        "Timestamps are three hours ahead, as if built from Moscow or Istanbul local time.",
        "SSO-132",
        _shift(hours=3),
    ),
    Scenario(
        "clock_drift",
        "Timing",
        "Broker clock five minutes fast",
        "The broker server's clock drifted; NTP is not running.",
        "SSO-132",
        _shift(seconds=300),
    ),
    Scenario(
        "cached",
        "Timing",
        "Token cached in the page",
        "iat is ten minutes old although exp is still in the future.",
        "SSO-133",
        _cached,
    ),
    Scenario(
        "long_lifetime",
        "Timing",
        "24-hour token",
        "exp is a day after iat. Launch tokens must be short lived.",
        "SSO-134",
        _long,
    ),
    Scenario(
        "millis", "Timing", "exp in milliseconds", "Date.now() used without dividing by 1000.", "SSO-141", _millis
    ),
    Scenario("missing_sub", "Claims", "No sub claim", "The user identifier is missing.", "SSO-140", _set(sub=None)),
    Scenario(
        "numeric_sub",
        "Claims",
        "sub as a number",
        "The client ID is sent as an integer instead of a string.",
        "SSO-141",
        _numeric_sub,
    ),
    Scenario(
        "wrong_aud",
        "Claims",
        "Wrong audience",
        "aud copied from another vendor's integration.",
        "SSO-142",
        _set(aud="analytics-portal"),
    ),
    Scenario(
        "iss_slash",
        "Claims",
        "Issuer with trailing slash",
        "iss differs from the agreed value by one character.",
        "SSO-143",
        _iss_slash,
    ),
    Scenario(
        "wrong_key",
        "Signature and keys",
        "Signed with the wrong key",
        "Staging credentials used in production.",
        "SSO-120",
        _wrong_key,
    ),
    Scenario(
        "secret_encoding",
        "Signature and keys",
        "Secret decoded from base64",
        "The broker base64-decodes the shared secret before signing; the portal uses it as text.",
        "SSO-120",
        _secret_encoding,
        frozenset({"HS256"}),
    ),
    Scenario(
        "unknown_kid",
        "Signature and keys",
        "Unknown key ID",
        "kid points to a key that is not published in the JWKS.",
        "SSO-111",
        _unknown_kid,
        frozenset({"RS256"}),
    ),
    Scenario(
        "confusion",
        "Signature and keys",
        "HS256 signed with the public key",
        "The algorithm-confusion attack shape. Must be rejected.",
        "SSO-110",
        _confusion,
        frozenset({"RS256"}),
    ),
    Scenario(
        "alg_none", "Signature and keys", "Unsigned token", "alg: none. Must always be rejected.", "SSO-110", _alg_none
    ),
    Scenario(
        "replay",
        "Transport",
        "Resend the previous token",
        "Simulates a double submit or the back button. Launch tokens are single use.",
        "SSO-150",
        _replay,
    ),
    Scenario(
        "bearer",
        "Transport",
        "Bearer prefix in the field",
        "The token is sent as 'Bearer eyJ...' in the form field.",
        "SSO-101",
        _bearer,
    ),
]

BY_ID = {s.id: s for s in SCENARIOS}


def scenarios_for(algorithm: str) -> list[Scenario]:
    return [s for s in SCENARIOS if algorithm in s.algs]


def public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def now() -> float:
    return time.time()
