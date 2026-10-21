from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import ErrorCode

HMAC_ALGS = {"HS256", "HS384", "HS512"}


class KeyResolutionError(Exception):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


class KeyProvider(Protocol):
    description: str

    def key_for(self, header: dict[str, Any]) -> Any: ...


@dataclass
class SecretKeyProvider:
    secret: bytes
    description: str = "shared secret"

    def key_for(self, header: dict[str, Any]) -> bytes:
        return self.secret


@dataclass
class PublicKeyProvider:
    pem: bytes
    description: str = "public key (PEM)"

    def key_for(self, header: dict[str, Any]) -> Any:
        alg = header.get("alg", "RS256")
        try:
            return jwt.get_algorithm_by_name(alg).prepare_key(self.pem)
        except Exception as exc:
            raise KeyResolutionError(
                ErrorCode.KEYS_UNAVAILABLE, f"Public key could not be loaded for {alg}: {exc}"
            ) from exc


class JWKSKeyProvider:
    def __init__(
        self,
        url: str | None = None,
        *,
        document: dict[str, Any] | None = None,
        ttl: float = 300,
        min_refresh_interval: float = 30,
        timeout: float = 3,
        fetcher: Callable[[str], dict[str, Any]] | None = None,
    ):
        if url is None and document is None:
            raise ValueError("JWKSKeyProvider needs a url or a document")
        self.url = url
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self.timeout = timeout
        self._fetcher = fetcher or self._http_fetch
        self._lock = threading.Lock()
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0
        self._static = document is not None
        if document is not None:
            self._keys = self._parse(document)
            self._fetched_at = time.monotonic()
        self.description = f"JWKS {url}" if url else "JWKS (inline)"

    def _http_fetch(self, url: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def _parse(document: dict[str, Any]) -> dict[str, jwt.PyJWK]:
        keys = document.get("keys")
        if not isinstance(keys, list) or not keys:
            raise KeyResolutionError(ErrorCode.KEYS_UNAVAILABLE, "JWKS document has no `keys` array")
        parsed: dict[str, jwt.PyJWK] = {}
        for index, jwk in enumerate(keys):
            try:
                key = jwt.PyJWK(jwk)
            except Exception:
                continue
            parsed[jwk.get("kid") or f"#{index}"] = key
        if not parsed:
            raise KeyResolutionError(ErrorCode.KEYS_UNAVAILABLE, "JWKS contains no usable keys")
        return parsed

    def _refresh(self) -> None:
        if self._static or self.url is None:
            return
        try:
            document = self._fetcher(self.url)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise KeyResolutionError(
                ErrorCode.KEYS_UNAVAILABLE, f"Could not fetch JWKS from {self.url}: {exc}"
            ) from exc
        self._keys = self._parse(document)
        self._fetched_at = time.monotonic()

    def key_for(self, header: dict[str, Any]) -> Any:
        kid = header.get("kid")
        with self._lock:
            now = time.monotonic()
            if not self._keys or (not self._static and now - self._fetched_at > self.ttl):
                self._refresh()
            if kid is None:
                if len(self._keys) == 1:
                    return next(iter(self._keys.values())).key
                raise KeyResolutionError(
                    ErrorCode.KEY_NOT_FOUND,
                    f"Token has no `kid` but the JWKS publishes {len(self._keys)} keys",
                )
            if kid not in self._keys and now - self._fetched_at > self.min_refresh_interval:
                self._refresh()
            if kid not in self._keys:
                known = ", ".join(sorted(self._keys)) or "none"
                raise KeyResolutionError(
                    ErrorCode.KEY_NOT_FOUND, f"kid `{kid}` is not in the JWKS (published: {known})"
                )
            return self._keys[kid].key

    @property
    def kids(self) -> list[str]:
        return sorted(self._keys)


def ensure_rsa_key(path: Path, bits: int = 2048) -> rsa.RSAPrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey)
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)
    return key


def public_jwk(key: rsa.RSAPrivateKey, kid: str, alg: str = "RS256") -> dict[str, Any]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": alg, "use": "sig"})
    return jwk
