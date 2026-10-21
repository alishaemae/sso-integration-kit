from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .inspect import Profile
from .keys import JWKSKeyProvider, KeyProvider, PublicKeyProvider, SecretKeyProvider

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def expand_env(value: str) -> str:
    return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)


def _expand(obj: Any) -> Any:
    if isinstance(obj, str):
        return expand_env(obj)
    if isinstance(obj, dict):
        return {k: _expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v) for v in obj]
    return obj


class ConfigError(Exception):
    pass


@dataclass
class Branding:
    display_name: str
    primary: str = "#0B6E64"
    on_primary: str = "#FFFFFF"
    monogram: str = ""
    return_url: str = ""
    support_email: str = ""


@dataclass
class Tenant:
    id: str
    name: str
    issuer: str
    audience: str
    algorithms: list[str]
    branding: Branding
    jwks_url: str | None = None
    public_key_path: str | None = None
    secret_env: str | None = None
    secret: bytes | None = None
    required_claims: tuple[str, ...] = ("sub", "iat", "exp", "jti", "iss", "aud")
    leeway: int = 30
    max_age: int = 120
    max_lifetime: int = 300
    webtrader_url: str = ""
    status: str = "live"
    extra: dict[str, Any] = field(default_factory=dict)
    _provider: KeyProvider | None = field(default=None, repr=False)

    @property
    def profile(self) -> Profile:
        return Profile(
            algorithms=self.algorithms,
            issuer=self.issuer,
            audience=self.audience,
            required_claims=self.required_claims,
            leeway=self.leeway,
            max_age=self.max_age,
            max_lifetime=self.max_lifetime,
            strict_transport=True,
            name=self.id,
        )

    @property
    def key_provider(self) -> KeyProvider:
        if self._provider is None:
            if self.jwks_url:
                self._provider = JWKSKeyProvider(self.jwks_url)
            elif self.public_key_path:
                self._provider = PublicKeyProvider(Path(self.public_key_path).read_bytes())
            elif self.secret is not None:
                self._provider = SecretKeyProvider(self.secret, f"shared secret ({self.secret_env or 'inline'})")
            else:
                raise ConfigError(f"Tenant {self.id} has no key configured")
        return self._provider

    @property
    def key_source(self) -> str:
        if self.jwks_url:
            return self.jwks_url
        if self.public_key_path:
            return self.public_key_path
        return f"env:{self.secret_env}" if self.secret_env else "inline secret"

    def webtrader_link(self, symbol: str) -> str:
        return self.webtrader_url.replace("{symbol}", symbol) if self.webtrader_url else ""


def load_tenants(path: str | Path) -> dict[str, Tenant]:
    path = Path(path)
    try:
        data = _expand(tomllib.loads(path.read_text("utf-8")))
    except FileNotFoundError as exc:
        raise ConfigError(f"Tenant config not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc

    tenants: dict[str, Tenant] = {}
    for tenant_id, raw in (data.get("tenants") or {}).items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", tenant_id):
            raise ConfigError(f"Invalid tenant id `{tenant_id}` (lowercase letters, digits, dashes)")
        raw = dict(raw)
        branding = Branding(**raw.pop("branding", {"display_name": raw.get("name", tenant_id)}))
        secret = None
        secret_env = raw.get("secret_env")
        if secret_env:
            value = os.environ.get(secret_env)
            if value is None:
                raise ConfigError(f"Tenant {tenant_id}: environment variable {secret_env} is not set")
            secret = value.encode()
        if "required_claims" in raw:
            raw["required_claims"] = tuple(raw["required_claims"])
        known = {f for f in Tenant.__dataclass_fields__ if not f.startswith("_")}
        extra = {k: v for k, v in raw.items() if k not in known}
        kwargs = {k: v for k, v in raw.items() if k in known}
        tenant = Tenant(id=tenant_id, branding=branding, secret=secret, extra=extra, **kwargs)
        if sum(bool(x) for x in (tenant.jwks_url, tenant.public_key_path, tenant.secret)) != 1:
            raise ConfigError(f"Tenant {tenant_id}: configure exactly one of jwks_url, public_key_path, secret_env")
        tenants[tenant_id] = tenant
    if not tenants:
        raise ConfigError(f"No tenants defined in {path}")
    return tenants
