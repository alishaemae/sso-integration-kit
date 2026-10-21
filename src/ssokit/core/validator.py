from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .errors import ErrorCode
from .inspect import Finding, Report, Severity, inspect_token
from .replay import ReplayStore
from .tenants import Tenant


@dataclass
class LaunchResult:
    ok: bool
    report: Report
    claims: dict[str, Any] | None = None
    error: ErrorCode | None = None
    error_finding: Finding | None = None

    @property
    def subject(self) -> str | None:
        sub = (self.report.payload or {}).get("sub")
        return str(sub) if sub is not None else None


class LaunchValidator:
    def __init__(self, replay_store: ReplayStore, clock=time.time):
        self.replay_store = replay_store
        self.clock = clock

    def validate(self, tenant: Tenant, token: str | None) -> LaunchResult:
        report = inspect_token(token, profile=tenant.profile, key_provider=tenant.key_provider, now=self.clock())
        primary = report.primary_error
        if primary is not None:
            return LaunchResult(False, report, error=primary.code, error_finding=primary)
        if not report.signature_valid:
            finding = report.add(
                Severity.ERROR, "signature.unverified", "Signature not verified", code=ErrorCode.SIGNATURE_INVALID
            )
            return LaunchResult(False, report, error=finding.code, error_finding=finding)

        payload = report.payload or {}
        jti = payload.get("jti")
        if jti is not None:
            expires_at = float(payload.get("exp", self.clock() + tenant.max_lifetime)) + tenant.leeway
            if not self.replay_store.consume(f"{tenant.id}:{jti}", expires_at):
                finding = report.add(
                    Severity.ERROR,
                    "claims.jti.replay",
                    "Token already used",
                    f"`jti` {jti} was accepted earlier. Launch tokens are single use.",
                    ErrorCode.TOKEN_REPLAYED.fix,
                    ErrorCode.TOKEN_REPLAYED,
                )
                report.findings = [f for f in report.findings if f.check != "verdict"]
                return LaunchResult(False, report, error=finding.code, error_finding=finding)
        return LaunchResult(True, report, claims=payload)
