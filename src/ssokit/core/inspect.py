from __future__ import annotations

import base64
import binascii
import json
import time
import urllib.parse
import warnings
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

import jwt

from .errors import ErrorCode
from .keys import HMAC_ALGS, KeyProvider, KeyResolutionError, SecretKeyProvider

MILLISECONDS_THRESHOLD = 100_000_000_000
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "card",
    "card_number",
    "cardnumber",
    "pan",
    "cvv",
    "cvc",
    "ssn",
    "pin",
    "iban",
}
PERSONAL_KEYS = {"email", "phone", "phone_number", "address", "birthdate", "dob"}
TIME_CLAIMS = ("iat", "nbf", "exp")


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    PASS = "pass"


@dataclass
class Finding:
    severity: Severity
    check: str
    title: str
    detail: str = ""
    hint: str = ""
    code: ErrorCode | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["code"] = self.code.code if self.code else None
        return data


@dataclass
class Profile:
    algorithms: list[str] | None = None
    issuer: str | None = None
    audience: str | None = None
    required_claims: tuple[str, ...] = ("sub", "iat", "exp", "jti")
    leeway: int = 30
    max_age: int | None = 120
    max_lifetime: int | None = 300
    strict_transport: bool = False
    name: str = "custom"


@dataclass
class Report:
    raw: str
    token: str
    header: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    segments: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    signature_checked: bool = False
    signature_valid: bool | None = None
    key_description: str | None = None
    now: float = 0.0
    profile: Profile = field(default_factory=Profile)

    def add(
        self,
        severity: Severity,
        check: str,
        title: str,
        detail: str = "",
        hint: str = "",
        code: ErrorCode | None = None,
    ) -> Finding:
        finding = Finding(severity, check, title, detail, hint, code)
        self.findings.append(finding)
        return finding

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    @property
    def errors(self) -> list[Finding]:
        return self.by_severity(Severity.ERROR)

    @property
    def warnings(self) -> list[Finding]:
        return self.by_severity(Severity.WARNING)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def primary_error(self) -> Finding | None:
        return next((f for f in self.errors if f.code is not None), None)

    @property
    def verdict(self) -> str:
        if self.errors:
            return "invalid"
        if not self.signature_checked:
            return "unverified"
        return "valid" if not self.warnings else "valid-with-warnings"

    def timeline(self) -> dict[str, Any]:
        points: dict[str, float] = {}
        for claim in TIME_CLAIMS:
            value = (self.payload or {}).get(claim)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value < MILLISECONDS_THRESHOLD:
                points[claim] = float(value)
        return {"now": self.now, "leeway": self.profile.leeway, "points": points}

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "header": self.header,
            "payload": self.payload,
            "signature": {
                "checked": self.signature_checked,
                "valid": self.signature_valid,
                "key": self.key_description,
            },
            "primary_error": self.primary_error.to_dict() if self.primary_error else None,
            "findings": [f.to_dict() for f in self.findings],
            "timeline": self.timeline(),
            "checked_at": int(self.now),
        }


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def humanize(seconds: float) -> str:
    seconds = int(abs(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def format_ts(value: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(value))


def timezone_offset_hint(delta: float) -> str:
    if abs(delta) < 1800:
        return ""
    half_hours = round(delta / 1800)
    if half_hours and abs(delta - half_hours * 1800) <= 120:
        hours = abs(half_hours) / 2
        label = f"{hours:g} hour" + ("" if hours == 1 else "s")
        return (
            f"The offset is almost exactly {label}. That is the classic sign of a "
            "timestamp built from local time instead of UTC, for example "
            "`strtotime('now', $localDate)` in PHP or `new Date(localString)` in Node."
        )
    return ""


def _secret_variants(secret: bytes) -> list[tuple[str, bytes]]:
    variants: list[tuple[str, bytes]] = []
    stripped = secret.strip()
    if stripped != secret:
        variants.append(("stripped of surrounding whitespace / newline", stripped))
    variants.append(("followed by a trailing newline", secret + b"\n"))
    for label, decoder in (
        ("base64-decoded", base64.b64decode),
        ("base64url-decoded", lambda s: base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))),
        ("hex-decoded", lambda s: binascii.unhexlify(s)),
    ):
        try:
            decoded = decoder(stripped)
        except (binascii.Error, ValueError):
            continue
        if decoded and decoded != secret:
            variants.append((label, decoded))
    variants.append(("base64-encoded", base64.b64encode(stripped)))
    return variants


def _verify_signature(token: str, key: Any, alg: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        jwt.PyJWS().decode(token, key=key, algorithms=[alg])


def _normalize(report: Report) -> str:
    token = report.raw
    strict = report.profile.strict_transport
    sev = Severity.ERROR if strict else Severity.WARNING
    code = ErrorCode.TOKEN_MALFORMED if strict else None

    stripped = token.strip()
    if stripped != token and token:
        report.add(
            Severity.INFO,
            "transport.whitespace",
            "Surrounding whitespace removed",
            "The token had leading or trailing whitespace or a newline.",
            "Trim the value before sending it.",
        )
    token = stripped
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        token = token[1:-1]
        report.add(
            sev,
            "transport.quoted",
            "Token is wrapped in quotes",
            "The value starts and ends with a quote character, usually the result of JSON-encoding a string twice.",
            "Send the raw token string.",
            code,
        )
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
        report.add(
            sev,
            "transport.bearer",
            "Token has a `Bearer ` prefix",
            "`Bearer` belongs in an Authorization header, not in the launch parameter.",
            "Send only the token itself.",
            code,
        )
    if "%2E" in token.upper() or "%3D" in token.upper() or "%2D" in token.upper():
        token = urllib.parse.unquote(token)
        report.add(
            sev,
            "transport.urlencoded",
            "Token is URL-encoded twice",
            "The token contains percent-encoded characters after the request was decoded.",
            "Encode the token once (or let the HTTP client do it), never twice.",
            code,
        )
    return token


def _check_structure(report: Report) -> bool:
    token = report.token
    if not token:
        report.add(
            Severity.ERROR,
            "structure.missing",
            "No token supplied",
            code=ErrorCode.TOKEN_MISSING,
            hint=ErrorCode.TOKEN_MISSING.fix,
        )
        return False
    parts = token.split(".")
    report.segments = parts
    if len(parts) == 5:
        report.add(
            Severity.ERROR,
            "structure.jwe",
            "This is an encrypted token (JWE)",
            "The token has five segments. The launch flow expects a signed token (JWS) with three segments.",
            "Sign the token, do not encrypt it.",
            ErrorCode.TOKEN_MALFORMED,
        )
        return False
    if len(parts) != 3:
        report.add(
            Severity.ERROR,
            "structure.segments",
            f"Expected 3 dot-separated segments, found {len(parts)}",
            "A JWT looks like `header.payload.signature`.",
            "Check that the token was not truncated by a URL length limit, a database column, or a log line.",
            ErrorCode.TOKEN_MALFORMED,
        )
        return False
    bad = [
        name
        for name, seg in zip(("header", "payload", "signature"), parts, strict=True)
        if any(ch in seg for ch in "+/=")
    ]
    if bad:
        report.add(
            Severity.ERROR,
            "structure.base64",
            "Segments use standard base64, not base64url",
            f"Found `+`, `/` or `=` padding in: {', '.join(bad)}.",
            "JWT segments are base64url without padding. Use a JWT library instead of `base64_encode` / `btoa`.",
            ErrorCode.TOKEN_MALFORMED,
        )
        return False
    for name, seg in (("header", parts[0]), ("payload", parts[1])):
        try:
            value = json.loads(b64url_decode(seg))
        except (ValueError, binascii.Error) as exc:
            report.add(
                Severity.ERROR,
                f"structure.{name}",
                f"The {name} is not valid JSON",
                str(exc),
                "Use a JWT library to build the token.",
                ErrorCode.TOKEN_MALFORMED,
            )
            return False
        if not isinstance(value, dict):
            report.add(
                Severity.ERROR, f"structure.{name}", f"The {name} is not a JSON object", code=ErrorCode.TOKEN_MALFORMED
            )
            return False
        setattr(report, name, value)
    report.add(Severity.PASS, "structure", "Well-formed JWS", f"{len(token)} characters, three base64url segments.")
    if len(token) > 4000:
        report.add(
            Severity.WARNING,
            "structure.size",
            "Token is unusually large",
            f"{len(token)} characters. Browsers and proxies may truncate long query strings.",
            "Keep the payload to identifiers; fetch profile data server-side.",
        )
    return True


def _check_header(report: Report) -> bool:
    header = report.header or {}
    alg = header.get("alg")
    allowed = report.profile.algorithms
    if not isinstance(alg, str) or not alg:
        report.add(Severity.ERROR, "header.alg", "Header has no `alg`", code=ErrorCode.ALG_NOT_ALLOWED)
        return False
    if alg.lower() == "none":
        report.add(
            Severity.ERROR,
            "header.alg_none",
            "Unsigned token (`alg: none`)",
            "Anyone can forge an unsigned token. It must always be rejected.",
            "Sign the token with the agreed algorithm and key.",
            ErrorCode.ALG_NOT_ALLOWED,
        )
        return False
    if allowed is not None and alg not in allowed:
        hint = f"Sign with {' or '.join(allowed)} as agreed during onboarding."
        detail = f"`{alg}` is not in the allowed list ({', '.join(allowed)})."
        if alg in HMAC_ALGS and not any(a in HMAC_ALGS for a in allowed):
            detail += (
                " A HMAC token aimed at an RSA/EC verifier is the shape of an "
                "algorithm-confusion attack, or of a broker that never switched to "
                "its private key."
            )
        report.add(
            Severity.ERROR,
            "header.alg_allowed",
            "Signing algorithm not allowed",
            detail,
            hint,
            ErrorCode.ALG_NOT_ALLOWED,
        )
        return False
    if alg not in jwt.algorithms.get_default_algorithms():
        report.add(
            Severity.ERROR, "header.alg_unknown", f"Unsupported algorithm `{alg}`", code=ErrorCode.ALG_NOT_ALLOWED
        )
        return False
    report.add(Severity.PASS, "header.alg", f"Algorithm {alg} is allowed")
    typ = header.get("typ")
    if typ is not None and str(typ).upper() not in {"JWT", "AT+JWT"}:
        report.add(Severity.INFO, "header.typ", f"Unusual `typ`: {typ}", "Most libraries set `typ: JWT`. Not an error.")
    for risky in ("jku", "x5u", "jwk"):
        if risky in header:
            report.add(
                Severity.WARNING,
                f"header.{risky}",
                f"Header contains `{risky}`",
                "The portal ignores keys or key URLs supplied inside the token and only trusts the configured JWKS.",
                f"Remove `{risky}` from the header.",
            )
    return True


def _check_signature(report: Report, provider: KeyProvider | None) -> None:
    header = report.header or {}
    alg = header["alg"]
    if provider is None:
        report.add(
            Severity.INFO,
            "signature.skipped",
            "Signature not verified",
            "No secret or public key was provided, so only the contents were checked.",
            "Pass --secret-env, --public-key or --jwks to verify the signature.",
        )
        return
    report.key_description = provider.description
    is_hmac_alg = alg in HMAC_ALGS
    is_secret = isinstance(provider, SecretKeyProvider)
    if is_hmac_alg != is_secret:
        expected = "a shared secret" if is_hmac_alg else "a public key / JWKS"
        report.add(
            Severity.ERROR,
            "signature.key_type",
            "Key type does not match the algorithm",
            f"`{alg}` needs {expected}, but the verifier has {provider.description}.",
            "Agree on one algorithm and configure the matching key on both sides.",
            ErrorCode.ALG_NOT_ALLOWED,
        )
        return
    try:
        key = provider.key_for(header)
    except KeyResolutionError as exc:
        report.add(Severity.ERROR, "signature.key", exc.code.title, exc.detail, exc.code.fix, exc.code)
        return
    if is_secret and len(provider.secret) < 32:
        report.add(
            Severity.WARNING,
            "signature.short_secret",
            f"Shared secret is only {len(provider.secret)} bytes",
            f"{alg} secrets should be at least 32 random bytes.",
            "Generate one with `openssl rand -base64 48` and store it in a secret manager.",
        )
    report.signature_checked = True
    try:
        _verify_signature(report.token, key, alg)
    except Exception as exc:
        report.signature_valid = False
        if is_secret:
            for label, variant in _secret_variants(provider.secret):
                try:
                    _verify_signature(report.token, variant, alg)
                except Exception:
                    continue
                report.add(
                    Severity.ERROR,
                    "signature.secret_encoding",
                    "Secret encoding mismatch",
                    f"The signature verifies when the configured secret is {label}. Both "
                    "sides hold the same secret but treat its bytes differently.",
                    "Decide whether the secret is used as raw text or decoded bytes and "
                    "use the same form on both sides.",
                    ErrorCode.SIGNATURE_INVALID,
                )
                return
        hint = ErrorCode.SIGNATURE_INVALID.fix
        if not is_secret:
            hint = (
                "The token was signed by a different private key. Check that the broker "
                "signs with the key whose public part is published under this `kid`, "
                "and that staging and production keys are not mixed up."
            )
        report.add(
            Severity.ERROR,
            "signature.invalid",
            "Signature does not match",
            f"Verified with {provider.description}: {exc}",
            hint,
            ErrorCode.SIGNATURE_INVALID,
        )
        return
    report.signature_valid = True
    kid = f" (kid `{header['kid']}`)" if header.get("kid") else ""
    report.add(Severity.PASS, "signature", "Signature verified", f"Using {provider.description}{kid}.")


def _time_claim(report: Report, claim: str) -> float | None:
    payload = report.payload or {}
    if claim not in payload:
        return None
    value = payload[claim]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        shown = json.dumps(value)
        hint = "Use an integer number of seconds since the UNIX epoch."
        if isinstance(value, str) and value.strip().isdigit():
            hint = "Send the number, not a string: cast with `(int)` in PHP or `Number()` in JS."
        elif isinstance(value, str):
            hint += " Dates as strings (ISO 8601) are not valid JWT time claims."
        report.add(
            Severity.ERROR,
            f"claims.{claim}.type",
            f"`{claim}` is not a number",
            f"Got {shown}.",
            hint,
            ErrorCode.CLAIM_INVALID,
        )
        return None
    if value >= MILLISECONDS_THRESHOLD:
        report.add(
            Severity.ERROR,
            f"claims.{claim}.ms",
            f"`{claim}` is in milliseconds",
            f"{value} is milliseconds since the epoch ({format_ts(value / 1000)}).",
            "Divide by 1000: `Math.floor(Date.now() / 1000)` in Node, `time()` in PHP, `int(time.time())` in Python.",
            ErrorCode.CLAIM_INVALID,
        )
        return None
    return float(value)


def _check_claims(report: Report) -> None:
    payload = report.payload or {}
    profile = report.profile
    now = report.now
    leeway = profile.leeway

    missing = [c for c in profile.required_claims if c not in payload]
    for claim in missing:
        report.add(
            Severity.ERROR,
            f"claims.{claim}.missing",
            f"Required claim `{claim}` is missing",
            code=ErrorCode.CLAIM_MISSING,
            hint=_claim_hint(claim),
        )
    if profile.required_claims and not missing:
        report.add(
            Severity.PASS,
            "claims.required",
            "All required claims present",
            ", ".join(f"`{c}`" for c in profile.required_claims),
        )

    if "sub" in payload:
        sub = payload["sub"]
        if not isinstance(sub, str):
            report.add(
                Severity.ERROR,
                "claims.sub.type",
                "`sub` must be a string",
                f"Got {type(sub).__name__} {json.dumps(sub)}. RFC 7519 defines `sub` as a "
                "string, and recent versions of PyJWT and jsonwebtoken reject numbers.",
                "Cast the user ID: `(string) $user->id` in PHP, `String(user.id)` in JS.",
                ErrorCode.CLAIM_INVALID,
            )
        elif not sub.strip():
            report.add(
                Severity.ERROR,
                "claims.sub.empty",
                "`sub` is empty",
                "The portal needs a stable user identifier.",
                "Use the broker's internal client ID, not the email.",
                ErrorCode.CLAIM_INVALID,
            )
    if "jti" in payload and (not isinstance(payload["jti"], str) or len(payload["jti"]) < 8):
        report.add(
            Severity.ERROR,
            "claims.jti",
            "`jti` is too short or not a string",
            f"Got {json.dumps(payload['jti'])}. A guessable `jti` defeats replay protection.",
            "Use a random UUID v4.",
            ErrorCode.CLAIM_INVALID,
        )

    if profile.issuer is not None and "iss" in payload:
        iss = payload["iss"]
        if iss == profile.issuer:
            report.add(Severity.PASS, "claims.iss", "Issuer matches", f"`{iss}`")
        else:
            hint = ErrorCode.ISSUER_MISMATCH.fix
            if isinstance(iss, str) and iss.rstrip("/") == profile.issuer.rstrip("/"):
                hint = "Only the trailing slash differs. Issuers are compared as exact strings."
            elif isinstance(iss, str) and iss.lower() == profile.issuer.lower():
                hint = "Only letter case differs. Issuers are compared as exact strings."
            report.add(
                Severity.ERROR,
                "claims.iss",
                "Issuer mismatch",
                f"Expected `{profile.issuer}`, got `{iss}`.",
                hint,
                ErrorCode.ISSUER_MISMATCH,
            )

    if profile.audience is not None and "aud" in payload:
        aud = payload["aud"]
        audiences = aud if isinstance(aud, list) else [aud]
        if profile.audience in audiences:
            report.add(Severity.PASS, "claims.aud", "Audience matches", f"`{profile.audience}`")
        else:
            report.add(
                Severity.ERROR,
                "claims.aud",
                "Audience mismatch",
                f"Expected `{profile.audience}`, got {json.dumps(aud)}.",
                ErrorCode.AUDIENCE_MISMATCH.fix,
                ErrorCode.AUDIENCE_MISMATCH,
            )

    time_errors_before = len(report.errors)
    times = {claim: _time_claim(report, claim) for claim in TIME_CLAIMS}
    iat, nbf, exp = times["iat"], times["nbf"], times["exp"]

    if iat is not None and exp is not None and exp <= iat:
        report.add(
            Severity.ERROR,
            "claims.exp_before_iat",
            "`exp` is not after `iat`",
            f"exp {format_ts(exp)} vs iat {format_ts(iat)}.",
            "Compute exp as iat plus the lifetime in seconds.",
            ErrorCode.CLAIM_INVALID,
        )
    if exp is not None and exp + leeway < now:
        delta = now - exp
        report.add(
            Severity.ERROR,
            "claims.exp",
            "Token expired",
            f"Expired {humanize(delta)} ago, at {format_ts(exp)} (leeway {leeway}s).",
            timezone_offset_hint(now - (iat if iat is not None else exp)) or ErrorCode.TOKEN_EXPIRED.fix,
            ErrorCode.TOKEN_EXPIRED,
        )
    if nbf is not None and nbf - leeway > now:
        report.add(
            Severity.ERROR,
            "claims.nbf",
            "Token not yet valid",
            f"Valid from {format_ts(nbf)}, {humanize(nbf - now)} from now.",
            ErrorCode.TOKEN_NOT_YET_VALID.fix,
            ErrorCode.TOKEN_NOT_YET_VALID,
        )
    if iat is not None and iat - leeway > now:
        delta = iat - now
        report.add(
            Severity.ERROR,
            "claims.iat_future",
            "`iat` is in the future",
            f"Issued {humanize(delta)} ahead of the verifier's clock ({format_ts(iat)}).",
            timezone_offset_hint(delta) or ErrorCode.IAT_IN_FUTURE.fix,
            ErrorCode.IAT_IN_FUTURE,
        )
    if (
        iat is not None
        and profile.max_age is not None
        and iat <= now + leeway
        and now - iat > profile.max_age + leeway
        and not (exp is not None and exp + leeway < now)
    ):
        report.add(
            Severity.ERROR,
            "claims.max_age",
            "Token was issued too long ago",
            f"Issued {humanize(now - iat)} ago; launch tokens must be used within {profile.max_age}s.",
            ErrorCode.TOKEN_TOO_OLD.fix,
            ErrorCode.TOKEN_TOO_OLD,
        )
    if iat is not None and exp is not None and profile.max_lifetime is not None and exp - iat > profile.max_lifetime:
        report.add(
            Severity.ERROR,
            "claims.lifetime",
            "Token lifetime is too long",
            f"exp - iat = {humanize(exp - iat)}; the maximum is {profile.max_lifetime}s.",
            ErrorCode.LIFETIME_TOO_LONG.fix,
            ErrorCode.LIFETIME_TOO_LONG,
        )
    if len(report.errors) == time_errors_before and (exp is not None or iat is not None):
        remaining = f"expires in {humanize(exp - now)}" if exp is not None else "no `exp`"
        report.add(Severity.PASS, "claims.time", "Within its validity window", f"{remaining}, leeway {leeway}s.")

    for key in payload:
        lowered = key.lower()
        if lowered in SENSITIVE_KEYS:
            report.add(
                Severity.WARNING,
                "payload.sensitive",
                f"Sensitive field `{key}` in payload",
                "JWT payloads are only base64-encoded. Anyone holding the token can read them.",
                "Remove secrets, credentials and card data from the token.",
            )
        elif lowered in PERSONAL_KEYS:
            report.add(
                Severity.INFO,
                "payload.personal",
                f"Personal data `{key}` in payload",
                "Readable by anyone who sees the token (browser history, proxy logs).",
                "Send only what the portal needs to display.",
            )


def _claim_hint(claim: str) -> str:
    return {
        "sub": "Set `sub` to the broker's internal client ID, as a string.",
        "iat": "Set `iat` to the current UNIX time in seconds.",
        "exp": "Set `exp` to `iat` plus the lifetime (60 seconds is a good default).",
        "jti": "Set `jti` to a random UUID v4, new for every launch.",
        "iss": "Set `iss` to the issuer from the integration sheet.",
        "aud": "Set `aud` to the audience from the integration sheet.",
    }.get(claim, ErrorCode.CLAIM_MISSING.fix)


def inspect_token(
    raw: str | None,
    *,
    profile: Profile | None = None,
    key_provider: KeyProvider | None = None,
    now: float | None = None,
) -> Report:
    report = Report(raw=raw or "", token="", profile=profile or Profile(), now=time.time() if now is None else now)
    report.token = _normalize(report)
    if not _check_structure(report):
        return report
    if _check_header(report):
        _check_signature(report, key_provider)
    _check_claims(report)
    if report.ok and report.signature_checked:
        report.add(Severity.PASS, "verdict", "Token passes all checks")
    return report
