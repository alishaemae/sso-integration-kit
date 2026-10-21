from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class ErrorInfo:
    code: str
    title: str
    cause: str
    fix: str
    http_status: int = 401


class ErrorCode(Enum):
    TOKEN_MISSING = ErrorInfo(
        "SSO-100",
        "Token missing",
        "The launch request reached the portal without a `token` parameter.",
        "Send the JWT in the `token` field of the POST body (or the `token` query "
        "parameter for GET launches). Check that the broker's redirect did not drop it.",
        400,
    )
    TOKEN_MALFORMED = ErrorInfo(
        "SSO-101",
        "Token is not a valid JWT",
        "The value could not be parsed as a compact JWS: wrong number of segments, "
        "invalid base64url, or a header/payload that is not JSON.",
        "Use a maintained JWT library instead of building the token by hand. Make "
        "sure the token is not URL-encoded twice, wrapped in quotes, or prefixed "
        "with `Bearer `.",
        400,
    )
    UNKNOWN_TENANT = ErrorInfo(
        "SSO-102",
        "Unknown broker",
        "The launch URL refers to a broker ID that is not configured on the portal.",
        "Use the launch URL from your integration sheet: `/sso/<broker-id>/launch`. Broker IDs are case sensitive.",
        404,
    )
    ALG_NOT_ALLOWED = ErrorInfo(
        "SSO-110",
        "Signing algorithm not allowed",
        "The `alg` header names an algorithm this broker is not configured for (this includes `none`).",
        "Sign with the algorithm agreed during onboarding. Never accept or emit `alg: none`.",
    )
    KEY_NOT_FOUND = ErrorInfo(
        "SSO-111",
        "Signing key not found",
        "The `kid` header does not match any key published in the broker's JWKS.",
        "Publish the new key in the JWKS before you start signing with it, and set `kid` to the exact key ID.",
    )
    KEYS_UNAVAILABLE = ErrorInfo(
        "SSO-112",
        "Broker keys unavailable",
        "The portal could not download or parse the broker's JWKS document.",
        "Check that the JWKS URL is reachable from the internet, returns HTTP 200 "
        "with `application/json`, and contains a `keys` array.",
        502,
    )
    SIGNATURE_INVALID = ErrorInfo(
        "SSO-120",
        "Signature does not match",
        "The token was signed with a different key or secret than the one configured for this broker.",
        "Compare the secret byte for byte: watch for trailing newlines, base64 vs "
        "raw encoding, and staging vs production keys.",
    )
    TOKEN_EXPIRED = ErrorInfo(
        "SSO-130",
        "Token expired",
        "`exp` is in the past, beyond the allowed clock leeway.",
        "Generate the token when the user clicks the launch button, not when the "
        "page renders. Keep the server clock in sync (NTP).",
    )
    TOKEN_NOT_YET_VALID = ErrorInfo(
        "SSO-131",
        "Token not yet valid",
        "`nbf` is in the future, beyond the allowed clock leeway.",
        "Drop `nbf` or set it to the current time. Check the server clock.",
    )
    IAT_IN_FUTURE = ErrorInfo(
        "SSO-132",
        "Issued-at time is in the future",
        "`iat` is ahead of the portal's clock by more than the leeway. Usually a "
        "drifting server clock or local time used instead of UTC.",
        "Use UNIX time in seconds, UTC (`time()` in PHP, `Math.floor(Date.now()/1000)` "
        "in Node). Sync the server clock.",
    )
    TOKEN_TOO_OLD = ErrorInfo(
        "SSO-133",
        "Token issued too long ago",
        "`iat` is older than the maximum token age, even though `exp` may still be "
        "in the future. Usually a token cached in the page or in a link.",
        "Issue a fresh token for every launch. Do not embed tokens in pre-rendered links or cache them.",
    )
    LIFETIME_TOO_LONG = ErrorInfo(
        "SSO-134",
        "Token lifetime too long",
        "`exp - iat` exceeds the maximum lifetime allowed for launch tokens.",
        "Launch tokens are single-use and short lived. Set `exp` to at most a few minutes after `iat`.",
    )
    CLAIM_MISSING = ErrorInfo(
        "SSO-140",
        "Required claim missing",
        "One of the required claims is absent from the payload.",
        "Include every claim listed in the integration guide (`sub`, `iat`, `exp`, `jti`, `iss`, `aud` by default).",
    )
    CLAIM_INVALID = ErrorInfo(
        "SSO-141",
        "Claim has an invalid value",
        "A claim is present but has the wrong type or format, for example `sub` as a number or `exp` in milliseconds.",
        "`sub` must be a non-empty string. Time claims must be integer UNIX seconds.",
    )
    AUDIENCE_MISMATCH = ErrorInfo(
        "SSO-142",
        "Audience mismatch",
        "`aud` does not contain the audience configured for this broker.",
        "Set `aud` to the exact value from the integration sheet.",
    )
    ISSUER_MISMATCH = ErrorInfo(
        "SSO-143",
        "Issuer mismatch",
        "`iss` differs from the issuer configured for this broker.",
        "Set `iss` to the exact value from the integration sheet, including "
        "scheme and without a trailing slash unless agreed otherwise.",
    )
    TOKEN_REPLAYED = ErrorInfo(
        "SSO-150",
        "Token already used",
        "A token with this `jti` has already been accepted. Launch tokens are single use.",
        "Generate a new token with a random `jti` for every launch. Check for "
        "double submits and browser prefetching of launch links.",
    )

    @property
    def code(self) -> str:
        return self.value.code

    @property
    def title(self) -> str:
        return self.value.title

    @property
    def cause(self) -> str:
        return self.value.cause

    @property
    def fix(self) -> str:
        return self.value.fix

    @property
    def http_status(self) -> int:
        return self.value.http_status

    @classmethod
    def lookup(cls, code: str) -> ErrorCode | None:
        needle = code.strip().upper()
        if not needle.startswith("SSO-"):
            needle = f"SSO-{needle}"
        for item in cls:
            if item.code == needle or item.name == code.strip().upper():
                return item
        return None
