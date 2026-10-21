import base64
import json
import time

import jwt
import pytest

from ssokit.core import ErrorCode, Profile, SecretKeyProvider, Severity, inspect_token
from tests.conftest import SECRET, VEGA_ISS

PROFILE = Profile(
    algorithms=["HS256"],
    issuer=VEGA_ISS,
    audience="lumen-analytics",
    required_claims=("sub", "iat", "exp", "jti", "iss", "aud"),
    max_age=120,
    max_lifetime=300,
)
KEY = SecretKeyProvider(SECRET)


def check(token, profile=PROFILE, key=KEY, now=None):
    return inspect_token(token, profile=profile, key_provider=key, now=now)


def primary(report):
    return report.primary_error.code if report.primary_error else None


def test_valid_token_passes(hs_token):
    report = check(hs_token())
    assert report.ok and report.verdict == "valid"
    assert report.signature_valid is True
    assert report.findings[-1].check == "verdict"


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"iat": int(time.time()) - 400, "exp": int(time.time()) - 300}, ErrorCode.TOKEN_EXPIRED),
        ({"exp": int(time.time() * 1000)}, ErrorCode.CLAIM_INVALID),
        ({"exp": str(int(time.time()) + 60)}, ErrorCode.CLAIM_INVALID),
        ({"iat": int(time.time()) + 600, "exp": int(time.time()) + 660}, ErrorCode.IAT_IN_FUTURE),
        ({"iat": int(time.time()) - 600, "exp": int(time.time()) + 30}, ErrorCode.TOKEN_TOO_OLD),
        ({"exp": int(time.time()) + 86400}, ErrorCode.LIFETIME_TOO_LONG),
        ({"nbf": int(time.time()) + 600}, ErrorCode.TOKEN_NOT_YET_VALID),
        ({"sub": None}, ErrorCode.CLAIM_MISSING),
        ({"sub": 100482}, ErrorCode.CLAIM_INVALID),
        ({"sub": " "}, ErrorCode.CLAIM_INVALID),
        ({"jti": "1"}, ErrorCode.CLAIM_INVALID),
        ({"aud": "someone-else"}, ErrorCode.AUDIENCE_MISMATCH),
        ({"iss": VEGA_ISS + "/"}, ErrorCode.ISSUER_MISMATCH),
    ],
)
def test_claim_problems_map_to_codes(hs_token, over, code):
    assert primary(check(hs_token(**over))) is code


def test_audience_list_is_accepted(hs_token):
    assert check(hs_token(aud=["other", "lumen-analytics"])).ok


def test_timezone_offset_is_recognised(hs_token):
    now = int(time.time())
    report = check(hs_token(iat=now + 3 * 3600, exp=now + 3 * 3600 + 60))
    assert primary(report) is ErrorCode.IAT_IN_FUTURE
    assert "3 hours" in report.primary_error.hint and "UTC" in report.primary_error.hint


def test_trailing_slash_hint(hs_token):
    report = check(hs_token(iss=VEGA_ISS + "/"))
    assert "trailing slash" in report.primary_error.hint


def test_milliseconds_hint(hs_token):
    report = check(hs_token(exp=int(time.time() * 1000)))
    assert "milliseconds" in report.primary_error.title


def test_wrong_secret(hs_token):
    report = check(hs_token(key=b"another-secret-that-is-long-enough-123"))
    assert primary(report) is ErrorCode.SIGNATURE_INVALID
    assert report.primary_error.check == "signature.invalid"


@pytest.mark.parametrize(
    ("signing_key", "label"),
    [
        (base64.b64decode(SECRET), "base64-decoded"),
        (SECRET + b"\n", "trailing newline"),
        (base64.b64encode(SECRET), "base64-encoded"),
    ],
)
def test_secret_encoding_mismatch_is_explained(hs_token, signing_key, label):
    report = check(hs_token(key=signing_key))
    assert primary(report) is ErrorCode.SIGNATURE_INVALID
    assert report.primary_error.title == "Secret encoding mismatch"
    assert label in report.primary_error.detail


def test_alg_none_rejected(claims):
    token = jwt.encode(claims(iss=VEGA_ISS), None, algorithm="none")
    assert primary(check(token)) is ErrorCode.ALG_NOT_ALLOWED


def test_disallowed_algorithm(claims):
    token = jwt.encode(claims(iss=VEGA_ISS), SECRET, algorithm="HS512")
    assert primary(check(token)) is ErrorCode.ALG_NOT_ALLOWED


def test_algorithm_confusion_explained(claims):
    token = jwt.encode(claims(), SECRET, algorithm="HS256")
    report = check(token, profile=Profile(algorithms=["RS256"]))
    assert primary(report) is ErrorCode.ALG_NOT_ALLOWED
    assert "algorithm-confusion" in report.primary_error.detail


@pytest.mark.parametrize("garbage", ["abc", "a.b", "a.b.c.d", "!!!.???.###"])
def test_malformed(garbage):
    assert primary(check(garbage)) is ErrorCode.TOKEN_MALFORMED


def test_empty_token_is_missing():
    assert primary(check("")) is ErrorCode.TOKEN_MISSING
    assert primary(check(None)) is ErrorCode.TOKEN_MISSING


def test_standard_base64_detected():
    header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(b'{"sub":"1","x":"\xff\xfe>>"}').decode()
    report = check(f"{header}.{payload}.sig")
    assert primary(report) is ErrorCode.TOKEN_MALFORMED
    assert report.primary_error.check == "structure.base64"


def test_jwe_detected():
    report = check("a.b.c.d.e")
    assert report.primary_error.check == "structure.jwe"


def test_bearer_prefix_lenient_vs_strict(hs_token):
    token = "Bearer " + hs_token()
    assert check(token).ok
    assert any(f.check == "transport.bearer" for f in check(token).warnings)
    strict = Profile(**{**PROFILE.__dict__, "strict_transport": True})
    assert primary(check(token, profile=strict)) is ErrorCode.TOKEN_MALFORMED


def test_quoted_and_double_encoded(hs_token):
    token = hs_token()
    assert check(f'"{token}"').ok
    assert check(token.replace(".", "%2E")).ok


def test_unverified_without_key(hs_token):
    report = inspect_token(hs_token(), profile=PROFILE)
    assert report.verdict == "unverified"
    assert report.signature_checked is False


def test_key_type_mismatch(rs_token):
    report = check(rs_token(), profile=Profile(algorithms=["RS256"]), key=KEY)
    assert primary(report) is ErrorCode.ALG_NOT_ALLOWED


def test_short_secret_warning(claims):
    token = jwt.encode(claims(iss=VEGA_ISS), b"short", algorithm="HS256")
    report = check(token, key=SecretKeyProvider(b"short"))
    assert report.ok
    assert any(f.check == "signature.short_secret" for f in report.warnings)


def test_sensitive_payload_warning(hs_token):
    report = check(hs_token(password="hunter2", email="a@b.c"))
    assert report.ok
    assert any(f.check == "payload.sensitive" for f in report.warnings)
    assert any(f.check == "payload.personal" for f in report.findings if f.severity is Severity.INFO)


def test_evaluate_at_a_point_in_time(hs_token):
    token = hs_token()
    assert check(token, now=time.time() + 3600).primary_error.code is ErrorCode.TOKEN_EXPIRED


def test_report_serialises(hs_token):
    data = check(hs_token(exp=int(time.time()) - 600, iat=int(time.time()) - 660)).to_dict()
    assert data["verdict"] == "invalid"
    assert data["primary_error"]["code"] == "SSO-130"
    assert set(data["timeline"]["points"]) == {"iat", "exp"}
    json.dumps(data)


def test_invalid_time_claim_never_reported_as_within_window(hs_token):
    report = check(hs_token(exp=int(time.time() * 1000)))
    assert not any(f.check == "claims.time" for f in report.findings)
