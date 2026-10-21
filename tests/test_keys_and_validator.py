import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ssokit.core import ErrorCode, InMemoryReplayStore, JWKSKeyProvider, LaunchValidator
from ssokit.core.keys import KeyResolutionError, public_jwk


def test_jwks_refetches_on_unknown_kid(jwks_doc):
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    docs = [jwks_doc, {"keys": [*jwks_doc["keys"], public_jwk(new, "next")]}]
    calls = []

    def fetch(url):
        calls.append(url)
        return docs[min(len(calls) - 1, 1)]

    provider = JWKSKeyProvider("http://x/jwks", fetcher=fetch, min_refresh_interval=0)
    provider.key_for({"kid": "orbis-test"})
    assert len(calls) == 1
    provider.key_for({"kid": "next"})
    assert len(calls) == 2


def test_jwks_refresh_is_rate_limited(jwks_doc):
    calls = []
    provider = JWKSKeyProvider("http://x/jwks", fetcher=lambda u: calls.append(u) or jwks_doc, min_refresh_interval=60)
    for _ in range(5):
        with pytest.raises(KeyResolutionError) as exc:
            provider.key_for({"kid": "nope"})
        assert exc.value.code is ErrorCode.KEY_NOT_FOUND
    assert len(calls) == 1


def test_jwks_unreachable():
    def boom(url):
        raise OSError("connection refused")

    with pytest.raises(KeyResolutionError) as exc:
        JWKSKeyProvider("http://x/jwks", fetcher=boom).key_for({"kid": "a"})
    assert exc.value.code is ErrorCode.KEYS_UNAVAILABLE


def test_jwks_without_keys():
    with pytest.raises(KeyResolutionError):
        JWKSKeyProvider(document={"keys": []})


def test_missing_kid_with_several_keys(jwks_doc):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = JWKSKeyProvider(document={"keys": [*jwks_doc["keys"], public_jwk(other, "b")]})
    with pytest.raises(KeyResolutionError) as exc:
        provider.key_for({})
    assert exc.value.code is ErrorCode.KEY_NOT_FOUND


def test_launch_validator_accepts_and_blocks_replay(tenants, rs_token):
    validator = LaunchValidator(InMemoryReplayStore())
    token = rs_token()
    first = validator.validate(tenants["orbis"], token)
    assert first.ok and first.subject == "100482"
    second = validator.validate(tenants["orbis"], token)
    assert not second.ok and second.error is ErrorCode.TOKEN_REPLAYED
    assert all(f.check != "verdict" for f in second.report.findings)


def test_replay_scope_is_per_tenant(tenants, rs_token):
    store = InMemoryReplayStore()
    assert store.consume("orbis:abc", 2e9)
    assert store.consume("vega:abc", 2e9)
    assert not store.consume("orbis:abc", 2e9)


def test_replay_entries_expire():
    clock = [1000.0]
    store = InMemoryReplayStore(clock=lambda: clock[0])
    assert store.consume("t:1", 1100)
    clock[0] = 1200
    assert store.consume("t:1", 1300)


def test_unknown_kid_rejected(tenants, rs_token):
    result = LaunchValidator(InMemoryReplayStore()).validate(tenants["orbis"], rs_token(headers={"kid": "old"}))
    assert result.error is ErrorCode.KEY_NOT_FOUND
