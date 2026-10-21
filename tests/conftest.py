import base64
import os
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ssokit.core.keys import JWKSKeyProvider, public_jwk
from ssokit.core.tenants import Branding, Tenant

SECRET = base64.b64encode(os.urandom(33))
KID = "orbis-test"
ORBIS_ISS = "https://clients.orbis-capital.example"
VEGA_ISS = "https://my.vegamarkets.example"
AUD = "lumen-analytics"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks_doc(rsa_key):
    return {"keys": [public_jwk(rsa_key, KID)]}


@pytest.fixture
def tenants(jwks_doc):
    orbis = Tenant(
        id="orbis",
        name="Orbis Capital",
        issuer=ORBIS_ISS,
        audience=AUD,
        algorithms=["RS256"],
        branding=Branding(display_name="Orbis Capital", monogram="OC", return_url="http://broker/b/orbis/"),
        jwks_url="http://broker.test/b/orbis/.well-known/jwks.json",
        webtrader_url="http://broker.test/b/orbis/webtrader?symbol={symbol}",
    )
    orbis._provider = JWKSKeyProvider(document=jwks_doc)
    vega = Tenant(
        id="vega",
        name="Vega Markets",
        issuer=VEGA_ISS,
        audience=AUD,
        algorithms=["HS256"],
        branding=Branding(display_name="Vega Markets", monogram="V"),
        secret=SECRET,
        secret_env="VEGA_SSO_SECRET",
    )
    return {"orbis": orbis, "vega": vega}


@pytest.fixture
def claims():
    def make(**over):
        now = int(time.time())
        data = {"iss": ORBIS_ISS, "aud": AUD, "sub": "100482", "iat": now, "exp": now + 60, "jti": str(uuid.uuid4())}
        data.update(over)
        return {k: v for k, v in data.items() if v is not None}

    return make


@pytest.fixture
def rs_token(rsa_key, claims):
    def make(headers=None, **over):
        return jwt.encode(claims(**over), rsa_key, algorithm="RS256", headers={"kid": KID, **(headers or {})})

    return make


@pytest.fixture
def hs_token(claims):
    def make(key=SECRET, **over):
        over.setdefault("iss", VEGA_ISS)
        return jwt.encode(claims(**over), key, algorithm="HS256")

    return make
