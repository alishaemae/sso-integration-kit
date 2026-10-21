import html
import re

import pytest
from fastapi.testclient import TestClient

from ssokit.broker.app import Broker
from ssokit.broker.app import create_app as broker_app
from ssokit.broker.scenarios import SCENARIOS
from ssokit.portal.app import create_app as portal_app
from tests.conftest import AUD, KID, ORBIS_ISS, SECRET, VEGA_ISS

USERS = {"orbis": "mila.novak@example.com", "vega": "daniel.reyes@example.com"}


@pytest.fixture
def portal(tenants):
    app = portal_app(tenants, console_password="pw", session_secret="s" * 32)
    return TestClient(app, base_url="http://portal.test", follow_redirects=False)


@pytest.fixture
def broker(rsa_key, monkeypatch):
    monkeypatch.setenv("VEGA_SSO_SECRET", SECRET.decode())
    brokers = {
        "orbis": Broker(
            id="orbis",
            name="Orbis Capital",
            tagline="",
            issuer=ORBIS_ISS,
            audience=AUD,
            algorithm="RS256",
            kid=KID,
            portal_launch_url="http://portal.test/sso/orbis/launch",
            launch_method="post",
            theme={"primary": "#0B6E64", "primary_dark": "#07524A", "surface": "#fff", "monogram": "OC"},
            _key=rsa_key,
        ),
        "vega": Broker(
            id="vega",
            name="Vega Markets",
            tagline="",
            issuer=VEGA_ISS,
            audience=AUD,
            algorithm="HS256",
            secret_env="VEGA_SSO_SECRET",
            portal_launch_url="http://portal.test/sso/vega/launch",
            launch_method="get",
            theme={"primary": "#4B3BB8", "primary_dark": "#372A8F", "surface": "#fff", "monogram": "V"},
        ),
    }
    client = TestClient(
        broker_app(brokers, session_secret="b" * 32), base_url="http://broker.test", follow_redirects=False
    )
    for bid, email in USERS.items():
        assert client.post(f"/b/{bid}/login", data={"email": email, "password": "demo"}).status_code == 303
    return client


def launch(broker, portal, bid, scenario, symbol=""):
    r = broker.post(f"/b/{bid}/launch", data={"scenario": scenario, "symbol": symbol})
    if r.status_code == 200:
        token = html.unescape(re.search(r'name="token" value="([^"]*)"', r.text).group(1))
        data = {"token": token, **({"symbol": symbol} if symbol else {})}
        return portal.post(f"/sso/{bid}/launch", data=data)
    assert r.status_code == 303
    return portal.get(r.headers["location"].replace("http://portal.test", ""))


CASES = [(bid, s) for bid, alg in (("orbis", "RS256"), ("vega", "HS256")) for s in SCENARIOS if alg in s.algs]


@pytest.mark.parametrize(("bid", "scenario"), CASES, ids=[f"{b}-{s.id}" for b, s in CASES])
def test_scenario(broker, portal, bid, scenario):
    if scenario.id == "replay":
        assert launch(broker, portal, bid, "healthy").status_code == 303
    response = launch(broker, portal, bid, scenario.id)
    if scenario.expect is None:
        assert response.status_code == 303
        assert response.headers["location"] == "/app"
    else:
        assert response.status_code >= 400
        assert f"<dd>{scenario.expect}</dd>" in response.text
        assert "LMN-" in response.text


def test_successful_launch_opens_branded_dashboard(broker, portal):
    response = launch(broker, portal, "orbis", "healthy", symbol="XAUUSD")
    assert response.headers["location"] == "/app?symbol=XAUUSD"
    page = portal.get("/app?symbol=XAUUSD")
    assert page.status_code == 200
    assert "Orbis Capital" in page.text and "Mila Novak" in page.text and "Gold" in page.text
    assert "--brand: #0B6E64" in page.text


def test_webtrader_deep_link_is_logged(broker, portal, tenants):
    launch(broker, portal, "orbis", "healthy")
    r = portal.get("/app/trade/EURUSD")
    assert r.status_code == 303
    assert r.headers["location"] == "http://broker.test/b/orbis/webtrader?symbol=EURUSD"
    assert portal.app.state.attempts.events("orbis", "webtrader")[0].detail == "EURUSD"


def test_dashboard_requires_session(portal):
    r = portal.get("/app")
    assert r.status_code == 401
    assert "session has ended" in r.text


def test_unknown_tenant(portal):
    r = portal.post("/sso/acme/launch", data={"token": "x.y.z"})
    assert r.status_code == 404 and "SSO-102" in r.text


def test_missing_token(portal):
    r = portal.post("/sso/orbis/launch", data={})
    assert r.status_code == 400 and "SSO-100" in r.text


def test_security_headers(portal):
    r = portal.post("/sso/orbis/launch", data={"token": "a.b.c"})
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_sign_out_returns_to_broker(broker, portal):
    launch(broker, portal, "orbis", "healthy")
    r = portal.post("/app/sign-out")
    assert r.headers["location"] == "http://broker/b/orbis/"
    assert portal.get("/app").status_code == 401


def test_jwks_endpoint(broker):
    doc = broker.get("/b/orbis/.well-known/jwks.json").json()
    assert doc["keys"][0]["kid"] == KID and "d" not in doc["keys"][0]
    assert broker.get("/b/vega/.well-known/jwks.json").status_code == 404


def test_console_requires_login(portal):
    r = portal.get("/console")
    assert r.status_code == 303 and r.headers["location"].startswith("/console/login")
    assert portal.post("/console/login", data={"password": "wrong"}).status_code == 401


def test_console_shows_launches_and_detail(broker, portal):
    launch(broker, portal, "orbis", "healthy")
    launch(broker, portal, "orbis", "timezone")
    portal.post("/console/login", data={"password": "pw", "next": "/console"})
    overview = portal.get("/console")
    assert overview.status_code == 200 and "SSO-132" in overview.text
    row = re.compile(
        r'/console/launches/(LMN-\w+)">LMN-\w+</a></td>\s*<td>Orbis Capital</td>\s*'
        r'<td><span class="result result--fail">'
    )
    ref = row.search(overview.text).group(1)
    detail = portal.get(f"/console/launches/{ref}")
    assert "3 hours" in detail.text and "Validity window" in detail.text
    data = portal.get("/console/launches.json").json()
    assert {row["code"] for row in data} == {None, "SSO-132"}


def test_console_session_survives_a_test_launch(broker, portal):
    portal.post("/console/login", data={"password": "pw"})
    launch(broker, portal, "orbis", "healthy")
    assert portal.get("/console").status_code == 200


def test_console_inspector_and_broker_page(portal, rs_token):
    portal.post("/console/login", data={"password": "pw"})
    page = portal.post("/console/inspect", data={"token": rs_token(aud="nope"), "tenant": "orbis"})
    assert "SSO-142" in page.text
    sheet = portal.get("/console/brokers/orbis")
    assert sheet.status_code == 200 and "Launch readiness" in sheet.text and "/sso/orbis/launch" in sheet.text
