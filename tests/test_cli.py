import json
import time

from typer.testing import CliRunner

from ssokit.doctor.cli import app
from tests.conftest import SECRET

runner = CliRunner()


def test_valid_token_exit_zero(hs_token, monkeypatch):
    monkeypatch.setenv("S", SECRET.decode())
    result = runner.invoke(app, ["check", hs_token(), "--secret-env", "S"])
    assert result.exit_code == 0, result.output
    assert "ACCEPTED" in result.output


def test_expired_token_exit_one(hs_token, monkeypatch):
    monkeypatch.setenv("S", SECRET.decode())
    now = int(time.time())
    result = runner.invoke(app, ["check", hs_token(iat=now - 900, exp=now - 840), "--secret-env", "S"])
    assert result.exit_code == 1
    assert "SSO-130" in result.output and "Fix:" in result.output


def test_json_output_and_stdin(hs_token):
    result = runner.invoke(app, ["check", "-", "--json"], input=hs_token())
    data = json.loads(result.output)
    assert data["verdict"] == "unverified" and data["payload"]["sub"] == "100482"


def test_at_option(hs_token):
    result = runner.invoke(app, ["check", hs_token(), "--json", "--at", str(time.time() + 7200)])
    assert json.loads(result.output)["primary_error"]["code"] == "SSO-130"


def test_public_key_file(tmp_path, rsa_key, rs_token):
    from ssokit.broker.scenarios import public_pem

    pem = tmp_path / "pub.pem"
    pem.write_bytes(public_pem(rsa_key))
    result = runner.invoke(app, ["check", rs_token(), "--public-key", str(pem), "--alg", "RS256"])
    assert result.exit_code == 0, result.output


def test_conflicting_key_options(hs_token):
    result = runner.invoke(app, ["check", hs_token(), "--secret", "a", "--jwks", "http://x"])
    assert result.exit_code == 2


def test_explain_and_codes():
    assert "Token issued too long ago" in runner.invoke(app, ["explain", "133"]).output
    assert runner.invoke(app, ["explain", "999"]).exit_code == 2
    assert "SSO-150" in runner.invoke(app, ["codes"]).output


def test_decode(hs_token):
    out = json.loads(runner.invoke(app, ["decode", hs_token()]).output)
    assert out["header"]["alg"] == "HS256"
