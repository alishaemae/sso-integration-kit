import base64
import os
import sys
import time
from pathlib import Path

import jwt
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ssokit.core.inspect import inspect_token
from ssokit.core.keys import SecretKeyProvider
from ssokit.core.tenants import load_tenants
from ssokit.doctor import cli

secret = os.environ.get("VEGA_SSO_SECRET") or base64.b64encode(os.urandom(33)).decode()
tenant = load_tenants(Path(__file__).resolve().parents[1] / "config" / "tenants.toml")["vega"]
now = int(time.time())
token = jwt.encode(
    {
        "iss": tenant.issuer,
        "aud": tenant.audience,
        "sub": "58201",
        "iat": now - 5,
        "exp": now + 55,
        "jti": "9b2d6c1e-4f0a-4c39-8a51-2f6f0e1d7a44",
    },
    base64.b64decode(secret),
    algorithm="HS256",
)
profile = tenant.profile
profile.strict_transport = False
key = SecretKeyProvider(secret.encode(), "secret from $VEGA_SSO_SECRET")
report = inspect_token(token, profile=profile, key_provider=key)

cli.console = Console(record=True, width=100, force_terminal=True)
cli.console.print("[dim]$[/] jwt-doctor check $TOKEN --tenant vega")
cli.render(report, verbose=False)
out = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots") / "jwt-doctor.svg"
out.parent.mkdir(parents=True, exist_ok=True)
cli.console.save_svg(str(out), title="jwt-doctor")
print("wrote", out)
