from __future__ import annotations

import html
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import jwt


@dataclass(frozen=True)
class LumenSso:
    launch_url: str
    issuer: str
    audience: str
    algorithm: str
    signing_key: str | bytes
    kid: str | None = None
    lifetime: int = 60

    def token(self, client_id: str | int, *, name: str = "", account_id: str = "") -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": str(client_id),
            "iat": now,
            "exp": now + self.lifetime,
            "jti": str(uuid.uuid4()),
        }
        if name:
            claims["name"] = name
        if account_id:
            claims["account_id"] = account_id
        headers = {"kid": self.kid} if self.kid else None
        return jwt.encode(claims, self.signing_key, algorithm=self.algorithm, headers=headers)

    def launch_page(self, client_id: str | int, **profile: str) -> str:
        token = html.escape(self.token(client_id, **profile))
        return (
            '<!doctype html><meta name="referrer" content="no-referrer"><title>Opening Analytics…</title>'
            f'<form id="f" method="post" action="{html.escape(self.launch_url)}">'
            f'<input type="hidden" name="token" value="{token}">'
            '<noscript><button type="submit">Continue to Analytics</button></noscript></form>'
            '<script>document.getElementById("f").submit();</script>'
        )


if __name__ == "__main__":
    pem = os.environ.get("LUMEN_PRIVATE_KEY")
    sso = LumenSso(
        launch_url=os.environ.get("LUMEN_LAUNCH_URL", "http://localhost:8000/sso/vega/launch"),
        issuer=os.environ.get("LUMEN_ISSUER", "https://my.vegamarkets.example"),
        audience="lumen-analytics",
        algorithm="RS256" if pem else "HS256",
        signing_key=Path(pem).read_bytes() if pem else os.environ["LUMEN_SSO_SECRET"],
        kid=os.environ.get("LUMEN_KID") if pem else None,
    )
    print(sso.token(sys.argv[1] if len(sys.argv) > 1 else "58201", name="Daniel Reyes", account_id="VM-220981"))
