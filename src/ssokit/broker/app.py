from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from ..core.keys import ensure_rsa_key, public_jwk
from ..core.tenants import _expand
from . import scenarios as sc

log = logging.getLogger("ssokit.broker")
HERE = Path(__file__).parent
DEFAULT_CONFIG = Path(os.environ.get("SSOKIT_BROKERS", "config/brokers.toml"))


@dataclass
class DemoUser:
    sub: str
    email: str
    name: str
    account: str
    balance: float
    equity: float
    leverage: str
    password: str = "demo"


USERS: dict[str, list[DemoUser]] = {
    "orbis": [DemoUser("100482", "mila.novak@example.com", "Mila Novak", "OC-7731450", 12480.55, 12902.10, "1:100")],
    "vega": [DemoUser("58201", "daniel.reyes@example.com", "Daniel Reyes", "VM-220981", 3150.00, 3087.42, "1:30")],
}


@dataclass
class Broker:
    id: str
    name: str
    tagline: str
    issuer: str
    audience: str
    algorithm: str
    portal_launch_url: str
    launch_method: str = "post"
    token_lifetime: int = 60
    kid: str | None = None
    private_key_path: str | None = None
    secret_env: str | None = None
    theme: dict[str, str] = field(default_factory=dict)
    _key: Any = None

    @property
    def signing_key(self) -> Any:
        if self._key is None:
            if self.algorithm.startswith("HS"):
                value = os.environ.get(self.secret_env or "")
                if not value:
                    raise RuntimeError(f"{self.secret_env} is not set for broker {self.id}")
                self._key = value.encode()
            else:
                self._key = ensure_rsa_key(Path(self.private_key_path or f"keys/{self.id}.pem"))
        return self._key

    @property
    def users(self) -> list[DemoUser]:
        return USERS.get(self.id, [])


def load_brokers(path: Path) -> dict[str, Broker]:
    data = _expand(tomllib.loads(path.read_text("utf-8")))
    return {bid: Broker(id=bid, **raw) for bid, raw in data["brokers"].items()}


def build_claims(broker: Broker, user: DemoUser, now: float) -> dict[str, Any]:
    issued = int(now)
    return {
        "iss": broker.issuer,
        "aud": broker.audience,
        "sub": user.sub,
        "iat": issued,
        "exp": issued + broker.token_lifetime,
        "jti": str(uuid.uuid4()),
        "name": user.name,
        "account_id": user.account,
    }


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encode(build: sc.TokenBuild) -> str:
    if build.algorithm.startswith("HS") and isinstance(build.key, bytes) and build.key.startswith(b"-----"):
        header = {"alg": build.algorithm, "typ": "JWT", **build.headers}
        signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(build.claims).encode())}"
        sig = hmac.new(build.key, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{_b64(sig)}"
    return jwt.encode(build.claims, build.key, algorithm=build.algorithm, headers=build.headers or None)


def create_app(
    brokers: dict[str, Broker] | None = None, *, config_path: Path | None = None, session_secret: str | None = None
) -> FastAPI:
    brokers = brokers if brokers is not None else load_brokers(config_path or DEFAULT_CONFIG)
    app = FastAPI(title="Broker simulator", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret or secrets.token_hex(32),
        session_cookie="broker_session",
        same_site="lax",
    )
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    last_tokens: dict[str, str] = {}
    app.state.brokers = brokers

    def render(request: Request, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    def get_broker(bid: str) -> Broker | None:
        return brokers.get(bid)

    def current_user(request: Request, broker: Broker) -> DemoUser | None:
        sub = request.session.get(f"user:{broker.id}")
        return next((u for u in broker.users if u.sub == sub), None)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return render(request, "index.html", brokers=brokers)

    @app.get("/b/{bid}/.well-known/jwks.json")
    async def jwks(bid: str):
        broker = get_broker(bid)
        if broker is None or not broker.algorithm.startswith(("RS", "ES", "PS")):
            return JSONResponse({"error": "not found"}, status_code=404)
        key = broker.signing_key
        return JSONResponse(
            {"keys": [public_jwk(key, broker.kid or broker.id, broker.algorithm)]},
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/b/{bid}/", response_class=HTMLResponse)
    async def client_area(request: Request, bid: str, scenario: str = "healthy"):
        broker = get_broker(bid)
        if broker is None:
            return RedirectResponse("/", status_code=303)
        user = current_user(request, broker)
        if user is None:
            return RedirectResponse(f"/b/{bid}/login", status_code=303)
        groups: dict[str, list[sc.Scenario]] = {}
        for s in sc.scenarios_for(broker.algorithm):
            groups.setdefault(s.group, []).append(s)
        return render(
            request,
            "client.html",
            broker=broker,
            user=user,
            groups=groups,
            selected=scenario if scenario in sc.BY_ID else "healthy",
            has_last=f"{bid}:{user.sub}" in last_tokens,
        )

    @app.get("/b/{bid}/login", response_class=HTMLResponse)
    async def login_form(request: Request, bid: str):
        broker = get_broker(bid)
        if broker is None:
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", broker=broker, user=broker.users[0], error=None)

    @app.post("/b/{bid}/login", response_class=HTMLResponse)
    async def login(request: Request, bid: str):
        broker = get_broker(bid)
        if broker is None:
            return RedirectResponse("/", status_code=303)
        form = await request.form()
        email = str(form.get("email", "")).strip().lower()
        password = str(form.get("password", ""))
        user = next((u for u in broker.users if u.email == email), None)
        if user is None or not hmac.compare_digest(password, user.password):
            return render(
                request, "login.html", 401, broker=broker, user=broker.users[0], error="Email or password is incorrect."
            )
        request.session[f"user:{bid}"] = user.sub
        return RedirectResponse(f"/b/{bid}/", status_code=303)

    @app.post("/b/{bid}/logout")
    async def logout(request: Request, bid: str):
        request.session.pop(f"user:{bid}", None)
        return RedirectResponse(f"/b/{bid}/login", status_code=303)

    @app.post("/b/{bid}/launch", response_class=HTMLResponse)
    async def launch(request: Request, bid: str):
        broker = get_broker(bid)
        if broker is None:
            return RedirectResponse("/", status_code=303)
        user = current_user(request, broker)
        if user is None:
            return RedirectResponse(f"/b/{bid}/login", status_code=303)
        form = await request.form()
        scenario = sc.BY_ID.get(str(form.get("scenario", "healthy")), sc.BY_ID["healthy"])
        symbol = str(form.get("symbol", ""))[:10]

        now = time.time()
        build = sc.TokenBuild(
            claims=build_claims(broker, user, now),
            headers={"kid": broker.kid} if broker.kid else {},
            algorithm=broker.algorithm,
            key=broker.signing_key,
            public_pem=sc.public_pem(broker.signing_key) if not broker.algorithm.startswith("HS") else None,
        )
        scenario.apply(build, now)
        slot = f"{bid}:{user.sub}"
        if build.reuse_last and slot in last_tokens:
            token = last_tokens[slot]
        else:
            token = encode(build)
            if build.reuse_last:
                last_tokens[slot] = token
        if scenario.id == "healthy":
            last_tokens[slot] = token
        token = build.prefix + token
        log.info("launch broker=%s sub=%s scenario=%s", bid, user.sub, scenario.id)

        if broker.launch_method == "get":
            sep = "&" if "?" in broker.portal_launch_url else "?"
            url = f"{broker.portal_launch_url}{sep}token={token}" + (f"&symbol={symbol}" if symbol else "")
            return RedirectResponse(url, status_code=303)
        return render(
            request, "launching.html", broker=broker, token=token, symbol=symbol, action=broker.portal_launch_url
        )

    @app.get("/b/{bid}/webtrader", response_class=HTMLResponse)
    async def webtrader(request: Request, bid: str, symbol: str = "EURUSD"):
        broker = get_broker(bid)
        if broker is None:
            return RedirectResponse("/", status_code=303)
        return render(
            request, "webtrader.html", broker=broker, symbol=symbol[:10].upper(), user=current_user(request, broker)
        )

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "brokers": list(brokers)}

    return app


def get_app() -> FastAPI:
    return create_app()
