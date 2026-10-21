from __future__ import annotations

import hmac
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.sessions import SessionMiddleware

from ..core import ErrorCode, InMemoryReplayStore, LaunchValidator, inspect_token
from ..core.inspect import Report, Severity, format_ts, humanize
from ..core.keys import JWKSKeyProvider, KeyResolutionError
from ..core.tenants import Branding, Tenant, load_tenants
from . import market
from .attempts import Attempt, AttemptLog, new_ref

log = logging.getLogger("ssokit.portal")
HERE = Path(__file__).parent
DEFAULT_CONFIG = Path(os.environ.get("SSOKIT_TENANTS", "config/tenants.toml"))
SESSION_TTL = 8 * 3600
LUMEN = Branding(display_name="Lumen Analytics", primary="#24406B", monogram="L")


def _ago(ts: float | None) -> str:
    if ts is None:
        return "never"
    delta = time.time() - ts
    return "just now" if delta < 5 else f"{humanize(delta)} ago"


def _hm(value: datetime) -> str:
    return value.strftime("%H:%M")


def _segments(token: str) -> list[str]:
    parts = token.split(".")
    return parts if len(parts) == 3 else [token]


def _timeline(report: dict[str, Any]) -> dict[str, Any] | None:
    tl = report.get("timeline") or {}
    points = dict(tl.get("points") or {})
    if not points:
        return None
    now = tl["now"]
    leeway = tl.get("leeway", 0)
    values = [*points.values(), now]
    lo, hi = min(values) - leeway, max(values) + leeway
    span = (hi - lo) or 1
    pad = span * 0.08
    lo, hi = lo - pad, hi + pad
    span = hi - lo

    def pos(v: float) -> float:
        return round((v - lo) / span * 100, 2)

    window = None
    start = points.get("nbf", points.get("iat"))
    if start is not None and "exp" in points:
        window = {
            "left": pos(start),
            "width": max(pos(points["exp"]) - pos(start), 0.6),
            "grace": max(pos(points["exp"] + leeway) - pos(points["exp"]), 0),
        }
    marks = []
    for name in ("iat", "nbf", "exp"):
        if name in points:
            delta = points[name] - now
            rel = "now" if abs(delta) < 1 else (f"in {humanize(delta)}" if delta > 0 else f"{humanize(delta)} ago")
            marks.append({"name": name, "pos": pos(points[name]), "label": format_ts(points[name])[11:19], "rel": rel})
    marks.sort(key=lambda m: m["pos"])
    for i, mark in enumerate(marks):
        mark["row"] = 1 if i and mark["pos"] - marks[i - 1]["pos"] < 14 and marks[i - 1].get("row") == 0 else 0
    return {"now": pos(now), "window": window, "marks": marks, "now_label": format_ts(now)[11:19]}


_CODE = re.compile(r"`([^`]+)`")


def inline_code(text: str | None) -> Markup:
    return Markup(_CODE.sub(r"<code>\1</code>", str(escape(text or ""))))


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def build_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    env = templates.env
    env.filters["ago"] = _ago
    env.filters["ts"] = lambda v: format_ts(v) if v else "—"
    env.filters["hm"] = _hm
    env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False)
    env.filters["segments"] = _segments
    env.filters["md"] = inline_code
    env.globals["plural"] = plural
    env.globals["timeline"] = _timeline
    env.globals["humanize"] = humanize
    return templates


def create_app(
    tenants: dict[str, Tenant] | None = None,
    *,
    config_path: Path | None = None,
    console_password: str | None = None,
    session_secret: str | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    tenants = tenants if tenants is not None else load_tenants(config_path or DEFAULT_CONFIG)
    console_password = console_password or os.environ.get("CONSOLE_PASSWORD", "")
    if not console_password:
        console_password = secrets.token_urlsafe(9)
        log.warning("CONSOLE_PASSWORD not set; generated one for this run: %s", console_password)
    session_secret = session_secret or os.environ.get("PORTAL_SESSION_SECRET") or secrets.token_hex(32)

    app = FastAPI(title="Lumen Analytics portal", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="lumen_session",
        max_age=SESSION_TTL,
        same_site="lax",
        https_only=os.environ.get("SSOKIT_SECURE_COOKIES", "0") == "1",
    )
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    templates = build_templates()
    templates.env.globals["broker_ids"] = list(tenants)
    attempts = AttemptLog()
    validator = LaunchValidator(InMemoryReplayStore(clock=clock), clock=clock)
    app.state.tenants = tenants
    app.state.attempts = attempts
    app.state.validator = validator

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'self'")
        if request.url.path.startswith(("/sso/", "/console")):
            response.headers["Cache-Control"] = "no-store"
        return response

    def render(request: Request, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status)

    @app.api_route("/sso/{tenant_id}/launch", methods=["GET", "POST"])
    async def launch(request: Request, tenant_id: str):
        started = time.perf_counter()
        token: str | None = request.query_params.get("token")
        symbol = request.query_params.get("symbol")
        if request.method == "POST":
            form = await request.form()
            token = form.get("token") or token
            symbol = form.get("symbol") or symbol
        ref = new_ref()
        tenant = tenants.get(tenant_id)
        client_ip = request.client.host if request.client else "-"
        user_agent = request.headers.get("user-agent", "")[:200]

        if tenant is None:
            report = inspect_token(token, now=clock())
            _record(
                attempts,
                ref,
                tenant_id,
                False,
                ErrorCode.UNKNOWN_TENANT,
                report,
                request,
                client_ip,
                user_agent,
                started,
                token,
            )
            return render(
                request,
                "error.html",
                404,
                brand=LUMEN,
                error=ErrorCode.UNKNOWN_TENANT,
                finding=None,
                ref=ref,
                tenant=None,
            )

        result = await run_in_threadpool(validator.validate, tenant, token)
        _record(
            attempts,
            ref,
            tenant.id,
            result.ok,
            result.error,
            result.report,
            request,
            client_ip,
            user_agent,
            started,
            token,
        )

        if not result.ok:
            assert result.error is not None
            return render(
                request,
                "error.html",
                result.error.http_status,
                brand=tenant.branding,
                error=result.error,
                finding=result.error_finding,
                ref=ref,
                tenant=tenant,
            )

        claims = result.claims or {}
        console = request.session.get("console")
        request.session.clear()
        if console:
            request.session["console"] = True
        request.session.update(
            {
                "tenant": tenant.id,
                "sub": str(claims["sub"]),
                "name": str(claims.get("name") or "")[:80],
                "account": str(claims.get("account_id") or "")[:40],
                "started": int(clock()),
                "ref": ref,
            }
        )
        target = "/app"
        if symbol and symbol in market.INSTRUMENTS:
            target += f"?symbol={symbol}"
        return RedirectResponse(target, status_code=303)

    def current_user(request: Request) -> tuple[Tenant, dict[str, Any]] | None:
        session = request.session
        tenant = tenants.get(session.get("tenant", ""))
        if tenant is None or clock() - session.get("started", 0) > SESSION_TTL:
            return None
        return tenant, dict(session)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        if current_user(request):
            return RedirectResponse("/app", status_code=303)
        return render(request, "home.html", brand=LUMEN, tenants=tenants)

    @app.get("/app", response_class=HTMLResponse)
    async def dashboard(request: Request, symbol: str = "EURUSD"):
        user = current_user(request)
        if user is None:
            return render(request, "signed_out.html", 401, brand=LUMEN)
        tenant, session = user
        if symbol not in market.INSTRUMENTS:
            symbol = "EURUSD"
        snaps = {s: market.snapshot(s) for s in market.INSTRUMENTS}
        focus = snaps[symbol]
        return render(
            request,
            "app.html",
            brand=tenant.branding,
            tenant=tenant,
            session=session,
            focus=focus,
            chart=market.chart_paths(focus.series, 760, 260),
            snaps=snaps,
            sparks={s: market.chart_paths(v.series, 120, 34, 3) for s, v in snaps.items()},
            calendar=market.calendar(),
            now=datetime.now(UTC),
        )

    @app.get("/app/trade/{symbol}")
    async def trade(request: Request, symbol: str):
        user = current_user(request)
        if user is None or symbol not in market.INSTRUMENTS:
            return RedirectResponse("/app", status_code=303)
        tenant, _ = user
        attempts.event(tenant.id, "webtrader", symbol)
        link = tenant.webtrader_link(symbol)
        return RedirectResponse(link or "/app", status_code=303)

    @app.post("/app/sign-out")
    async def sign_out(request: Request):
        user = current_user(request)
        for key in ("tenant", "sub", "name", "account", "started", "ref"):
            request.session.pop(key, None)
        back = user[0].branding.return_url if user and user[0].branding.return_url else "/"
        return RedirectResponse(back, status_code=303)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "tenants": len(tenants), "launches_logged": len(attempts)}

    def console_guard(request: Request) -> RedirectResponse | None:
        if request.session.get("console") is True:
            return None
        return RedirectResponse(f"/console/login?next={request.url.path}", status_code=303)

    @app.get("/console/login", response_class=HTMLResponse)
    async def console_login_form(request: Request, next: str = "/console"):
        return render(request, "console/login.html", next=next, error=None)

    @app.post("/console/login", response_class=HTMLResponse)
    async def console_login(request: Request):
        form = await request.form()
        password = str(form.get("password", ""))
        target = str(form.get("next") or "/console")
        if not target.startswith("/console"):
            target = "/console"
        if hmac.compare_digest(password.encode(), console_password.encode()):
            request.session["console"] = True
            return RedirectResponse(target, status_code=303)
        return render(request, "console/login.html", 401, next=target, error="That password is not correct.")

    @app.post("/console/logout")
    async def console_logout(request: Request):
        request.session.pop("console", None)
        return RedirectResponse("/console/login", status_code=303)

    @app.get("/console", response_class=HTMLResponse)
    async def console_overview(request: Request, tenant: str | None = None, status: str | None = None):
        if (redirect := console_guard(request)) is not None:
            return redirect
        stats = {tid: attempts.stats(tid) for tid in tenants}
        rows = attempts.recent(tenant=tenant, status=status, limit=60)
        return render(
            request,
            "console/overview.html",
            tenants=tenants,
            stats=stats,
            rows=rows,
            f_tenant=tenant,
            f_status=status,
            nav="overview",
        )

    @app.get("/console/launches.json")
    async def console_launches_json(request: Request, tenant: str | None = None, limit: int = 50):
        if request.session.get("console") is not True:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        rows = attempts.recent(tenant=tenant, limit=min(limit, 500))
        return [
            {
                "ref": a.ref,
                "ts": a.ts,
                "tenant": a.tenant_id,
                "ok": a.ok,
                "code": a.code,
                "title": a.title,
                "sub": a.subject,
                "latency_ms": round(a.latency_ms, 1),
            }
            for a in rows
        ]

    @app.get("/console/launches/{ref}", response_class=HTMLResponse)
    async def console_attempt(request: Request, ref: str):
        if (redirect := console_guard(request)) is not None:
            return redirect
        attempt = attempts.get(ref.upper())
        if attempt is None:
            return render(request, "console/not_found.html", 404, ref=ref, nav="overview")
        return render(
            request,
            "console/attempt.html",
            a=attempt,
            tenant=tenants.get(attempt.tenant_id),
            report=attempt.report,
            nav="overview",
        )

    @app.api_route("/console/inspect", methods=["GET", "POST"], response_class=HTMLResponse)
    async def console_inspect(request: Request):
        if (redirect := console_guard(request)) is not None:
            return redirect
        token, tenant_id, report = "", next(iter(tenants)), None
        if request.method == "POST":
            form = await request.form()
            token = str(form.get("token", ""))
            tenant_id = str(form.get("tenant", tenant_id))
            tenant = tenants.get(tenant_id)
            if tenant is None:
                rep = await run_in_threadpool(inspect_token, token, now=clock())
            else:
                profile = tenant.profile
                profile.strict_transport = False
                rep = await run_in_threadpool(_inspect_safe, token, tenant, profile, clock())
            report = rep.to_dict()
        return render(
            request,
            "console/inspect.html",
            tenants=tenants,
            token=token,
            tenant_id=tenant_id,
            report=report,
            nav="inspect",
        )

    @app.get("/console/brokers/{tenant_id}", response_class=HTMLResponse)
    async def console_tenant(request: Request, tenant_id: str):
        if (redirect := console_guard(request)) is not None:
            return redirect
        tenant = tenants.get(tenant_id)
        if tenant is None:
            return render(request, "console/not_found.html", 404, ref=tenant_id, nav="overview")
        key_check = await run_in_threadpool(_key_health, tenant)
        stats = attempts.stats(tenant_id, window=30 * 86400)
        seen = stats["codes_seen"]
        webtrader = attempts.events(tenant_id, "webtrader")
        webtrader_note = (
            f"{webtrader[0].detail}, {_ago(webtrader[0].ts)}"
            if webtrader
            else "Open any instrument in WebTrader from the dashboard."
        )
        checklist = [
            ("Signing keys reachable", key_check["ok"], key_check["detail"]),
            (
                "Successful launch received",
                stats["ok"] > 0,
                f"Last success {_ago(stats['last_ok'])}"
                if stats["ok"]
                else "Ask the broker to launch with a test user.",
            ),
            (
                "Expired token rejected",
                "SSO-130" in seen,
                "Seen SSO-130"
                if "SSO-130" in seen
                else "Send a token with exp in the past and confirm the error page.",
            ),
            (
                "Replay rejected",
                "SSO-150" in seen,
                "Seen SSO-150" if "SSO-150" in seen else "Resubmit a used token (browser back + resend).",
            ),
            (
                "Bad signature rejected",
                "SSO-120" in seen,
                "Seen SSO-120" if "SSO-120" in seen else "Sign with a wrong key or secret once.",
            ),
            ("WebTrader deep link opened", bool(webtrader), webtrader_note),
        ]
        recent = attempts.recent(tenant=tenant_id, limit=12)
        return render(
            request,
            "console/tenant.html",
            tenant=tenant,
            key_check=key_check,
            stats=stats,
            checklist=checklist,
            recent=recent,
            nav="brokers",
            tenants=tenants,
            launch_url=str(request.base_url).rstrip("/") + f"/sso/{tenant.id}/launch",
        )

    return app


def _inspect_safe(token: str, tenant: Tenant, profile, now: float) -> Report:
    return inspect_token(token, profile=profile, key_provider=tenant.key_provider, now=now)


def _key_health(tenant: Tenant) -> dict[str, Any]:
    provider = tenant.key_provider
    if isinstance(provider, JWKSKeyProvider):
        try:
            provider._refresh()
        except KeyResolutionError as exc:
            return {"ok": False, "detail": exc.detail, "kids": []}
        return {"ok": True, "detail": f"{len(provider.kids)} key(s): {', '.join(provider.kids)}", "kids": provider.kids}
    return {"ok": True, "detail": f"Configured from {tenant.key_source}", "kids": []}


def _record(
    attempts: AttemptLog,
    ref: str,
    tenant_id: str,
    ok: bool,
    error: ErrorCode | None,
    report: Report,
    request: Request,
    ip: str,
    ua: str,
    started: float,
    token: str | None,
) -> None:
    latency = (time.perf_counter() - started) * 1000
    data = report.to_dict()
    if error is ErrorCode.UNKNOWN_TENANT:
        data["findings"].insert(
            0,
            {
                "severity": Severity.ERROR.value,
                "check": "tenant",
                "title": error.title,
                "detail": f"No broker `{tenant_id}` is configured.",
                "hint": error.fix,
                "code": error.code,
            },
        )
        data["verdict"] = "invalid"
    sub = (report.payload or {}).get("sub")
    attempts.add(
        Attempt(
            ref=ref,
            ts=time.time(),
            tenant_id=tenant_id,
            ok=ok,
            code=error.code if error else None,
            title="Signed in" if ok else (error.title if error else "Failed"),
            subject=str(sub) if sub is not None else None,
            method=request.method,
            ip=ip,
            user_agent=ua,
            latency_ms=latency,
            report=data,
            segments=report.token.split(".") if report.token else [],
        )
    )
    log.info(
        json.dumps(
            {
                "event": "sso_launch",
                "ref": ref,
                "tenant": tenant_id,
                "ok": ok,
                "code": error.code if error else None,
                "sub": str(sub) if sub is not None else None,
                "kid": (report.header or {}).get("kid"),
                "latency_ms": round(latency, 1),
                "ip": ip,
            }
        )
    )


app = None


def get_app() -> FastAPI:
    return create_app()
