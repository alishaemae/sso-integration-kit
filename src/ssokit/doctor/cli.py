from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.errors import ErrorCode
from ..core.inspect import (
    MILLISECONDS_THRESHOLD,
    Profile,
    Report,
    Severity,
    format_ts,
    humanize,
    inspect_token,
)
from ..core.keys import JWKSKeyProvider, KeyProvider, PublicKeyProvider, SecretKeyProvider
from ..core.tenants import ConfigError, load_tenants

app = typer.Typer(
    name="jwt-doctor",
    help="Explain why a JWT is or is not accepted, and how to fix it.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

STYLE = {
    Severity.ERROR: ("✗", "bold red"),
    Severity.WARNING: ("!", "bold yellow"),
    Severity.INFO: ("i", "bold blue"),
    Severity.PASS: ("✓", "bold green"),
}
VERDICT = {
    "invalid": ("REJECTED", "white on red"),
    "valid": ("ACCEPTED", "black on green"),
    "valid-with-warnings": ("ACCEPTED WITH WARNINGS", "black on yellow"),
    "unverified": ("DECODED, SIGNATURE NOT CHECKED", "white on blue"),
}
_TICKS = re.compile(r"`([^`]+)`")


def md(text: str) -> str:
    return _TICKS.sub(r"[bold cyan]\1[/]", escape(text or ""))


def _read_token(token: str) -> str:
    if token == "-":
        return sys.stdin.read()
    if token.count(".") >= 2 or len(token) > 255:
        return token
    try:
        path = Path(token)
        if path.is_file():
            return path.read_text("utf-8")
    except OSError:
        pass
    return token


def _fail(message: str) -> None:
    err.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(2)


def _token_text(report: Report, width: int) -> Text:
    styles = ("red", "magenta", "cyan")
    text = Text()
    segments = report.token.split(".") if report.token else []
    for i, seg in enumerate(segments):
        if i:
            text.append(".", style="dim")
        shown = seg if len(seg) <= width else f"{seg[: width // 2 - 2]}…{seg[-(width // 2 - 2) :]}"
        text.append(shown, style=styles[i] if i < 3 else "")
    return text


def _claims_table(title: str, data: dict, colour: str) -> Table:
    table = Table(
        title=title,
        title_justify="left",
        title_style=f"bold {colour}",
        box=box.SIMPLE_HEAD,
        show_header=False,
        pad_edge=False,
        expand=True,
    )
    table.add_column(style=colour, no_wrap=True, width=12)
    table.add_column(overflow="fold")
    for key, value in data.items():
        shown = escape(json.dumps(value, ensure_ascii=False))
        if (
            key in ("iat", "exp", "nbf")
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value < MILLISECONDS_THRESHOLD
        ):
            shown += f"  [dim]{format_ts(value)}[/]"
        table.add_row(key, shown)
    return table


def _timeline(report: Report, width: int = 56) -> Text | None:
    tl = report.timeline()
    points = tl["points"]
    if not points:
        return None
    now = tl["now"]
    values = [*points.values(), now]
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    lo -= span * 0.05
    hi += span * 0.05
    span = hi - lo

    def col(v: float) -> int:
        return max(0, min(width - 1, round((v - lo) / span * (width - 1))))

    bar = ["─"] * width
    start = points.get("nbf", points.get("iat"))
    ok = not any(
        f.code
        in {ErrorCode.TOKEN_EXPIRED, ErrorCode.IAT_IN_FUTURE, ErrorCode.TOKEN_NOT_YET_VALID, ErrorCode.TOKEN_TOO_OLD}
        for f in report.errors
    )
    if start is not None and "exp" in points:
        for i in range(col(start), col(points["exp"]) + 1):
            bar[i] = "━"
    labels = [" "] * width
    for name, value in points.items():
        c = col(value)
        bar[c] = "┃"
        for j, ch in enumerate(name):
            if c + j < width:
                labels[c + j] = ch
    n = col(now)
    pointer = [" "] * width
    pointer[n] = "▲"
    text = Text()
    text.append("".join(labels) + "\n", style="bold")
    text.append("".join(bar) + "\n", style="green" if ok else "red")
    text.append("".join(pointer), style="bold cyan")
    text.append("  now " + format_ts(now)[11:], style="cyan")
    for name in ("iat", "nbf", "exp"):
        if name in points:
            delta = points[name] - now
            rel = "now" if abs(delta) < 1 else (f"in {humanize(delta)}" if delta > 0 else f"{humanize(delta)} ago")
            text.append(f"\n{name:>3}  {format_ts(points[name])}  ({rel})", style="dim")
    return text


def render(report: Report, *, verbose: bool) -> None:
    label, style = VERDICT[report.verdict]
    pe = report.primary_error
    head = Text.from_markup(f"[{style}] {label} [/]")
    if pe and pe.code:
        body = [Text.from_markup(f"[bold red]{pe.code.code}[/]  [bold]{md(pe.title)}[/]")]
        if pe.detail:
            body.append(Text.from_markup(md(pe.detail)))
        if pe.hint:
            body.append(Text.from_markup(f"[bold]Fix:[/] {md(pe.hint)}"))
    elif report.verdict == "unverified":
        body = [
            Text(
                "Contents look right. Pass a key (--secret-env, --public-key, --jwks or --tenant) "
                "to verify the signature."
            )
        ]
    else:
        body = [Text("Signature, claims and validity window are within policy.")]
    console.print(
        Panel(
            Group(head, Text(""), *body),
            title="[bold]jwt-doctor[/]",
            title_align="left",
            border_style="red" if pe else "green",
            padding=(1, 2),
        )
    )

    if report.token and report.header is not None:
        console.print(Text("Token", style="bold"))
        console.print(_token_text(report, 96 if verbose else 48))
        console.print()
    if report.header is not None or report.payload is not None:
        grid = Table.grid(expand=True, padding=(0, 3))
        grid.add_column(ratio=3)
        grid.add_column(ratio=2)
        grid.add_row(
            _claims_table("Payload", report.payload or {}, "magenta"),
            _claims_table("Header", report.header or {}, "red"),
        )
        console.print(grid)
    tl = _timeline(report)
    if tl is not None:
        console.print(Text(f"Validity window (leeway {report.profile.leeway}s)", style="bold"))
        console.print(tl)
        console.print()

    console.print(Text("Checks", style="bold"))
    for f in report.findings:
        if f.severity is Severity.PASS and not verbose and f.check != "verdict":
            continue
        icon, st = STYLE[f.severity]
        code = f" [dim]{f.code.code}[/]" if f.code else ""
        console.print(Text.from_markup(f" [{st}]{icon}[/] {md(f.title)}{code}"))
        if f.detail and (verbose or f.severity is not Severity.PASS):
            console.print(Padding(Text.from_markup(f"[dim]{md(f.detail)}[/]"), (0, 0, 0, 3)))
        if f.hint and f.severity in (Severity.ERROR, Severity.WARNING):
            console.print(Padding(Text.from_markup(f"[bold]Fix:[/] {md(f.hint)}"), (0, 0, 0, 3)))
    passed = len(report.by_severity(Severity.PASS))
    if passed and not verbose:
        console.print(Text(f" ✓ {passed} checks passed (use -v to list them)", style="green dim"))


@app.command(help="Verify a token and explain every problem found. Exit code 1 when it would be rejected.")
def check(
    token: Annotated[str, typer.Argument(help="The JWT, a file containing it, or - to read stdin.")],
    secret_env: Annotated[str | None, typer.Option(help="Env var holding the HS256 secret.")] = None,
    secret_file: Annotated[Path | None, typer.Option(help="File holding the HS256 secret.")] = None,
    secret: Annotated[
        str | None, typer.Option(help="HS256 secret (ends up in shell history; prefer --secret-env).")
    ] = None,
    public_key: Annotated[Path | None, typer.Option(help="PEM public key for RS/ES tokens.")] = None,
    jwks: Annotated[str | None, typer.Option(help="JWKS URL to fetch the verification key from.")] = None,
    tenant: Annotated[str | None, typer.Option(help="Use the portal's settings for this broker.")] = None,
    config: Annotated[Path, typer.Option(help="Portal tenant config used with --tenant.")] = Path(
        os.environ.get("SSOKIT_TENANTS", "config/tenants.toml")
    ),
    alg: Annotated[list[str] | None, typer.Option(help="Allowed algorithm (repeatable).")] = None,
    iss: Annotated[str | None, typer.Option(help="Expected issuer.")] = None,
    aud: Annotated[str | None, typer.Option(help="Expected audience.")] = None,
    require: Annotated[str, typer.Option(help="Comma-separated required claims.")] = "sub,iat,exp",
    leeway: Annotated[int, typer.Option(help="Clock skew tolerance in seconds.")] = 30,
    max_age: Annotated[int | None, typer.Option(help="Max seconds since iat.")] = None,
    max_lifetime: Annotated[int | None, typer.Option(help="Max seconds between iat and exp.")] = None,
    at: Annotated[float | None, typer.Option(help="Evaluate as of this UNIX time instead of now.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show passed checks and full token.")] = False,
) -> None:
    raw = _read_token(token)
    provider: KeyProvider | None = None

    if tenant:
        try:
            tenants = load_tenants(config)
        except ConfigError as exc:
            _fail(str(exc))
        if tenant not in tenants:
            _fail(f"unknown tenant `{tenant}`; configured: {', '.join(tenants)}")
        t = tenants[tenant]
        profile = t.profile
        profile.strict_transport = False
        provider = t.key_provider
    else:
        profile = Profile(
            algorithms=alg or None,
            issuer=iss,
            audience=aud,
            required_claims=tuple(c.strip() for c in require.split(",") if c.strip()),
            leeway=leeway,
            max_age=max_age,
            max_lifetime=max_lifetime,
        )
        sources = [x for x in (secret_env, secret_file, secret, public_key, jwks) if x]
        if len(sources) > 1:
            _fail("use only one of --secret-env, --secret-file, --secret, --public-key, --jwks")
        if secret is not None:
            err.print("[yellow]warning:[/] --secret is stored in your shell history; prefer --secret-env")
            provider = SecretKeyProvider(secret.encode(), "secret from --secret")
        elif secret_env:
            value = os.environ.get(secret_env)
            if value is None:
                _fail(f"environment variable {secret_env} is not set")
            provider = SecretKeyProvider(value.encode(), f"secret from ${secret_env}")
        elif secret_file:
            provider = SecretKeyProvider(secret_file.read_bytes().rstrip(b"\r\n"), f"secret from {secret_file}")
        elif public_key:
            provider = PublicKeyProvider(public_key.read_bytes(), f"public key {public_key}")
        elif jwks:
            provider = JWKSKeyProvider(jwks)

    report = inspect_token(raw, profile=profile, key_provider=provider, now=at)
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        render(report, verbose=verbose)
    raise typer.Exit(0 if report.ok else 1)


@app.command(help="Print header and payload as JSON without any verification.")
def decode(token: Annotated[str, typer.Argument(help="The JWT, a file, or - for stdin.")]) -> None:
    report = inspect_token(_read_token(token), profile=Profile(required_claims=()))
    if report.header is None:
        _fail(report.primary_error.title if report.primary_error else "not a JWT")
    print(json.dumps({"header": report.header, "payload": report.payload}, indent=2, ensure_ascii=False))


@app.command(help="Explain an error code shown on the portal's error page.")
def explain(code: Annotated[str, typer.Argument(help="Error code, e.g. SSO-132 or 132.")]) -> None:
    item = ErrorCode.lookup(code)
    if item is None:
        _fail(f"unknown code {code}; run `jwt-doctor codes` for the list")
    console.print(
        Panel(
            Group(
                Text.from_markup(
                    f"[bold red]{item.code}[/]  [bold]{md(item.title)}[/]  [dim]HTTP {item.http_status}[/]"
                ),
                Text(""),
                Text.from_markup(f"[bold]Cause[/]  {md(item.cause)}"),
                Text.from_markup(f"[bold]Fix[/]    {md(item.fix)}"),
            ),
            border_style="red",
            padding=(1, 2),
        )
    )


@app.command(help="List every error code the portal can return.")
def codes() -> None:
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Code", style="bold red", no_wrap=True)
    table.add_column("Meaning")
    table.add_column("HTTP", justify="right", style="dim")
    for item in ErrorCode:
        table.add_row(item.code, Text.from_markup(md(item.title)), str(item.http_status))
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
