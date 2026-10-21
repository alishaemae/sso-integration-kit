from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import os
import secrets
from pathlib import Path

import uvicorn

DEV_DEFAULTS = {
    "VEGA_SSO_SECRET": base64.b64encode(secrets.token_bytes(33)).decode(),
    "CONSOLE_PASSWORD": "console",
    "PORTAL_PUBLIC_URL": "http://localhost:8000",
    "BROKER_PUBLIC_URL": "http://localhost:8001",
    "BROKER_INTERNAL_URL": "http://127.0.0.1:8001",
}


def load_dotenv(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("'\"")
        if value:
            os.environ.setdefault(key.strip(), value)


async def _serve() -> None:
    from .broker.app import create_app as broker_app
    from .portal.app import create_app as portal_app

    portal = uvicorn.Server(uvicorn.Config(portal_app(), host="0.0.0.0", port=8000, log_level="warning"))
    broker = uvicorn.Server(uvicorn.Config(broker_app(), host="0.0.0.0", port=8001, log_level="warning"))
    await asyncio.gather(portal.serve(), broker.serve())


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-15s %(message)s", datefmt="%H:%M:%S")
    load_dotenv()
    for key, value in DEV_DEFAULTS.items():
        if not os.environ.get(key):
            os.environ[key] = value
    print(
        "\n  Broker simulator     http://localhost:8001\n"
        "  Analytics portal     http://localhost:8000\n"
        f"  Integration console  http://localhost:8000/console   password: {os.environ['CONSOLE_PASSWORD']}\n"
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_serve())


if __name__ == "__main__":
    main()
