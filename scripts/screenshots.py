import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

PORTAL = "http://localhost:8000"
BROKER = "http://localhost:8001"
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots")
OUT.mkdir(parents=True, exist_ok=True)


def launch(page, broker: str, scenario: str) -> None:
    page.goto(f"{BROKER}/b/{broker}/")
    page.select_option("#scenario", scenario)
    page.click("text=Launch with this token")
    page.wait_for_load_state("networkidle")


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1360, "height": 900}, device_scale_factor=2)
    page = ctx.new_page()

    page.goto(f"{BROKER}/b/orbis/login")
    page.screenshot(path=OUT / "broker-login.png")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=OUT / "broker-client-area.png", full_page=True)

    page.click("text=Open Analytics")
    page.wait_for_url(f"{PORTAL}/app*")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=OUT / "portal-dashboard.png", full_page=True)
    page.click("text=Trade EURUSD in WebTrader")
    page.wait_for_load_state("networkidle")

    for scenario in ("expired", "timezone", "wrong_key", "replay", "numeric_sub"):
        launch(page, "orbis", scenario)
    page.screenshot(path=OUT / "portal-error.png")

    page.goto(f"{BROKER}/b/vega/login")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    for scenario in ("healthy", "secret_encoding", "millis"):
        launch(page, "vega", scenario)

    page.goto(f"{PORTAL}/console")
    page.fill("#pw", "console")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=OUT / "console-launches.png", full_page=True)

    ref = page.locator("tr:has-text('SSO-132') a.ref").first.inner_text()
    page.goto(f"{PORTAL}/console/launches/{ref}")
    page.screenshot(path=OUT / "console-launch-detail.png", full_page=True)

    ref = page.goto(f"{PORTAL}/console?tenant=vega") and page.locator("tr:has-text('SSO-120') a.ref").first.inner_text()
    page.goto(f"{PORTAL}/console/launches/{ref}")
    page.screenshot(path=OUT / "console-secret-encoding.png", full_page=True)

    page.goto(f"{PORTAL}/console/brokers/orbis")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=OUT / "console-broker.png", full_page=True)

    mobile = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    mpage = mobile.new_page()
    mpage.goto(f"{BROKER}/b/orbis/login")
    mpage.click("button[type=submit]")
    mpage.click("text=Open Analytics")
    mpage.wait_for_url(f"{PORTAL}/app*")
    mpage.wait_for_load_state("networkidle")
    mpage.screenshot(path=OUT / "portal-dashboard-mobile.png", full_page=True)
    browser.close()
print("saved to", OUT)
