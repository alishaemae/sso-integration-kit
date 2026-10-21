import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssokit.core.errors import ErrorCode

TARGET = Path(__file__).resolve().parents[1] / "docs" / "troubleshooting.md"

HEADER = """# Troubleshooting launch errors

When a launch fails, the client sees an error page with a **reference** (`LMN-XXXXXX`) and an
**error code** (`SSO-1xx`). The reference finds the exact attempt in the integration console;
the code tells you which rule the token broke.

Fastest path when a broker reports a problem:

1. Ask for the reference from the error page, open `/console/launches/<reference>`.
2. Read the first failed check. It names the claim, the expected value and what was received.
3. If the broker sends you a token from their logs instead, paste it into the console's
   token inspector or run `jwt-doctor check <token> --tenant <broker-id> --at <unix time>`
   to evaluate it as of the moment it was issued.

| Code | Problem | HTTP |
| --- | --- | --- |
"""


def render() -> str:
    rows = "".join(f"| [{e.code}](#{e.code.lower()}) | {e.title} | {e.http_status} |\n" for e in ErrorCode)
    sections = "".join(
        f"\n## {e.code}\n\n**{e.title}**\n\n**Cause.** {e.cause}\n\n**Fix.** {e.fix}\n" for e in ErrorCode
    )
    return HEADER + rows + sections


if __name__ == "__main__":
    content = render()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text("utf-8") != content:
            print(f"{TARGET} is out of date; run python scripts/gen_error_docs.py")
            sys.exit(1)
        print("troubleshooting.md is up to date")
    else:
        TARGET.write_text(content, "utf-8")
        print(f"wrote {TARGET}")
