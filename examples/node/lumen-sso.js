import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import jwt from "jsonwebtoken";

export function createLumenSso({ launchUrl, issuer, audience, algorithm, signingKey, kid, lifetime = 60 }) {
  function token(clientId, { name, accountId } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: issuer,
      aud: audience,
      sub: String(clientId),
      iat: now,
      exp: now + lifetime,
      jti: randomUUID(),
      ...(name && { name }),
      ...(accountId && { account_id: accountId }),
    };
    return jwt.sign(claims, signingKey, { algorithm, ...(kid && { keyid: kid }) });
  }

  function launchPage(clientId, profile) {
    const escape = (s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
    return `<!doctype html><meta name="referrer" content="no-referrer"><title>Opening Analytics…</title>
<form id="f" method="post" action="${escape(launchUrl)}">
  <input type="hidden" name="token" value="${escape(token(clientId, profile))}">
  <noscript><button type="submit">Continue to Analytics</button></noscript>
</form>
<script>document.getElementById("f").submit();</script>`;
  }

  return { token, launchPage };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const pem = process.env.LUMEN_PRIVATE_KEY;
  const sso = createLumenSso({
    launchUrl: process.env.LUMEN_LAUNCH_URL ?? "http://localhost:8000/sso/vega/launch",
    issuer: process.env.LUMEN_ISSUER ?? "https://my.vegamarkets.example",
    audience: "lumen-analytics",
    algorithm: pem ? "RS256" : "HS256",
    signingKey: pem ? readFileSync(pem) : process.env.LUMEN_SSO_SECRET,
    kid: pem ? process.env.LUMEN_KID : undefined,
  });
  console.log(sso.token(process.argv[2] ?? "58201", { name: "Daniel Reyes", accountId: "VM-220981" }));
}
