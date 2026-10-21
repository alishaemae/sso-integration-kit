# Troubleshooting launch errors

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
| [SSO-100](#sso-100) | Token missing | 400 |
| [SSO-101](#sso-101) | Token is not a valid JWT | 400 |
| [SSO-102](#sso-102) | Unknown broker | 404 |
| [SSO-110](#sso-110) | Signing algorithm not allowed | 401 |
| [SSO-111](#sso-111) | Signing key not found | 401 |
| [SSO-112](#sso-112) | Broker keys unavailable | 502 |
| [SSO-120](#sso-120) | Signature does not match | 401 |
| [SSO-130](#sso-130) | Token expired | 401 |
| [SSO-131](#sso-131) | Token not yet valid | 401 |
| [SSO-132](#sso-132) | Issued-at time is in the future | 401 |
| [SSO-133](#sso-133) | Token issued too long ago | 401 |
| [SSO-134](#sso-134) | Token lifetime too long | 401 |
| [SSO-140](#sso-140) | Required claim missing | 401 |
| [SSO-141](#sso-141) | Claim has an invalid value | 401 |
| [SSO-142](#sso-142) | Audience mismatch | 401 |
| [SSO-143](#sso-143) | Issuer mismatch | 401 |
| [SSO-150](#sso-150) | Token already used | 401 |

## SSO-100

**Token missing**

**Cause.** The launch request reached the portal without a `token` parameter.

**Fix.** Send the JWT in the `token` field of the POST body (or the `token` query parameter for GET launches). Check that the broker's redirect did not drop it.

## SSO-101

**Token is not a valid JWT**

**Cause.** The value could not be parsed as a compact JWS: wrong number of segments, invalid base64url, or a header/payload that is not JSON.

**Fix.** Use a maintained JWT library instead of building the token by hand. Make sure the token is not URL-encoded twice, wrapped in quotes, or prefixed with `Bearer `.

## SSO-102

**Unknown broker**

**Cause.** The launch URL refers to a broker ID that is not configured on the portal.

**Fix.** Use the launch URL from your integration sheet: `/sso/<broker-id>/launch`. Broker IDs are case sensitive.

## SSO-110

**Signing algorithm not allowed**

**Cause.** The `alg` header names an algorithm this broker is not configured for (this includes `none`).

**Fix.** Sign with the algorithm agreed during onboarding. Never accept or emit `alg: none`.

## SSO-111

**Signing key not found**

**Cause.** The `kid` header does not match any key published in the broker's JWKS.

**Fix.** Publish the new key in the JWKS before you start signing with it, and set `kid` to the exact key ID.

## SSO-112

**Broker keys unavailable**

**Cause.** The portal could not download or parse the broker's JWKS document.

**Fix.** Check that the JWKS URL is reachable from the internet, returns HTTP 200 with `application/json`, and contains a `keys` array.

## SSO-120

**Signature does not match**

**Cause.** The token was signed with a different key or secret than the one configured for this broker.

**Fix.** Compare the secret byte for byte: watch for trailing newlines, base64 vs raw encoding, and staging vs production keys.

## SSO-130

**Token expired**

**Cause.** `exp` is in the past, beyond the allowed clock leeway.

**Fix.** Generate the token when the user clicks the launch button, not when the page renders. Keep the server clock in sync (NTP).

## SSO-131

**Token not yet valid**

**Cause.** `nbf` is in the future, beyond the allowed clock leeway.

**Fix.** Drop `nbf` or set it to the current time. Check the server clock.

## SSO-132

**Issued-at time is in the future**

**Cause.** `iat` is ahead of the portal's clock by more than the leeway. Usually a drifting server clock or local time used instead of UTC.

**Fix.** Use UNIX time in seconds, UTC (`time()` in PHP, `Math.floor(Date.now()/1000)` in Node). Sync the server clock.

## SSO-133

**Token issued too long ago**

**Cause.** `iat` is older than the maximum token age, even though `exp` may still be in the future. Usually a token cached in the page or in a link.

**Fix.** Issue a fresh token for every launch. Do not embed tokens in pre-rendered links or cache them.

## SSO-134

**Token lifetime too long**

**Cause.** `exp - iat` exceeds the maximum lifetime allowed for launch tokens.

**Fix.** Launch tokens are single-use and short lived. Set `exp` to at most a few minutes after `iat`.

## SSO-140

**Required claim missing**

**Cause.** One of the required claims is absent from the payload.

**Fix.** Include every claim listed in the integration guide (`sub`, `iat`, `exp`, `jti`, `iss`, `aud` by default).

## SSO-141

**Claim has an invalid value**

**Cause.** A claim is present but has the wrong type or format, for example `sub` as a number or `exp` in milliseconds.

**Fix.** `sub` must be a non-empty string. Time claims must be integer UNIX seconds.

## SSO-142

**Audience mismatch**

**Cause.** `aud` does not contain the audience configured for this broker.

**Fix.** Set `aud` to the exact value from the integration sheet.

## SSO-143

**Issuer mismatch**

**Cause.** `iss` differs from the issuer configured for this broker.

**Fix.** Set `iss` to the exact value from the integration sheet, including scheme and without a trailing slash unless agreed otherwise.

## SSO-150

**Token already used**

**Cause.** A token with this `jti` has already been accepted. Launch tokens are single use.

**Fix.** Generate a new token with a random `jti` for every launch. Check for double submits and browser prefetching of launch links.
