# Launch checklist

One integration from first call to production. Copy this into the broker's ticket and keep
the owner column honest: most delays come from items nobody owns.

## Discovery call

| Item | Owner |
| --- | --- |
| Who on the broker side owns the integration (name, timezone, channel) | Broker |
| Their stack for the client area (PHP, Node, .NET, CRM vendor) | Broker |
| RS256 with JWKS possible? If not, HS256 and how the secret is stored | Broker |
| Staging environment available, and from which date | Broker |
| Branding: logo, primary colour, display name, support email | Broker |
| WebTrader deep link format, for example `https://webtrader.broker/?symbol={symbol}` | Broker |
| Target go-live date and any freeze periods | Both |

Send the [integration guide](integration-guide.md) and the integration sheet from the
console (`/console/brokers/<id>`) after the call, with a summary of what was agreed and the
next steps with owners and dates.

## Implementation

| Check | How to verify |
| --- | --- |
| JWKS reachable from the internet | Console broker page shows the key IDs |
| First successful launch in staging | "Successful launch received" ticked |
| `sub` is the stable client ID, as a string | Launch detail, Payload panel |
| Token generated on click, not on page render | `iat` is seconds before the launch, never minutes |
| Token travels by POST | Launch detail, Method column |

## End-to-end tests before go-live

These map to the "Launch readiness" checklist in the console, which ticks them automatically
as the attempts arrive.

- [ ] Successful launch with a real staging client
- [ ] Expired token rejected (`SSO-130`), error page links back to the broker
- [ ] Replay rejected (`SSO-150`): back button and resubmit
- [ ] Wrong key rejected (`SSO-120`)
- [ ] Branding correct on the dashboard and on the error page, on mobile too
- [ ] WebTrader deep link opens the right symbol
- [ ] Broker support knows what to do with a reference from the error page

## Go-live

- [ ] Production tenant configured with the production JWKS or secret
- [ ] Status switched from `testing` to `live` in `config/tenants.toml`
- [ ] First production launches watched in the console for the first hour
- [ ] Recurring issues from this integration added to [troubleshooting.md](troubleshooting.md)
      or to the integration guide
