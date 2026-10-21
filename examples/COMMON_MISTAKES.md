# Common mistakes in broker token code

Each of these has shown up in real integrations. The broker simulator can reproduce every
one of them (Integration lab panel), and the portal names them precisely.

## Time in milliseconds (`SSO-141`)

```js
// wrong
const now = Date.now();
// right
const now = Math.floor(Date.now() / 1000);
```

## Local time instead of UTC (`SSO-132`, "almost exactly 3 hours")

```php
// wrong: depends on the server's timezone and DST
$iat = strtotime(date('Y-m-d H:i:s'), (new DateTime('now', new DateTimeZone('Europe/Moscow')))->getTimestamp());
// right: time() is always UTC seconds
$iat = time();
```

## `sub` as a number (`SSO-141`)

```php
// wrong
'sub' => $client->id,
// right
'sub' => (string) $client->id,
```

Recent PyJWT and jsonwebtoken versions reject numeric `sub`, so this often appears only after
the portal upgrades a library.

## Token created when the page renders (`SSO-130`, `SSO-133`)

The client area page is rendered with a link that already contains the token. The client
reads the dashboard for five minutes, then clicks. Generate the token in the click handler.

## Secret encoding (`SSO-120`, "Secret encoding mismatch")

```php
// broker
JWT::encode($claims, base64_decode(getenv('SSO_SECRET')), 'HS256');
// portal
jwt.decode(token, os.environ["SSO_SECRET"].encode(), ...)
```

Both sides hold the same string; one signs with its decoded bytes. Agree on one form. A
trailing newline from `cat secret.txt` causes the same symptom.

## `noTimestamp` in jsonwebtoken removes your `iat` (`SSO-140`)

```js
// wrong: jsonwebtoken deletes payload.iat when noTimestamp is set,
// even if you set iat yourself
jwt.sign({ ...claims, iat: now }, key, { algorithm: "RS256", noTimestamp: true });
// right: an explicit iat in the payload is kept as is
jwt.sign({ ...claims, iat: now }, key, { algorithm: "RS256" });
```

Found by `jwt-doctor` while writing the Node example in this repository.

## Issuer with a trailing slash (`SSO-143`)

`https://clients.broker.example/` and `https://clients.broker.example` are different
issuers. Copy the value from the integration sheet.

## `Bearer ` in the form field (`SSO-101`)

`Bearer` belongs in an `Authorization` header. The launch field takes the bare token.

## Key rotated before it was published (`SSO-111`)

Publish the new key in the JWKS first, start signing with its `kid` only after the portal's
cache (5 minutes) has seen it.
