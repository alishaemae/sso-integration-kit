<?php

declare(strict_types=1);

use Firebase\JWT\JWT;

final class LumenSso
{
    public function __construct(
        private readonly string $launchUrl,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly string $algorithm,
        private readonly string $signingKey,
        private readonly ?string $kid = null,
        private readonly int $lifetime = 60,
    ) {
    }

    public function token(string|int $clientId, string $name = '', string $accountId = ''): string
    {
        $now = time();
        $claims = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'sub' => (string) $clientId,
            'iat' => $now,
            'exp' => $now + $this->lifetime,
            'jti' => bin2hex(random_bytes(16)),
        ];
        if ($name !== '') {
            $claims['name'] = $name;
        }
        if ($accountId !== '') {
            $claims['account_id'] = $accountId;
        }

        return JWT::encode($claims, $this->signingKey, $this->algorithm, $this->kid);
    }

    public function launchPage(string|int $clientId, string $name = '', string $accountId = ''): string
    {
        $token = htmlspecialchars($this->token($clientId, $name, $accountId), ENT_QUOTES);
        $action = htmlspecialchars($this->launchUrl, ENT_QUOTES);

        return <<<HTML
            <!doctype html><meta name="referrer" content="no-referrer"><title>Opening Analytics…</title>
            <form id="f" method="post" action="{$action}">
              <input type="hidden" name="token" value="{$token}">
              <noscript><button type="submit">Continue to Analytics</button></noscript>
            </form>
            <script>document.getElementById('f').submit();</script>
            HTML;
    }
}
