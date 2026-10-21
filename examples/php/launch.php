<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/LumenSso.php';

$rsa = getenv('LUMEN_PRIVATE_KEY');
$sso = new LumenSso(
    launchUrl: getenv('LUMEN_LAUNCH_URL') ?: 'http://localhost:8000/sso/vega/launch',
    issuer: getenv('LUMEN_ISSUER') ?: 'https://my.vegamarkets.example',
    audience: 'lumen-analytics',
    algorithm: $rsa ? 'RS256' : 'HS256',
    signingKey: $rsa ? file_get_contents($rsa) : (string) getenv('LUMEN_SSO_SECRET'),
    kid: $rsa ? (getenv('LUMEN_KID') ?: null) : null,
);

if (PHP_SAPI === 'cli') {
    echo $sso->token($argv[1] ?? '58201', 'Daniel Reyes', 'VM-220981'), PHP_EOL;
    exit(0);
}

header('Cache-Control: no-store');
echo $sso->launchPage($_SESSION['client_id'] ?? '58201');
