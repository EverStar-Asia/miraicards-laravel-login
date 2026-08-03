<?php

namespace EverstarAsia\MiraiCardsLogin\Support;

use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;

final class MobileBrokerConfiguration
{
    public function enabled(): bool
    {
        return config('miraicards.mobile_broker.enabled') === true;
    }

    public function callbackUrl(): string
    {
        $callback = config('miraicards.mobile_broker.callback_url');
        if (! is_string($callback) || ! str_starts_with($callback, 'https://') || ! $this->validUri($callback, true)) {
            throw new MiraiCardsAuthenticationException('The mobile broker callback URL must be a valid HTTPS URL.');
        }

        return $callback;
    }

    public function assertClientRedirect(string $clientId, string $redirectUri): void
    {
        $clients = config('miraicards.mobile_broker.clients', []);
        $registered = is_array($clients) && is_array($clients[$clientId] ?? null)
            ? ($clients[$clientId]['redirect_uris'] ?? null)
            : null;

        if ($clientId === '' || ! is_array($registered) || ! $this->validUri($redirectUri)
            || ! in_array($redirectUri, $registered, true)) {
            throw new MiraiCardsAuthenticationException('The mobile broker client or redirect URI is invalid.');
        }
    }

    /** @return list<string> */
    public function errors(): array
    {
        $errors = [];
        try {
            $this->callbackUrl();
        } catch (MiraiCardsAuthenticationException $exception) {
            $errors[] = $exception->getMessage();
        }

        $clients = config('miraicards.mobile_broker.clients', []);
        if (! is_array($clients) || $clients === []) {
            $errors[] = 'The mobile broker requires at least one client.';

            return $errors;
        }

        foreach ($clients as $clientId => $client) {
            if (! is_string($clientId) || $clientId === '' || ! is_array($client)
                || ! is_array($client['redirect_uris'] ?? null) || $client['redirect_uris'] === []) {
                $errors[] = 'Every mobile broker client must have a non-empty redirect URI list.';

                continue;
            }
            foreach ($client['redirect_uris'] as $uri) {
                if (! is_string($uri) || ! $this->validUri($uri)) {
                    $errors[] = "The mobile broker redirect URI for {$clientId} is invalid.";
                }
            }
        }

        return $errors;
    }

    private function validUri(string $uri, bool $httpsOnly = false): bool
    {
        if ($uri === '' || str_starts_with($uri, '//') || preg_match('/[\x00-\x20]/', $uri)
            || preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:/', $uri) !== 1) {
            return false;
        }

        $parts = parse_url($uri);
        if (! is_array($parts) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($httpsOnly || in_array($scheme, ['http', 'https'], true)) {
            return $scheme === 'https' && is_string($parts['host'] ?? null) && $parts['host'] !== '';
        }

        return $scheme !== '';
    }
}
