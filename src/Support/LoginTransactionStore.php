<?php

namespace EverstarAsia\MiraiCardsLogin\Support;

use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Cache;

final class LoginTransactionStore
{
    /** @param array<string, mixed> $transaction */
    public function put(array $transaction, string $sessionBinding): string
    {
        $state = self::base64Url(random_bytes(32));
        $this->cache()->put($this->key($state), [
            ...$transaction,
            'session_hash' => hash('sha256', $sessionBinding),
        ], now()->addMinutes(10));

        return $state;
    }

    /** @return array<string, mixed> */
    public function consume(string $state, string $sessionBinding): array
    {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $state) !== 1) {
            throw new MiraiCardsAuthenticationException('The OpenID Connect state is invalid.');
        }

        $key = $this->key($state);
        $payload = $this->cache()->lock($key.':lock', 10)->block(2, function () use ($key, $sessionBinding): ?array {
            $payload = $this->cache()->get($key);
            if (! is_array($payload)
                || ! isset($payload['session_hash'])
                || ! hash_equals((string) $payload['session_hash'], hash('sha256', $sessionBinding))) {
                return null;
            }

            $this->cache()->forget($key);

            return $payload;
        });

        if (! is_array($payload)) {
            throw new MiraiCardsAuthenticationException('The OpenID Connect state expired or was already used.');
        }

        return $payload;
    }

    private function cache(): Repository
    {
        return Cache::store(config('miraicards.cache_store'));
    }

    private function key(string $state): string
    {
        return 'miraicards:login:'.hash('sha256', $state);
    }

    public static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
