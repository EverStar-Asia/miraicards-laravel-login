<?php

namespace EverstarAsia\MiraiCardsLogin\Support;

use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Cache;

final class MobileLoginTransactionStore
{
    /** @param array<string, mixed> $transaction */
    public function put(array $transaction): string
    {
        $state = LoginTransactionStore::base64Url(random_bytes(32));
        $this->cache()->put($this->key($state), $transaction, now()->addSeconds(
            max(1, (int) config('miraicards.mobile_broker.transaction_ttl', 600)),
        ));

        return $state;
    }

    /** @return array<string, mixed> */
    public function consume(string $state): array
    {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $state) !== 1) {
            throw new MiraiCardsAuthenticationException('The mobile provider state is invalid.');
        }

        $payload = $this->cache()->lock($this->key($state).':lock', 10)->block(2, function () use ($state): ?array {
            $key = $this->key($state);
            $payload = $this->cache()->get($key);
            if (! is_array($payload)) {
                return null;
            }
            $this->cache()->forget($key);

            return $payload;
        });

        if (! is_array($payload)) {
            throw new MiraiCardsAuthenticationException('The mobile provider state expired or was already used.');
        }

        return $payload;
    }

    private function cache(): Repository
    {
        return Cache::store(config('miraicards.cache_store'));
    }

    private function key(string $state): string
    {
        return 'miraicards:mobile:transaction:'.hash('sha256', $state);
    }
}
