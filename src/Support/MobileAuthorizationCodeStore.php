<?php

namespace EverstarAsia\MiraiCardsLogin\Support;

use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Cache;

final class MobileAuthorizationCodeStore
{
    public function put(MiraiCardsIdentity $identity, string $clientId, string $redirectUri, string $challenge): string
    {
        $code = LoginTransactionStore::base64Url(random_bytes(32));
        $this->cache()->put($this->key($code), compact('identity', 'clientId', 'redirectUri', 'challenge'), now()->addSeconds(
            max(1, (int) config('miraicards.mobile_broker.code_ttl', 60)),
        ));

        return $code;
    }

    public function consume(string $code, string $clientId, string $redirectUri, string $verifier): MiraiCardsIdentity
    {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $code) !== 1
            || preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) !== 1) {
            throw new MiraiCardsAuthenticationException('The mobile authorization grant is invalid.');
        }

        $payload = $this->cache()->lock($this->key($code).':lock', 10)->block(2, function () use ($code): ?array {
            $key = $this->key($code);
            $payload = $this->cache()->get($key);
            if (! is_array($payload)) {
                return null;
            }
            $this->cache()->forget($key);

            return $payload;
        });
        $challenge = LoginTransactionStore::base64Url(hash('sha256', $verifier, true));

        if (! is_array($payload) || ! $payload['identity'] instanceof MiraiCardsIdentity
            || ! hash_equals((string) ($payload['clientId'] ?? ''), $clientId)
            || ! hash_equals((string) ($payload['redirectUri'] ?? ''), $redirectUri)
            || ! hash_equals((string) ($payload['challenge'] ?? ''), $challenge)) {
            throw new MiraiCardsAuthenticationException('The mobile authorization grant is invalid.');
        }

        return $payload['identity'];
    }

    private function cache(): Repository
    {
        return Cache::store(config('miraicards.cache_store'));
    }

    private function key(string $code): string
    {
        return 'miraicards:mobile:code:'.hash('sha256', $code);
    }
}
