<?php

namespace EverstarAsia\MiraiCardsLogin;

use DateTimeImmutable;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use EverstarAsia\MiraiCardsLogin\Support\Jwk;
use EverstarAsia\MiraiCardsLogin\Support\LoginTransactionStore;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;

final class MiraiCardsOidcClient
{
    public function __construct(
        private readonly HttpFactory $http,
        private readonly LoginTransactionStore $transactions,
    ) {}

    public function redirect(Request $request, ?string $intended = null): RedirectResponse
    {
        $this->assertConfiguration();
        $discovery = $this->discovery();
        $verifier = LoginTransactionStore::base64Url(random_bytes(64));
        $nonce = LoginTransactionStore::base64Url(random_bytes(32));
        $callback = (string) config('miraicards.callback_url');
        $binding = $request->session()->get('miraicards.session_binding');
        if (! is_string($binding) || $binding === '') {
            $binding = LoginTransactionStore::base64Url(random_bytes(32));
            $request->session()->put('miraicards.session_binding', $binding);
        }
        $state = $this->transactions->put([
            'nonce' => $nonce,
            'verifier' => $verifier,
            'callback' => $callback,
            'intended' => $this->safeIntended($intended),
        ], $binding);

        $query = http_build_query([
            'client_id' => config('miraicards.client_id'),
            'redirect_uri' => $callback,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes()),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => LoginTransactionStore::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return redirect()->away($discovery['authorization_endpoint'].'?'.$query);
    }

    public function callback(Request $request): MiraiCardsIdentity
    {
        $this->assertConfiguration();
        if (! hash_equals((string) config('miraicards.callback_url'), $request->url())) {
            throw new MiraiCardsAuthenticationException('The callback URI does not match the configured URI.');
        }

        $binding = $request->session()->get('miraicards.session_binding');
        if (! is_string($binding) || $binding === '') {
            throw new MiraiCardsAuthenticationException('The initiating login session is unavailable.');
        }
        $transaction = $this->transactions->consume((string) $request->query('state'), $binding);
        $request->attributes->set('miraicards.intended', $transaction['intended'] ?? null);
        if ($request->filled('error')) {
            throw new MiraiCardsAuthenticationException('MiraiCards denied the login request: '.$request->string('error')->toString());
        }
        $code = $request->string('code')->toString();
        if ($code === '') {
            throw new MiraiCardsAuthenticationException('The authorization response did not contain a code.');
        }

        $discovery = $this->discovery();
        $tokenResponse = $this->request()
            ->withBasicAuth((string) config('miraicards.client_id'), (string) config('miraicards.client_secret'))
            ->asForm()
            ->post($discovery['token_endpoint'], [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $transaction['callback'],
                'code_verifier' => $transaction['verifier'],
            ])
            ->throw()
            ->json();

        if (! is_array($tokenResponse) || ! is_string($tokenResponse['id_token'] ?? null)
            || ! is_string($tokenResponse['access_token'] ?? null)) {
            throw new MiraiCardsAuthenticationException('The provider returned an invalid token response.');
        }

        $token = $this->validateIdToken($tokenResponse['id_token'], (string) $transaction['nonce']);
        $userinfo = $this->request()
            ->withToken($tokenResponse['access_token'])
            ->get($discovery['userinfo_endpoint'])
            ->throw()
            ->json();
        $subject = (string) $token->claims()->get('sub');
        if (! is_array($userinfo) || ! is_string($userinfo['sub'] ?? null) || ! hash_equals($subject, $userinfo['sub'])) {
            throw new MiraiCardsAuthenticationException('The UserInfo subject does not match the ID token.');
        }

        $claims = $token->claims();

        return new MiraiCardsIdentity(
            issuer: (string) $claims->get('iss'),
            subject: $subject,
            name: $this->optionalString($userinfo, 'name'),
            preferredUsername: $this->optionalString($userinfo, 'preferred_username'),
            picture: $this->optionalString($userinfo, 'picture'),
            profile: $this->optionalString($userinfo, 'profile'),
            locale: $this->optionalString($userinfo, 'locale'),
            updatedAt: isset($userinfo['updated_at']) && is_int($userinfo['updated_at']) ? (new DateTimeImmutable)->setTimestamp($userinfo['updated_at']) : null,
            scopes: $this->scopes(),
            issuedAt: $claims->get('iat'),
            expiresAt: $claims->get('exp'),
            authenticatedAt: (new DateTimeImmutable)->setTimestamp((int) $claims->get('auth_time')),
        );
    }

    private function validateIdToken(string $encoded, string $nonce): Plain
    {
        try {
            $token = (new Parser(new JoseEncoder))->parse($encoded);
        } catch (\Throwable $exception) {
            throw new MiraiCardsAuthenticationException('The ID token is malformed.', previous: $exception);
        }
        if (! $token instanceof Plain || $token->headers()->get('alg') !== 'RS256') {
            throw new MiraiCardsAuthenticationException('The ID token must use RS256.');
        }

        $keyId = $token->headers()->get('kid');
        if (! is_string($keyId) || $keyId === '') {
            throw new MiraiCardsAuthenticationException('The ID token has no signing key ID.');
        }
        $jwk = $this->findJwk($keyId, false) ?? $this->findJwk($keyId, true);
        if ($jwk === null || ! (new Sha256)->verify($token->signature()->hash(), $token->payload(), InMemory::plainText(Jwk::rsaPublicPem($jwk)))) {
            throw new MiraiCardsAuthenticationException('The ID token signature is invalid.');
        }

        $claims = $token->claims();
        $issuer = (string) config('miraicards.issuer');
        $audiences = (array) $claims->get('aud', []);
        $clientId = (string) config('miraicards.client_id');
        $now = time();
        $skew = (int) config('miraicards.clock_skew');
        $issuedAt = $claims->get('iat', null);
        $expiresAt = $claims->get('exp', null);

        if ($claims->get('iss', null) !== $issuer
            || ! in_array($clientId, $audiences, true)
            || (count($audiences) > 1 && $claims->get('azp', null) !== $clientId)
            || ! $issuedAt instanceof DateTimeImmutable || $issuedAt->getTimestamp() > $now + $skew
            || ! $expiresAt instanceof DateTimeImmutable || $expiresAt->getTimestamp() <= $now - $skew
            || ! is_string($claims->get('sub', null)) || trim($claims->get('sub')) === ''
            || ! is_string($claims->get('nonce', null)) || ! hash_equals($nonce, $claims->get('nonce'))
            || ! is_int($claims->get('auth_time', null))) {
            throw new MiraiCardsAuthenticationException('The ID token claims are invalid.');
        }

        return $token;
    }

    /** @return array<string, mixed>|null */
    private function findJwk(string $keyId, bool $refresh): ?array
    {
        $keys = $this->jwks($refresh)['keys'] ?? [];

        return collect($keys)->first(fn (mixed $key): bool => is_array($key) && ($key['kid'] ?? null) === $keyId);
    }

    /** @return array<string, mixed> */
    private function discovery(bool $refresh = false): array
    {
        $issuer = rtrim((string) config('miraicards.issuer'), '/');
        $key = 'miraicards:discovery:'.hash('sha256', $issuer);
        if ($refresh) {
            Cache::store(config('miraicards.cache_store'))->forget($key);
        }

        $document = Cache::store(config('miraicards.cache_store'))->remember($key, 3600, fn (): array => $this->request()
            ->get($issuer.'/.well-known/openid-configuration')->throw()->json());
        if (($document['issuer'] ?? null) !== $issuer
            || ($document['code_challenge_methods_supported'] ?? null) !== ['S256']
            || ! in_array('RS256', $document['id_token_signing_alg_values_supported'] ?? [], true)) {
            throw new MiraiCardsAuthenticationException('The provider discovery document is incompatible.');
        }

        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $endpoint) {
            if (! is_string($document[$endpoint] ?? null) || ! str_starts_with($document[$endpoint], 'https://')) {
                throw new MiraiCardsAuthenticationException('The provider discovery document has an invalid endpoint.');
            }
        }

        return $document;
    }

    /** @return array<string, mixed> */
    private function jwks(bool $refresh): array
    {
        $uri = $this->discovery()['jwks_uri'];
        $key = 'miraicards:jwks:'.hash('sha256', $uri);
        if ($refresh) {
            Cache::store(config('miraicards.cache_store'))->forget($key);
        }

        return Cache::store(config('miraicards.cache_store'))->remember($key, 3600, fn (): array => $this->request()->get($uri)->throw()->json());
    }

    private function request(): PendingRequest
    {
        return $this->http
            ->connectTimeout((int) config('miraicards.connect_timeout'))
            ->timeout((int) config('miraicards.request_timeout'))
            ->acceptJson();
    }

    private function assertConfiguration(): void
    {
        foreach (['issuer', 'client_id', 'client_secret', 'callback_url'] as $key) {
            if (! is_string(config('miraicards.'.$key)) || trim((string) config('miraicards.'.$key)) === '') {
                throw new MiraiCardsAuthenticationException("The miraicards.{$key} configuration value is required.");
            }
        }
        if (! str_starts_with((string) config('miraicards.issuer'), 'https://')) {
            throw new MiraiCardsAuthenticationException('The MiraiCards issuer must use HTTPS.');
        }
    }

    private function safeIntended(?string $intended): ?string
    {
        if ($intended === null || ! str_starts_with($intended, '/') || str_starts_with($intended, '//') || preg_match('/[\x00-\x1F]/', $intended)) {
            return null;
        }

        return $intended;
    }

    /** @return list<string> */
    private function scopes(): array
    {
        return collect((array) config('miraicards.scopes'))->map('strval')->prepend('openid')->unique()->values()->all();
    }

    /** @param array<string, mixed> $values */
    private function optionalString(array $values, string $key): ?string
    {
        return is_string($values[$key] ?? null) ? $values[$key] : null;
    }
}
