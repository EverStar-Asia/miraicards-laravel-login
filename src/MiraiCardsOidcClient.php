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
    /** @var list<string> */
    private const PROTOCOL_SCOPES = ['openid', 'basic_identity'];

    public function __construct(
        private readonly HttpFactory $http,
        private readonly LoginTransactionStore $transactions,
    ) {}

    public function redirect(Request $request, ?string $intended = null): RedirectResponse
    {
        $this->assertConfiguration((string) config('miraicards.callback_url'));
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
            'scopes' => self::PROTOCOL_SCOPES,
        ], $binding);

        return $this->redirectToProvider($callback, $state, $nonce, $verifier);
    }

    public function redirectToProvider(
        string $callback,
        string $state,
        string $nonce,
        string $verifier,
    ): RedirectResponse {
        $this->assertConfiguration($callback);
        $discovery = $this->discovery();
        $query = http_build_query([
            'client_id' => config('miraicards.client_id'),
            'redirect_uri' => $callback,
            'response_type' => 'code',
            'scope' => implode(' ', self::PROTOCOL_SCOPES),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => LoginTransactionStore::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return redirect()->away($discovery['authorization_endpoint'].'?'.$query);
    }

    public function callback(Request $request): MiraiCardsIdentity
    {
        $binding = $request->session()->get('miraicards.session_binding');
        if (! is_string($binding) || $binding === '') {
            throw new MiraiCardsAuthenticationException('The initiating login session is unavailable.');
        }
        $transaction = $this->transactions->consume((string) $request->query('state'), $binding);
        $request->attributes->set('miraicards.intended', $transaction['intended'] ?? null);

        return $this->completeCallback($request, $transaction);
    }

    /** @param array<string, mixed> $transaction */
    public function completeCallback(Request $request, array $transaction): MiraiCardsIdentity
    {
        $callback = $transaction['callback'] ?? null;
        if (! is_string($callback)) {
            throw new MiraiCardsAuthenticationException('The callback transaction is invalid.');
        }
        $this->assertConfiguration($callback);
        if (! hash_equals($callback, $request->url())) {
            throw new MiraiCardsAuthenticationException('The callback URI does not match the configured URI.');
        }

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
        $grantedScopes = $this->grantedScopes($tokenResponse, $transaction);

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
            preferredUsername: null,
            picture: null,
            profile: null,
            locale: null,
            updatedAt: null,
            scopes: $grantedScopes,
            issuedAt: $claims->get('iat'),
            expiresAt: $claims->get('exp'),
            authenticatedAt: (new DateTimeImmutable)->setTimestamp((int) $claims->get('auth_time')),
            email: $this->optionalString($userinfo, 'email'),
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
        $supportedScopes = $document['scopes_supported'] ?? null;
        if (($document['issuer'] ?? null) !== $issuer
            || ! in_array('S256', $document['code_challenge_methods_supported'] ?? [], true)
            || ! in_array('RS256', $document['id_token_signing_alg_values_supported'] ?? [], true)
            || ! is_array($supportedScopes)
            || collect(self::PROTOCOL_SCOPES)->diff($supportedScopes)->isNotEmpty()) {
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

    private function assertConfiguration(string $callback): void
    {
        foreach (['issuer', 'client_id', 'client_secret'] as $key) {
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

    /**
     * @param  array<string, mixed>  $tokenResponse
     * @param  array<string, mixed>  $transaction
     * @return list<string>
     */
    private function grantedScopes(array $tokenResponse, array $transaction): array
    {
        $scope = $tokenResponse['scope'] ?? null;
        if (! is_string($scope)) {
            throw new MiraiCardsAuthenticationException('The provider token response did not include its granted scopes.');
        }

        $grantedScopes = collect(preg_split('/\s+/', trim($scope)) ?: [])
            ->filter()
            ->unique()
            ->values();
        $requestedScopes = collect((array) ($transaction['scopes'] ?? []))->map('strval');

        if ($grantedScopes->diff($requestedScopes)->isNotEmpty()
            || collect(self::PROTOCOL_SCOPES)->diff($grantedScopes)->isNotEmpty()) {
            throw new MiraiCardsAuthenticationException('The provider did not grant the required Basic identity scope.');
        }

        return $grantedScopes->all();
    }

    /** @param array<string, mixed> $values */
    private function optionalString(array $values, string $key): ?string
    {
        return is_string($values[$key] ?? null) ? $values[$key] : null;
    }
}
