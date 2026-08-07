<?php

namespace EverstarAsia\MiraiCardsLogin\Tests;

use DateTimeImmutable;
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsMobileSessionIssuer;
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsUserResolver;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileContext;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileSession;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use EverstarAsia\MiraiCardsLogin\Support\LoginTransactionStore;
use EverstarAsia\MiraiCardsLogin\Support\MobileAuthorizationCodeStore;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class MiraiCardsMobileBrokerTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('miraicards.mobile_broker', [
            'enabled' => true,
            'callback_url' => 'https://client.test/auth/miraicards/mobile/callback',
            'clients' => [
                'mirai-ios' => ['redirect_uris' => ['com.mirai.cards:/oauth/callback']],
            ],
            'middleware' => [],
            'transaction_ttl' => 600,
            'code_ttl' => 60,
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::store('array')->clear();
        Http::preventStrayRequests();
    }

    public function test_mobile_authorize_is_sessionless_and_uses_independent_provider_pkce(): void
    {
        $this->fakeDiscovery();
        $verifier = str_repeat('a', 43);
        $challenge = $this->challenge($verifier);

        $response = $this->get($this->authorizeUrl($challenge, 'app-state').'&ui_locales=zh-CN')->assertRedirect();
        $this->assertNull($response->headers->get('Set-Cookie'));
        parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $providerQuery);

        $this->assertSame('https://client.test/auth/miraicards/mobile/callback', $providerQuery['redirect_uri']);
        $this->assertSame('S256', $providerQuery['code_challenge_method']);
        $this->assertNotSame($challenge, $providerQuery['code_challenge']);
        $this->assertNotSame('app-state', $providerQuery['state']);
        $this->assertNotEmpty($providerQuery['nonce']);
        $this->assertSame('zh-CN', $providerQuery['ui_locales']);
    }

    public function test_mobile_flow_resolves_user_and_returns_custom_session_only_after_code_exchange(): void
    {
        $verifier = str_repeat('b', 43);
        [$providerQuery, $idToken, $jwk] = $this->beginFlow($verifier);
        $this->fakeProviderExchange($idToken, $jwk);
        $calls = (object) ['resolver' => 0, 'issuer' => 0, 'context' => null];
        $this->app->instance(MiraiCardsUserResolver::class, new class($calls) implements MiraiCardsUserResolver
        {
            public function __construct(private object $calls) {}

            public function resolve(MiraiCardsIdentity $identity): Authenticatable
            {
                $this->calls->resolver++;

                return new GenericUser(['id' => 42]);
            }
        });
        $this->app->instance(MiraiCardsMobileSessionIssuer::class, new class($calls) implements MiraiCardsMobileSessionIssuer
        {
            public function __construct(private object $calls) {}

            public function issue(
                Authenticatable $user,
                MiraiCardsIdentity $identity,
                MiraiCardsMobileContext $context,
            ): MiraiCardsMobileSession {
                $this->calls->issuer++;
                $this->calls->context = $context;

                return new MiraiCardsMobileSession([
                    'user' => ['id' => $user->getAuthIdentifier()],
                    'credentials' => ['token' => 'host-session-token'],
                ]);
            }
        });

        $callback = $this->get('https://client.test/auth/miraicards/mobile/callback?'.http_build_query([
            'state' => $providerQuery['state'],
            'code' => 'provider-code',
        ]))->assertRedirect();
        $this->assertSame(0, $calls->resolver);
        parse_str((string) parse_url($callback->headers->get('Location'), PHP_URL_QUERY), $appQuery);
        $this->assertSame('app-state', $appQuery['state']);

        $token = $this->withHeader('User-Agent', 'MiraiCards iOS/1.0')
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.42'])
            ->post('/auth/miraicards/mobile/token', [
                'grant_type' => 'authorization_code',
                'client_id' => 'mirai-ios',
                'redirect_uri' => 'com.mirai.cards:/oauth/callback',
                'code' => $appQuery['code'],
                'code_verifier' => $verifier,
            ]);
        $token->assertOk()->assertExactJson([
            'version' => 1,
            'session' => [
                'user' => ['id' => 42],
                'credentials' => ['token' => 'host-session-token'],
            ],
        ])->assertHeader('Cache-Control', 'no-store, private');
        $this->assertSame(1, $calls->resolver);
        $this->assertSame(1, $calls->issuer);
        $this->assertSame('mirai-ios', $calls->context->clientId);
        $this->assertSame('com.mirai.cards:/oauth/callback', $calls->context->redirectUri);
        $this->assertSame('MiraiCards iOS/1.0', $calls->context->userAgent);
        $this->assertSame('203.0.113.42', $calls->context->ipAddress);

        $this->post('/auth/miraicards/mobile/token', [
            'grant_type' => 'authorization_code',
            'client_id' => 'mirai-ios',
            'redirect_uri' => 'com.mirai.cards:/oauth/callback',
            'code' => $appQuery['code'],
            'code_verifier' => $verifier,
        ])->assertStatus(400)->assertExactJson(['error' => 'invalid_grant']);
        $this->assertSame(1, $calls->issuer);
    }

    public function test_host_session_rejection_returns_access_denied_without_a_session_or_details(): void
    {
        $verifier = str_repeat('g', 43);
        [$providerQuery, $idToken, $jwk] = $this->beginFlow($verifier);
        $this->fakeProviderExchange($idToken, $jwk);
        $calls = (object) ['issuer' => 0];
        $this->app->instance(MiraiCardsUserResolver::class, new class implements MiraiCardsUserResolver
        {
            public function resolve(MiraiCardsIdentity $identity): Authenticatable
            {
                return new GenericUser(['id' => 42]);
            }
        });
        $this->app->instance(MiraiCardsMobileSessionIssuer::class, new class($calls) implements MiraiCardsMobileSessionIssuer
        {
            public function __construct(private object $calls) {}

            public function issue(
                Authenticatable $user,
                MiraiCardsIdentity $identity,
                MiraiCardsMobileContext $context,
            ): MiraiCardsMobileSession {
                $this->calls->issuer++;

                throw new MiraiCardsAuthenticationException('Sensitive host rejection reason.');
            }
        });

        $callback = $this->get('https://client.test/auth/miraicards/mobile/callback?'.http_build_query([
            'state' => $providerQuery['state'],
            'code' => 'provider-code',
        ]))->assertRedirect();
        parse_str((string) parse_url($callback->headers->get('Location'), PHP_URL_QUERY), $appQuery);

        $response = $this->post('/auth/miraicards/mobile/token', [
            'grant_type' => 'authorization_code',
            'client_id' => 'mirai-ios',
            'redirect_uri' => 'com.mirai.cards:/oauth/callback',
            'code' => $appQuery['code'],
            'code_verifier' => $verifier,
        ]);

        $response->assertStatus(403)->assertExactJson(['error' => 'access_denied']);
        $this->assertStringNotContainsString('Sensitive', $response->getContent());
        $this->assertSame(1, $calls->issuer);
    }

    public function test_mobile_authorize_rejects_unregistered_redirects_and_non_s256_pkce(): void
    {
        $this->get($this->authorizeUrl($this->challenge(str_repeat('c', 43)), 'state', 'https://evil.test/callback'))
            ->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
        config()->set('miraicards.mobile_broker.clients.mirai-ios.redirect_uris', [
            'com.mirai.cards:/oauth/callback#fragment',
        ]);
        $this->get($this->authorizeUrl(
            $this->challenge(str_repeat('c', 43)),
            'state',
            'com.mirai.cards:/oauth/callback#fragment',
        ))->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
        config()->set('miraicards.mobile_broker.clients.mirai-ios.redirect_uris', [
            'com.mirai.cards:/oauth/callback',
        ]);

        $url = str_replace(
            'code_challenge_method=S256',
            'code_challenge_method=plain',
            $this->authorizeUrl($this->challenge(str_repeat('c', 43)), 'state'),
        );
        $this->get($url)->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
        Http::assertNothingSent();
    }

    public function test_mobile_authorization_code_is_bound_to_app_pkce_and_burned_on_a_failed_exchange(): void
    {
        $now = new DateTimeImmutable;
        $identity = new MiraiCardsIdentity(
            issuer: 'https://mirai.cards',
            subject: 'subject',
            name: null,
            preferredUsername: null,
            picture: null,
            profile: null,
            locale: null,
            updatedAt: null,
            scopes: ['openid', 'basic_identity'],
            issuedAt: $now,
            expiresAt: $now->modify('+10 minutes'),
            authenticatedAt: $now,
        );
        $correctVerifier = str_repeat('e', 43);
        $store = app(MobileAuthorizationCodeStore::class);
        $code = $store->put(
            $identity,
            'mirai-ios',
            'com.mirai.cards:/oauth/callback',
            $this->challenge($correctVerifier),
        );

        try {
            $store->consume($code, 'mirai-ios', 'com.mirai.cards:/oauth/callback', str_repeat('f', 43));
            $this->fail('The wrong verifier was accepted.');
        } catch (MiraiCardsAuthenticationException $exception) {
            $this->assertSame('The mobile authorization grant is invalid.', $exception->getMessage());
        }

        $this->expectException(MiraiCardsAuthenticationException::class);
        $store->consume($code, 'mirai-ios', 'com.mirai.cards:/oauth/callback', $correctVerifier);
    }

    public function test_provider_denial_preserves_app_state_but_invalid_provider_state_never_redirects(): void
    {
        $this->fakeDiscovery();
        $response = $this->get($this->authorizeUrl($this->challenge(str_repeat('d', 43)), 'return-state'));
        parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $providerQuery);

        $denial = $this->get('https://client.test/auth/miraicards/mobile/callback?'.http_build_query([
            'state' => $providerQuery['state'],
            'error' => 'access_denied',
            'error_description' => 'sensitive provider detail',
        ]))->assertRedirect();
        $this->assertSame(
            'com.mirai.cards:/oauth/callback?error=access_denied&state=return-state',
            $denial->headers->get('Location'),
        );
        $this->assertStringNotContainsString('sensitive', (string) $denial->headers->get('Location'));

        $this->get('https://client.test/auth/miraicards/mobile/callback?state=invalid&code=x')
            ->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
    }

    public function test_doctor_rejects_enabled_mobile_broker_without_host_bindings(): void
    {
        $this->artisan('miraicards:doctor')
            ->expectsOutput('The enabled mobile broker requires MiraiCardsUserResolver and MiraiCardsMobileSessionIssuer bindings.')
            ->assertExitCode(1);
        Http::assertNothingSent();
    }

    /** @return array{0: array<string, string>, 1: string, 2: array<string, string>} */
    private function beginFlow(string $verifier): array
    {
        $this->fakeDiscovery();
        $response = $this->get($this->authorizeUrl($this->challenge($verifier), 'app-state'));
        parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $providerQuery);
        [$privatePem, $publicPem, $jwk] = $this->rsaKey();
        $now = new DateTimeImmutable;
        $jwt = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($privatePem), InMemory::plainText($publicPem));
        $idToken = $jwt->builder()
            ->withHeader('kid', 'mobile-key')
            ->issuedBy('https://mirai.cards')
            ->permittedFor('client-id')
            ->relatedTo('mobile-pairwise-subject')
            ->issuedAt($now)
            ->expiresAt($now->modify('+10 minutes'))
            ->withClaim('auth_time', $now->getTimestamp())
            ->withClaim('nonce', $providerQuery['nonce'])
            ->getToken($jwt->signer(), $jwt->signingKey())
            ->toString();

        return [$providerQuery, $idToken, $jwk];
    }

    /** @param array<string, string> $jwk */
    private function fakeProviderExchange(string $idToken, array $jwk): void
    {
        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery()),
            'https://mirai.cards/.well-known/jwks.json' => Http::response(['keys' => [$jwk]]),
            'https://mirai.cards/oauth/token' => Http::response([
                'access_token' => 'provider-access-token',
                'id_token' => $idToken,
                'scope' => 'openid basic_identity',
            ]),
            'https://mirai.cards/oauth/userinfo' => Http::response([
                'sub' => 'mobile-pairwise-subject',
                'name' => 'Mobile User',
                'email' => 'mobile@example.com',
            ]),
        ]);
    }

    private function fakeDiscovery(): void
    {
        Http::fake(['https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery())]);
    }

    /** @return array<string, mixed> */
    private function discovery(): array
    {
        return [
            'issuer' => 'https://mirai.cards',
            'authorization_endpoint' => 'https://mirai.cards/oauth/authorize',
            'token_endpoint' => 'https://mirai.cards/oauth/token',
            'userinfo_endpoint' => 'https://mirai.cards/oauth/userinfo',
            'jwks_uri' => 'https://mirai.cards/.well-known/jwks.json',
            'code_challenge_methods_supported' => ['plain', 'S256'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'basic_identity'],
        ];
    }

    private function authorizeUrl(string $challenge, string $state, string $redirect = 'com.mirai.cards:/oauth/callback'): string
    {
        return '/auth/miraicards/mobile/authorize?'.http_build_query([
            'client_id' => 'mirai-ios',
            'redirect_uri' => $redirect,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);
    }

    private function challenge(string $verifier): string
    {
        return LoginTransactionStore::base64Url(hash('sha256', $verifier, true));
    }

    /** @return array{0: string, 1: string, 2: array<string, string>} */
    private function rsaKey(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);

        return [$privatePem, $details['key'], [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'mobile-key',
            'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ]];
    }
}
