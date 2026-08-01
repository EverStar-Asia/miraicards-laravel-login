<?php

namespace EverstarAsia\MiraiCardsLogin\Tests;

use DateTimeImmutable;
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsUserResolver;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class MiraiCardsOidcClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery()),
        ]);
    }

    public function test_configuration_uses_permanent_issuer_and_application_callback(): void
    {
        $this->assertSame('https://mirai.cards', config('miraicards.issuer'));
        $this->assertSame(
            'https://client.test/auth/miraicards/callback',
            config('miraicards.callback_url'),
        );
    }

    public function test_login_button_is_registered_as_a_namespaced_anonymous_component(): void
    {
        $html = Blade::render('<x-miraicards::login-button />');

        $this->assertStringContainsString('/auth/miraicards/redirect', $html);
        $this->assertStringContainsString('Sign in with MiraiCards', $html);
    }

    public function test_redirect_uses_pkce_nonce_and_independent_state_for_concurrent_tabs(): void
    {
        $first = $this->get('https://client.test/auth/miraicards/redirect?intended=%2Fevents')->assertRedirect();
        $second = $this->get('https://client.test/auth/miraicards/redirect?intended=https%3A%2F%2Fevil.test')->assertRedirect();
        parse_str((string) parse_url($first->headers->get('Location'), PHP_URL_QUERY), $firstQuery);
        parse_str((string) parse_url($second->headers->get('Location'), PHP_URL_QUERY), $secondQuery);

        $this->assertNotSame($firstQuery['state'], $secondQuery['state']);
        $this->assertSame('S256', $firstQuery['code_challenge_method']);
        $this->assertSame('code', $firstQuery['response_type']);
        $this->assertNotEmpty($firstQuery['nonce']);
        $this->assertSame('https://client.test/auth/miraicards/callback', $firstQuery['redirect_uri']);
    }

    public function test_callback_validates_tokens_logs_in_and_rejects_replayed_state(): void
    {
        $redirect = $this->get('https://client.test/auth/miraicards/redirect?intended=%2Fevents');
        parse_str((string) parse_url($redirect->headers->get('Location'), PHP_URL_QUERY), $query);
        [$privatePem, $publicPem, $jwk] = $this->rsaKey();
        $now = new DateTimeImmutable;
        $jwt = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($privatePem), InMemory::plainText($publicPem));
        $idToken = $jwt->builder()
            ->withHeader('kid', 'test-key')
            ->issuedBy('https://mirai.cards')
            ->permittedFor('client-id')
            ->relatedTo('pairwise-subject')
            ->issuedAt($now)
            ->expiresAt($now->modify('+10 minutes'))
            ->withClaim('auth_time', $now->getTimestamp())
            ->withClaim('nonce', $query['nonce'])
            ->getToken($jwt->signer(), $jwt->signingKey())
            ->toString();

        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery()),
            'https://mirai.cards/.well-known/jwks.json' => Http::response(['keys' => [$jwk]]),
            'https://mirai.cards/oauth/token' => Http::response(['access_token' => 'access-token', 'id_token' => $idToken]),
            'https://mirai.cards/oauth/userinfo' => Http::response(['sub' => 'pairwise-subject', 'name' => 'Mirai User']),
        ]);
        $this->app->bind(MiraiCardsUserResolver::class, fn () => new class implements MiraiCardsUserResolver
        {
            public function resolve(MiraiCardsIdentity $identity): Authenticatable
            {
                return new GenericUser(['id' => 42, 'name' => $identity->name]);
            }
        });

        $callback = 'https://client.test/auth/miraicards/callback?'.http_build_query(['state' => $query['state'], 'code' => 'one-time-code']);
        $this->get($callback)->assertRedirect('/events');
        $this->assertAuthenticated();

        $this->withoutExceptionHandling();
        $this->expectException(MiraiCardsAuthenticationException::class);
        $this->get($callback);
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
            'code_challenge_methods_supported' => ['S256'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];
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
            'kid' => 'test-key',
            'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
        ]];
    }
}
