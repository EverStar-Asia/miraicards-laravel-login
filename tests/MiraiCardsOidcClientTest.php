<?php

namespace EverstarAsia\MiraiCardsLogin\Tests;

use DateTimeImmutable;
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsUserResolver;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class MiraiCardsOidcClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::store('array')->clear();
        Http::preventStrayRequests();
    }

    public function test_configuration_uses_permanent_issuer_and_application_callback(): void
    {
        $this->assertSame('https://mirai.cards', config('miraicards.issuer'));
        $this->assertSame(
            'https://client.test/auth/miraicards/callback',
            config('miraicards.callback_url'),
        );
    }

    public function test_mobile_broker_routes_are_not_registered_by_default(): void
    {
        $this->assertFalse(Route::has('miraicards.mobile.authorize'));
        $this->assertFalse(Route::has('miraicards.mobile.callback'));
        $this->assertFalse(Route::has('miraicards.mobile.token'));
    }

    public function test_login_button_is_registered_as_a_namespaced_anonymous_component(): void
    {
        $html = Blade::render('<x-miraicards::login-button />');

        $this->assertStringContainsString('/auth/miraicards/redirect', $html);
        $this->assertStringContainsString('Sign in with MiraiCards', $html);
        $this->assertStringContainsString('/auth/miraicards/assets/login-button.css', $html);
        $this->assertStringContainsString('/auth/miraicards/assets/icon.svg', $html);
        $this->assertStringContainsString('width="28"', $html);
        $this->assertStringContainsString('height="28"', $html);
        $this->assertStringContainsString('miraicards-login-button', $html);
        $this->assertStringNotContainsString('focus:ring', $html);
    }

    public function test_login_button_supports_a_translated_label(): void
    {
        $html = Blade::render('<x-miraicards::login-button>ミライカードでサインイン</x-miraicards::login-button>');

        $this->assertStringContainsString('ミライカードでサインイン', $html);
    }

    public function test_login_button_only_loads_its_stylesheet_once_per_view(): void
    {
        $html = Blade::render('<x-miraicards::login-button /><x-miraicards::login-button />');

        $this->assertSame(1, substr_count($html, '/auth/miraicards/assets/login-button.css'));
        $this->assertSame(2, substr_count($html, 'class="miraicards-login-button"'));
    }

    public function test_login_button_stylesheet_is_served_directly_by_the_package(): void
    {
        $response = $this->get('https://client.test/auth/miraicards/assets/login-button.css');

        $response->assertOk()
            ->assertHeader('Content-Type', 'text/css; charset=UTF-8')
            ->assertHeader('Cache-Control', 'max-age=604800, public')
            ->assertHeader('X-Content-Type-Options', 'nosniff');
        $stylesheet = $response->streamedContent();
        $this->assertSame(
            file_get_contents(__DIR__.'/../resources/css/miraicards-login.css'),
            $stylesheet,
        );
        $this->assertStringContainsString('width: 100%;', $stylesheet);
        $this->assertStringContainsString('height: 44px;', $stylesheet);
        $this->assertStringContainsString('width: 28px;', $stylesheet);
        $this->assertStringContainsString('height: 28px;', $stylesheet);
        $this->assertStringContainsString('linear-gradient(90deg, #08c9e4 0%, #181a63 100%)', $stylesheet);
    }

    public function test_login_button_icon_is_served_directly_by_the_package(): void
    {
        $response = $this->get('https://client.test/auth/miraicards/assets/icon.svg');

        $response->assertOk()
            ->assertHeader('Content-Type', 'image/svg+xml')
            ->assertHeader('Cache-Control', 'max-age=604800, public')
            ->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertSame(
            file_get_contents(__DIR__.'/../resources/images/miraicards-icon.svg'),
            $response->streamedContent(),
        );
    }

    public function test_redirect_uses_pkce_nonce_and_independent_state_for_concurrent_tabs(): void
    {
        $this->fakeDiscovery();
        app()->setLocale('zh_HK');

        $first = $this->get('https://client.test/auth/miraicards/redirect?intended=%2Fevents')->assertRedirect();
        $second = $this->get('https://client.test/auth/miraicards/redirect?intended=https%3A%2F%2Fevil.test')->assertRedirect();
        parse_str((string) parse_url($first->headers->get('Location'), PHP_URL_QUERY), $firstQuery);
        parse_str((string) parse_url($second->headers->get('Location'), PHP_URL_QUERY), $secondQuery);

        $this->assertNotSame($firstQuery['state'], $secondQuery['state']);
        $this->assertSame('S256', $firstQuery['code_challenge_method']);
        $this->assertSame('code', $firstQuery['response_type']);
        $this->assertSame('openid basic_identity', $firstQuery['scope']);
        $this->assertNotEmpty($firstQuery['nonce']);
        $this->assertSame('https://client.test/auth/miraicards/callback', $firstQuery['redirect_uri']);
        $this->assertSame('zh-HK', $firstQuery['ui_locales']);
    }

    public function test_callback_validates_tokens_logs_in_and_rejects_replayed_state(): void
    {
        $this->fakeDiscovery();

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
            'https://mirai.cards/oauth/token' => Http::response([
                'access_token' => 'access-token',
                'id_token' => $idToken,
                'scope' => 'openid basic_identity',
            ]),
            'https://mirai.cards/oauth/userinfo' => Http::response([
                'sub' => 'pairwise-subject',
                'name' => 'Mirai User',
                'email' => 'mirai@example.com',
            ]),
        ]);
        $resolver = new class implements MiraiCardsUserResolver
        {
            public ?MiraiCardsIdentity $identity = null;

            public function resolve(MiraiCardsIdentity $identity): Authenticatable
            {
                $this->identity = $identity;

                return new GenericUser(['id' => 42, 'name' => $identity->name, 'email' => $identity->email]);
            }
        };
        $this->app->instance(MiraiCardsUserResolver::class, $resolver);

        $callback = 'https://client.test/auth/miraicards/callback?'.http_build_query(['state' => $query['state'], 'code' => 'one-time-code']);
        $this->get($callback)->assertRedirect('/events');
        $this->assertAuthenticated();
        $this->assertSame('mirai@example.com', $resolver->identity?->email);
        $this->assertSame(['openid', 'basic_identity'], $resolver->identity?->scopes);

        $this->withoutExceptionHandling();
        $this->expectException(MiraiCardsAuthenticationException::class);
        $this->get($callback);
    }

    public function test_redirect_rejects_discovery_without_basic_identity_support(): void
    {
        $discovery = $this->discovery();
        $discovery['scopes_supported'] = ['openid'];
        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($discovery),
        ]);
        Cache::store('array')->clear();

        $this->withoutExceptionHandling();
        $this->expectException(MiraiCardsAuthenticationException::class);
        $this->expectExceptionMessage('The provider discovery document is incompatible.');

        $this->get('https://client.test/auth/miraicards/redirect');
    }

    public function test_callback_rejects_a_token_response_without_granted_scopes(): void
    {
        $this->fakeDiscovery();

        $redirect = $this->get('https://client.test/auth/miraicards/redirect');
        parse_str((string) parse_url($redirect->headers->get('Location'), PHP_URL_QUERY), $query);
        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery()),
            'https://mirai.cards/oauth/token' => Http::response([
                'access_token' => 'access-token',
                'id_token' => 'not-inspected-before-scope-validation',
            ]),
        ]);
        $this->app->bind(MiraiCardsUserResolver::class, fn () => new class implements MiraiCardsUserResolver
        {
            public function resolve(MiraiCardsIdentity $identity): Authenticatable
            {
                return new GenericUser(['id' => 42]);
            }
        });

        $this->withoutExceptionHandling();
        $this->expectException(MiraiCardsAuthenticationException::class);
        $this->expectExceptionMessage('The provider token response did not include its granted scopes.');

        $callback = 'https://client.test/auth/miraicards/callback?'.http_build_query([
            'state' => $query['state'],
            'code' => 'one-time-code',
        ]);
        $this->get($callback);
    }

    private function fakeDiscovery(): void
    {
        Http::fake([
            'https://mirai.cards/.well-known/openid-configuration' => Http::response($this->discovery()),
        ]);
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
            'scopes_supported' => ['openid', 'basic_identity'],
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
