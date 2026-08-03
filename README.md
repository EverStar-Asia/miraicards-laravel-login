# MiraiCards Laravel Login

Private Laravel 12–13 integration for “Sign in with MiraiCards”. The package implements Authorization Code + PKCE S256, confidential client authentication, nonce/state validation, RS256/JWKS verification, UserInfo subject matching, and safe post-login redirects.

Install from the private GitHub repository through an authenticated Composer VCS repository, publish `miraicards-config`, bind `MiraiCardsUserResolver`, and set the `MIRAICARDS_*` environment values. Identity linking must use the unique `(issuer, subject)` pair; never link by email.

The package always requests MiraiCards Basic identity. Applications do not configure scopes. The identity response contains the pairwise subject, name, and email address.

The login button stylesheet and icon are served directly by the package and do not require asset publishing. The component has no Tailwind CSS or other frontend framework dependency.

Run `php artisan miraicards:doctor` after configuring the application. Provider callback registration remains a manual administrator check.

## Optional mobile OAuth broker

The package can broker the MiraiCards browser login for native applications without putting the confidential MiraiCards client secret in the app. The broker is disabled by default and registers no mobile routes until explicitly enabled. The host and mobile flow use the same MiraiCards client ID and secret, but the mobile callback is distinct and must also be registered with MiraiCards.

Configure public mobile clients and exact redirect URIs in the published config:

```php
'mobile_broker' => [
    'enabled' => env('MIRAICARDS_MOBILE_BROKER_ENABLED', false),
    'callback_url' => env('MIRAICARDS_MOBILE_CALLBACK_URI'),
    'clients' => [
        'mirai-ios' => [
            'redirect_uris' => ['com.example.app:/oauth/miraicards'],
        ],
    ],
    'middleware' => ['throttle:60,1'],
    'transaction_ttl' => 600,
    'code_ttl' => 60,
],
```

Redirect URIs are compared exactly. HTTPS claimed links and explicitly registered application schemes are supported; HTTP URLs, fragments, credentials, wildcards, and prefix matching are rejected. Use a shared cache store with atomic-lock support in multi-node deployments. After changing `enabled` when routes are cached, rebuild Laravel's route cache.

The host must bind both `MiraiCardsUserResolver` and `MiraiCardsMobileSessionIssuer`. User resolution still happens only through the unique `(issuer, subject)` identity. The session issuer receives the resolved user, verified identity, and typed client context. The context contains `clientId`, `redirectUri`, and the nullable server-derived `userAgent` and `ipAddress`. The issuer returns the host's existing nested mobile session payload:

```php
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsMobileSessionIssuer;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileContext;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileSession;
use Illuminate\Contracts\Auth\Authenticatable;

final class MobileSessionIssuer implements MiraiCardsMobileSessionIssuer
{
    public function issue(
        Authenticatable $user,
        MiraiCardsIdentity $identity,
        MiraiCardsMobileContext $context,
    ): MiraiCardsMobileSession {
        return new MiraiCardsMobileSession([
            'user' => ['id' => $user->getAuthIdentifier()],
            'credentials' => ['token' => $this->tokens->issue($user)],
        ]);
    }
}
```

The native app performs these steps:

1. Generate a PKCE verifier and S256 challenge, then open `GET /auth/miraicards/mobile/authorize` in the system browser with `client_id`, exact `redirect_uri`, opaque `state`, `code_challenge`, and `code_challenge_method=S256`.
2. MiraiCards returns to the broker's HTTPS `GET /auth/miraicards/mobile/callback`. The broker verifies the provider response and redirects to the registered app URI with a short-lived, one-time `code` and the original app state. The HTTPS callback must reach Laravel and must not be intercepted as an application universal link.
3. Exchange the code at `POST /auth/miraicards/mobile/token` using form fields `grant_type=authorization_code`, `client_id`, the same `redirect_uri`, `code`, and `code_verifier`.

The successful token response is `{"version":1,"session":{...}}`; the contents of `session` come from the host issuer. Provider tokens and verified identity are never placed in the application redirect. A host resolver or session issuer may throw `MiraiCardsAuthenticationException` to reject login with a detail-free `access_denied` response; unexpected failures return `server_error`. Other protocol errors use `invalid_request`, `invalid_grant`, or `unsupported_grant_type` without provider details. Run `php artisan miraicards:doctor` after enabling the broker to validate its callback, client registry, and host bindings.
