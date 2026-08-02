<?php

namespace EverstarAsia\MiraiCardsLogin\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Throwable;

final class MiraiCardsDoctorCommand extends Command
{
    protected $signature = 'miraicards:doctor';

    protected $description = 'Validate the MiraiCards OpenID Connect login configuration';

    public function handle(): int
    {
        foreach (['issuer', 'client_id', 'client_secret', 'callback_url'] as $key) {
            if (! filled(config('miraicards.'.$key))) {
                $this->error("Missing miraicards.{$key}.");

                return self::FAILURE;
            }
        }

        $issuer = rtrim((string) config('miraicards.issuer'), '/');
        if (! str_starts_with($issuer, 'https://') || ! str_starts_with((string) config('miraicards.callback_url'), 'https://')) {
            $this->error('Issuer and callback URLs must use HTTPS.');

            return self::FAILURE;
        }

        try {
            $http = Http::connectTimeout((int) config('miraicards.connect_timeout'))
                ->timeout((int) config('miraicards.request_timeout'))
                ->acceptJson();
            $discovery = $http->get($issuer.'/.well-known/openid-configuration')->throw()->json();
            $jwks = $http->get($discovery['jwks_uri'])->throw()->json();
        } catch (Throwable $exception) {
            $this->error('Unable to load discovery/JWKS: '.$exception->getMessage());

            return self::FAILURE;
        }

        $supportedScopes = $discovery['scopes_supported'] ?? null;
        if (($discovery['issuer'] ?? null) !== $issuer
            || ($discovery['code_challenge_methods_supported'] ?? null) !== ['S256']
            || ! in_array('RS256', $discovery['id_token_signing_alg_values_supported'] ?? [], true)
            || ! is_array($supportedScopes)
            || collect(['openid', 'basic_identity'])->diff($supportedScopes)->isNotEmpty()
            || ! is_array($jwks['keys'] ?? null)
            || $jwks['keys'] === []) {
            $this->error('Discovery or JWKS does not meet MiraiCards login requirements.');

            return self::FAILURE;
        }

        $this->info('MiraiCards configuration, HTTPS discovery, PKCE S256, RS256, and JWKS are valid.');
        $this->warn('Manual check required: confirm this exact callback URI is registered by the MiraiCards administrator: '.config('miraicards.callback_url'));

        return self::SUCCESS;
    }
}
