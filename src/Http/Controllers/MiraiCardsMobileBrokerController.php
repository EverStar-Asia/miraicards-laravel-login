<?php

namespace EverstarAsia\MiraiCardsLogin\Http\Controllers;

use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsMobileSessionIssuer;
use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsUserResolver;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileContext;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use EverstarAsia\MiraiCardsLogin\MiraiCardsOidcClient;
use EverstarAsia\MiraiCardsLogin\Support\LoginTransactionStore;
use EverstarAsia\MiraiCardsLogin\Support\MobileAuthorizationCodeStore;
use EverstarAsia\MiraiCardsLogin\Support\MobileBrokerConfiguration;
use EverstarAsia\MiraiCardsLogin\Support\MobileLoginTransactionStore;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Throwable;

final class MiraiCardsMobileBrokerController
{
    public function authorize(
        Request $request,
        MiraiCardsOidcClient $oidc,
        MobileBrokerConfiguration $configuration,
        MobileLoginTransactionStore $transactions,
    ): RedirectResponse|JsonResponse {
        $clientId = $request->string('client_id')->toString();
        $redirectUri = $request->string('redirect_uri')->toString();
        $state = $request->string('state')->toString();
        $challenge = $request->string('code_challenge')->toString();
        $method = $request->string('code_challenge_method')->toString();

        try {
            $configuration->assertClientRedirect($clientId, $redirectUri);
            if ($state === '' || strlen($state) > 512 || preg_match('/[\x00-\x1F\x7F]/', $state)
                || $method !== 'S256' || preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) !== 1) {
                throw new MiraiCardsAuthenticationException('The mobile authorization request is invalid.');
            }
            $callback = $configuration->callbackUrl();
        } catch (MiraiCardsAuthenticationException $exception) {
            return $this->error('invalid_request', 400);
        }

        $nonce = LoginTransactionStore::base64Url(random_bytes(32));
        $verifier = LoginTransactionStore::base64Url(random_bytes(64));
        $providerState = $transactions->put([
            'nonce' => $nonce,
            'verifier' => $verifier,
            'callback' => $callback,
            'scopes' => ['openid', 'basic_identity'],
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'app_state' => $state,
            'app_challenge' => $challenge,
        ]);

        try {
            return $oidc->redirectToProvider($callback, $providerState, $nonce, $verifier);
        } catch (Throwable $exception) {
            return $this->error('server_error', 500);
        }
    }

    public function callback(
        Request $request,
        MiraiCardsOidcClient $oidc,
        MobileLoginTransactionStore $transactions,
        MobileAuthorizationCodeStore $codes,
    ): RedirectResponse|JsonResponse {
        try {
            $transaction = $transactions->consume($request->string('state')->toString());
        } catch (MiraiCardsAuthenticationException $exception) {
            return $this->error('invalid_request', 400);
        } catch (Throwable $exception) {
            return $this->error('server_error', 500);
        }

        $redirectUri = (string) ($transaction['redirect_uri'] ?? '');
        $appState = (string) ($transaction['app_state'] ?? '');
        if ($request->filled('error')) {
            return $this->appRedirect($redirectUri, ['error' => 'access_denied', 'state' => $appState]);
        }

        try {
            $identity = $oidc->completeCallback($request, $transaction);
            $code = $codes->put(
                $identity,
                (string) $transaction['client_id'],
                $redirectUri,
                (string) $transaction['app_challenge'],
            );
        } catch (Throwable $exception) {
            return $this->appRedirect($redirectUri, ['error' => 'server_error', 'state' => $appState]);
        }

        return $this->appRedirect($redirectUri, ['code' => $code, 'state' => $appState]);
    }

    public function token(
        Request $request,
        MobileBrokerConfiguration $configuration,
        MobileAuthorizationCodeStore $codes,
    ): JsonResponse {
        $clientId = $request->string('client_id')->toString();
        $redirectUri = $request->string('redirect_uri')->toString();
        if ($request->string('grant_type')->toString() !== 'authorization_code') {
            return $this->error('unsupported_grant_type', 400);
        }
        if (! app()->bound(MiraiCardsUserResolver::class) || ! app()->bound(MiraiCardsMobileSessionIssuer::class)) {
            return $this->error('server_error', 500);
        }

        try {
            $configuration->assertClientRedirect($clientId, $redirectUri);
            $identity = $codes->consume(
                $request->string('code')->toString(),
                $clientId,
                $redirectUri,
                $request->string('code_verifier')->toString(),
            );
        } catch (MiraiCardsAuthenticationException $exception) {
            return $this->error('invalid_grant', 400);
        } catch (Throwable $exception) {
            return $this->error('server_error', 500);
        }

        try {
            $user = app(MiraiCardsUserResolver::class)->resolve($identity);
            $session = app(MiraiCardsMobileSessionIssuer::class)->issue(
                $user,
                $identity,
                new MiraiCardsMobileContext(
                    clientId: $clientId,
                    redirectUri: $redirectUri,
                    userAgent: $request->userAgent(),
                    ipAddress: $request->ip(),
                ),
            );
        } catch (MiraiCardsAuthenticationException $exception) {
            return $this->error('access_denied', 403);
        } catch (Throwable $exception) {
            return $this->error('server_error', 500);
        }

        return $this->json(['version' => 1, 'session' => $session->payload]);
    }

    /** @param array<string, string> $parameters */
    private function appRedirect(string $redirectUri, array $parameters): RedirectResponse
    {
        $separator = str_contains($redirectUri, '?') ? '&' : '?';

        return redirect()->away($redirectUri.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986))
            ->withHeaders([
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ]);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return $this->json(['error' => $error], $status);
    }

    /** @param array<string, mixed> $payload */
    private function json(array $payload, int $status = 200): JsonResponse
    {
        return response()->json($payload, $status)->withHeaders([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
