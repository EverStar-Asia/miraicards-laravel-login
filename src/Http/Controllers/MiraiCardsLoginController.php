<?php

namespace EverstarAsia\MiraiCardsLogin\Http\Controllers;

use EverstarAsia\MiraiCardsLogin\Contracts\MiraiCardsUserResolver;
use EverstarAsia\MiraiCardsLogin\Events\MiraiCardsAuthenticated;
use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;
use EverstarAsia\MiraiCardsLogin\MiraiCardsOidcClient;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

final class MiraiCardsLoginController
{
    public function redirect(Request $request, MiraiCardsOidcClient $client): RedirectResponse
    {
        return $client->redirect($request, $request->query('intended'));
    }

    public function callback(Request $request, MiraiCardsOidcClient $client): RedirectResponse
    {
        if (! app()->bound(MiraiCardsUserResolver::class)) {
            throw new MiraiCardsAuthenticationException('The host application must bind MiraiCardsUserResolver.');
        }

        $identity = $client->callback($request);
        $resolver = app(MiraiCardsUserResolver::class);
        $user = $resolver->resolve($identity);
        $guard = Auth::guard((string) config('miraicards.guard'));
        if (! $guard instanceof StatefulGuard) {
            throw new MiraiCardsAuthenticationException('The configured authentication guard must be stateful.');
        }

        $guard->login($user);
        $request->session()->regenerate();
        MiraiCardsAuthenticated::dispatch($user, $identity);

        $intended = $request->attributes->get('miraicards.intended');
        if (is_string($intended) && str_starts_with($intended, '/') && ! str_starts_with($intended, '//')) {
            return redirect()->to($intended);
        }

        $route = (string) config('miraicards.post_login_route');
        if ($route === '' || ! Route::has($route)) {
            throw new MiraiCardsAuthenticationException('The configured post-login named route does not exist.');
        }

        return redirect()->route($route);
    }
}
