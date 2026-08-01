<?php

namespace EverstarAsia\MiraiCardsLogin\Tests;

use EverstarAsia\MiraiCardsLogin\MiraiCardsServiceProvider;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [MiraiCardsServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', 'https://client.test');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('miraicards', [
            'issuer' => 'https://mirai.cards',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'callback_url' => 'https://client.test/auth/miraicards/callback',
            'guard' => 'web',
            'post_login_route' => 'dashboard',
            'scopes' => ['openid', 'profile'],
            'cache_store' => 'array',
            'connect_timeout' => 1,
            'request_timeout' => 1,
            'clock_skew' => 60,
        ]);
    }

    protected function defineRoutes($router): void
    {
        Route::get('/dashboard', fn () => 'dashboard')->name('dashboard');
    }
}
