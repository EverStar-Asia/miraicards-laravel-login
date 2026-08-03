<?php

namespace EverstarAsia\MiraiCardsLogin;

use EverstarAsia\MiraiCardsLogin\Console\MiraiCardsDoctorCommand;
use EverstarAsia\MiraiCardsLogin\Http\Controllers\MiraiCardsAssetController;
use EverstarAsia\MiraiCardsLogin\Http\Controllers\MiraiCardsLoginController;
use EverstarAsia\MiraiCardsLogin\Http\Controllers\MiraiCardsMobileBrokerController;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

final class MiraiCardsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/miraicards.php', 'miraicards');
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'miraicards');
        Blade::anonymousComponentPath(__DIR__.'/../resources/views/components', 'miraicards');
        $this->publishes([
            __DIR__.'/../config/miraicards.php' => config_path('miraicards.php'),
        ], 'miraicards-config');
        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/miraicards'),
        ], 'miraicards-views');

        Route::get('/auth/miraicards/assets/icon.svg', [MiraiCardsAssetController::class, 'icon'])
            ->name('miraicards.assets.icon');
        Route::get('/auth/miraicards/assets/login-button.css', [MiraiCardsAssetController::class, 'stylesheet'])
            ->name('miraicards.assets.stylesheet');

        Route::middleware('web')->group(function (): void {
            Route::get('/auth/miraicards/redirect', [MiraiCardsLoginController::class, 'redirect'])
                ->name('miraicards.redirect');
            Route::get('/auth/miraicards/callback', [MiraiCardsLoginController::class, 'callback'])
                ->name('miraicards.callback');
        });

        if (config('miraicards.mobile_broker.enabled') === true) {
            Route::middleware((array) config('miraicards.mobile_broker.middleware', []))->group(function (): void {
                Route::get('/auth/miraicards/mobile/authorize', [MiraiCardsMobileBrokerController::class, 'authorize'])
                    ->name('miraicards.mobile.authorize');
                Route::get('/auth/miraicards/mobile/callback', [MiraiCardsMobileBrokerController::class, 'callback'])
                    ->name('miraicards.mobile.callback');
                Route::post('/auth/miraicards/mobile/token', [MiraiCardsMobileBrokerController::class, 'token'])
                    ->name('miraicards.mobile.token');
            });
        }

        if ($this->app->runningInConsole()) {
            $this->commands([MiraiCardsDoctorCommand::class]);
        }
    }
}
