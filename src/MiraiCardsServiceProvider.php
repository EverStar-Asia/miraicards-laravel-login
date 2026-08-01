<?php

namespace EverstarAsia\MiraiCardsLogin;

use EverstarAsia\MiraiCardsLogin\Console\MiraiCardsDoctorCommand;
use EverstarAsia\MiraiCardsLogin\Http\Controllers\MiraiCardsLoginController;
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

        Route::middleware('web')->group(function (): void {
            Route::get('/auth/miraicards/redirect', [MiraiCardsLoginController::class, 'redirect'])
                ->name('miraicards.redirect');
            Route::get('/auth/miraicards/callback', [MiraiCardsLoginController::class, 'callback'])
                ->name('miraicards.callback');
        });

        if ($this->app->runningInConsole()) {
            $this->commands([MiraiCardsDoctorCommand::class]);
        }
    }
}
