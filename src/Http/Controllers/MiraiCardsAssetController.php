<?php

namespace EverstarAsia\MiraiCardsLogin\Http\Controllers;

use Symfony\Component\HttpFoundation\BinaryFileResponse;

final class MiraiCardsAssetController
{
    public function stylesheet(): BinaryFileResponse
    {
        return response()->file(
            dirname(__DIR__, 3).'/resources/css/miraicards-login.css',
            [
                'Cache-Control' => 'public, max-age=604800',
                'Content-Type' => 'text/css; charset=UTF-8',
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }

    public function icon(): BinaryFileResponse
    {
        return response()->file(
            dirname(__DIR__, 3).'/resources/images/miraicards-icon.svg',
            [
                'Cache-Control' => 'public, max-age=604800',
                'Content-Type' => 'image/svg+xml',
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }
}
