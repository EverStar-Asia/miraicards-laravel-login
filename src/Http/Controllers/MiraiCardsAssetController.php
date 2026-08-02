<?php

namespace EverstarAsia\MiraiCardsLogin\Http\Controllers;

use Symfony\Component\HttpFoundation\BinaryFileResponse;

final class MiraiCardsAssetController
{
    public function loginButton(): BinaryFileResponse
    {
        return response()->file(
            dirname(__DIR__, 3).'/resources/images/btn_miraicardsOIDC.png',
            [
                'Cache-Control' => 'public, max-age=604800',
                'Content-Type' => 'image/png',
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }
}
