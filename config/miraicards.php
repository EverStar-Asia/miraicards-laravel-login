<?php

return [
    'issuer' => env('MIRAICARDS_ISSUER', 'https://mirai.cards'),
    'client_id' => env('MIRAICARDS_CLIENT_ID'),
    'client_secret' => env('MIRAICARDS_CLIENT_SECRET'),
    'callback_url' => env('MIRAICARDS_REDIRECT_URI'),
    'guard' => env('MIRAICARDS_GUARD', 'web'),
    'post_login_route' => env('MIRAICARDS_POST_LOGIN_ROUTE', 'dashboard'),
    'scopes' => ['openid', 'profile'],
    'cache_store' => env('MIRAICARDS_CACHE_STORE'),
    'connect_timeout' => (int) env('MIRAICARDS_CONNECT_TIMEOUT', 5),
    'request_timeout' => (int) env('MIRAICARDS_REQUEST_TIMEOUT', 10),
    'clock_skew' => 60,
];
