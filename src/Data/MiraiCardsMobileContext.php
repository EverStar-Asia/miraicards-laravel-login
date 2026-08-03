<?php

namespace EverstarAsia\MiraiCardsLogin\Data;

final readonly class MiraiCardsMobileContext
{
    public function __construct(
        public string $clientId,
        public string $redirectUri,
        public ?string $userAgent,
        public ?string $ipAddress,
    ) {}
}
