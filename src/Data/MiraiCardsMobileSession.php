<?php

namespace EverstarAsia\MiraiCardsLogin\Data;

final readonly class MiraiCardsMobileSession
{
    /** @param array<string, mixed> $payload */
    public function __construct(public array $payload) {}
}
