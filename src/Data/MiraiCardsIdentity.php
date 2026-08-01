<?php

namespace EverstarAsia\MiraiCardsLogin\Data;

use DateTimeImmutable;

final readonly class MiraiCardsIdentity
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $issuer,
        public string $subject,
        public ?string $name,
        public ?string $preferredUsername,
        public ?string $picture,
        public ?string $profile,
        public ?string $locale,
        public ?DateTimeImmutable $updatedAt,
        public array $scopes,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public DateTimeImmutable $authenticatedAt,
    ) {}
}
