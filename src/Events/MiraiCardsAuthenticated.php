<?php

namespace EverstarAsia\MiraiCardsLogin\Events;

use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

final class MiraiCardsAuthenticated
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly MiraiCardsIdentity $identity,
    ) {}
}
