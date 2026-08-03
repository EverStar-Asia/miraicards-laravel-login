<?php

namespace EverstarAsia\MiraiCardsLogin\Contracts;

use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileContext;
use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsMobileSession;
use Illuminate\Contracts\Auth\Authenticatable;

interface MiraiCardsMobileSessionIssuer
{
    public function issue(
        Authenticatable $user,
        MiraiCardsIdentity $identity,
        MiraiCardsMobileContext $context,
    ): MiraiCardsMobileSession;
}
