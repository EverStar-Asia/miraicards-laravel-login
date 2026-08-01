<?php

namespace EverstarAsia\MiraiCardsLogin\Contracts;

use EverstarAsia\MiraiCardsLogin\Data\MiraiCardsIdentity;
use Illuminate\Contracts\Auth\Authenticatable;

interface MiraiCardsUserResolver
{
    public function resolve(MiraiCardsIdentity $identity): Authenticatable;
}
