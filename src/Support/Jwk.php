<?php

namespace EverstarAsia\MiraiCardsLogin\Support;

use EverstarAsia\MiraiCardsLogin\Exceptions\MiraiCardsAuthenticationException;

final class Jwk
{
    /** @param array<string, mixed> $jwk */
    public static function rsaPublicPem(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'RSA' || ($jwk['alg'] ?? null) !== 'RS256'
            || ! is_string($jwk['n'] ?? null) || ! is_string($jwk['e'] ?? null)) {
            throw new MiraiCardsAuthenticationException('The provider returned an invalid RSA signing key.');
        }

        $modulus = self::decode($jwk['n']);
        $exponent = self::decode($jwk['e']);
        $rsaKey = self::sequence(self::integer($modulus).self::integer($exponent));
        $algorithm = self::sequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $subjectPublicKeyInfo = self::sequence($algorithm."\x03".self::length(strlen($rsaKey) + 1)."\x00".$rsaKey);

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private static function decode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (! is_string($decoded) || $decoded === '') {
            throw new MiraiCardsAuthenticationException('The provider returned an invalid RSA signing key.');
        }

        return $decoded;
    }

    private static function integer(string $value): string
    {
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00".$value;
        }

        return "\x02".self::length(strlen($value)).$value;
    }

    private static function sequence(string $value): string
    {
        return "\x30".self::length(strlen($value)).$value;
    }

    private static function length(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xFF).$encoded;
            $length >>= 8;
        }

        return chr(0x80 | strlen($encoded)).$encoded;
    }
}
