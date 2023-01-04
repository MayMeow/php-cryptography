<?php

declare(strict_types=1);

namespace MayMeow\Cryptography;

class CryptoKey
{
    public function helloWorld(): string
    {
        return "Hello World";
    }

    /**
     * Derive cryptographic key from given password
     *
     * @param string $password
     * @param string $salt
     * @param int $iterations
     * @param int $length
     * @return string
     */
    public function getCryptographicKey(
        string $password,
        string $salt = '',
        int $iterations = 1024,
        int $length = 48
    ): string {
        return hash_pbkdf2("sha256", $password, $salt, $iterations, $length);
    }
}
