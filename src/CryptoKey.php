<?php
declare(strict_types=1);

namespace Maymeow\Cryptography;

class CryptoKey
{
    public function HelloWorld() : string
    {
        return "Hello World";
    }

    public function getCryptographicKey(string $password, ?string $salt = null, int $iterations = 1024, int $length = 48) : string
    {
        return hash_pbkdf2("sha256", $password, $salt, $iterations, $length);
    }
}