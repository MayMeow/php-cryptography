<?php
declare(strict_types=1);

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\CryptoKey;
use PHPUnit\Framework\TestCase;

class PBKDF2Test extends TestCase
{
    /** @test */
    public function TestHelloWorld() :void
    {
        $p = new CryptoKey();

        $this->assertEquals("Hello World", $p->helloWorld());
    }

    /** @test */
    public function canGetCryptographicKey() : void
    {
        $p = new CryptoKey();
        $password = 'pa$$word1';
        $expectedKey = "10d7783e00821d6a309a271698bd5399";
        $salt = "cfe29b9ef459d95e280d7b3fc2f7e2ef2e10a102606a4469";

        $this->assertEquals($expectedKey, $p->getCryptographicKey($password, $salt));
    }
}