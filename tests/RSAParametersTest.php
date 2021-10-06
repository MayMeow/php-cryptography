<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\RSAParameters;
use PHPUnit\Framework\TestCase;

class RSAParametersTest extends TestCase
{

    /** @test */
    public function canGenerateKeys() :void {
        $parameters = new RSAParameters();
        $keys =  $parameters->generateKeys();

        $this->assertInstanceOf(RSAParameters::class, $keys);
    }
}