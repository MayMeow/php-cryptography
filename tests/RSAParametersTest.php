<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\RSAParameters;
use MayMeow\Cryptography\Tools\RsaParametersWriter;
use PHPUnit\Framework\TestCase;

class RSAParametersTest extends TestCase
{

    /** @test */
    public function canGenerateKeys() :void
    {
        $parameters = new RSAParameters();
        $keys =  $parameters->generateKeys();

        $this->assertInstanceOf(RSAParameters::class, $keys);
    }

    /** @test */
    public function canExportKeysToFile() : void
    {
        $parameters = new RSAParameters();
        $parameters->generateKeys();
        $writer = new RsaParametersWriter();
        $writer->write($parameters);

        $this->assertTrue(file_exists(KEYSTORE . DIRECTORY_SEPARATOR . 'key.pem'));
        $this->assertTrue(file_exists(KEYSTORE . DIRECTORY_SEPARATOR . 'pubkey.pem'));
        $this->assertTrue(file_exists(KEYSTORE . DIRECTORY_SEPARATOR . 'pass.txt'));
    }
}