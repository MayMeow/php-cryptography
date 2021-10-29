<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\RSAParameters;
use MayMeow\Cryptography\Tests\Tools\TestingParametersLocator;
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
        $locator = new TestingParametersLocator();

        $writer = new RsaParametersWriter($locator);
        $writer->write($parameters);

        $this->assertTrue(file_exists($locator->locatePrivateKey()));
        $this->assertTrue(file_exists($locator->locatePublicKey()));
        $this->assertTrue(file_exists($locator->locatePassphrase()));
    }
}