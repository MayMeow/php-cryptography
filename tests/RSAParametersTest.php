<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\RSACryptoServiceProvider;
use MayMeow\Cryptography\RSAParameters;
use MayMeow\Cryptography\Tests\Tools\TestingParametersLocator;
use MayMeow\Cryptography\Tools\RsaParametersReader;
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
    public function canExportKeysAndImportToFile() : void
    {
        $parameters = new RSAParameters();
        $parameters->generateKeys();
        $locator = new TestingParametersLocator();

        $writer = new RsaParametersWriter($locator);
        $writer->write($parameters);

        // Assert if exported files are on disk
        $this->assertTrue(file_exists($locator->locatePrivateKey()));
        $this->assertTrue(file_exists($locator->locatePublicKey()));
        $this->assertTrue(file_exists($locator->locatePassphrase()));

        // Encrypt text with newly created keys
        $csp1 = new RSACryptoServiceProvider();
        $csp1->setParameters($parameters);
        $text = 'Ahoj';
        $encryptedText = $csp1->encrypt($text);

        // read testing
        // read previously exported parameters
        $reader = new RsaParametersReader($locator);
        $parameters2 = $reader->read();

        
        // create new instance of RSA CSP with imported parameters
        $csp2 = new RSACryptoServiceProvider();
        $csp2->setParameters($parameters2);

        // Check if imported parameters are same as parameters that was exported
        $this->assertEquals($text, $csp2->decrypt($encryptedText));
    }
}

