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
    protected string $salt = 'salt';
    protected string $passphrase = 'passphrase';
    
    /** @test */
    public function canGenerateKeys() :void
    {
        $parameters = new RSAParameters();
        $keys =  $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $this->assertInstanceOf(RSAParameters::class, $keys);
    }

    /** @test */
    public function defaultKeyGenerationUsesEC(): void
    {
        $parameters = new RSAParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);
        
        $config = $parameters->getConfig();
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $config['private_key_type']);
        $this->assertEquals('prime256v1', $config['ec']['curve_name']);
    }

    /** @test */
    public function canExportKeysAndImportToFile() : void
    {
        $parameters = new RSAParameters();
        
        // Use RSA explicitly for encryption test  
        $rsaConfig = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ];
        $parameters->generateKeys(passphrase: $this->passphrase, configArgs: $rsaConfig, salt: $this->salt);
        $locator = new TestingParametersLocator();

        $writer = new RsaParametersWriter($locator);
        $writer->write($parameters, privateKeyPass: $this->passphrase, salt: $this->salt);

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
        $this->assertEquals($text, $csp2->decrypt($encryptedText, privateKeyPass: $this->passphrase, salt: $this->salt));
    }
}
