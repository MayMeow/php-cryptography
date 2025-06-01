<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\ECCryptoServiceProvider;
use MayMeow\Cryptography\ECParameters;
use MayMeow\Cryptography\Exceptions\NotImplementedException;
use PHPUnit\Framework\TestCase;

class ECCryptoServiceProviderTest extends TestCase
{
    protected string $salt = 'salt';
    protected string $passphrase = 'passphrase';
    
    /** @test */
    public function canSignAndVerifyData(): void
    {
        $plainText = "This is going to be signed!";
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        // Sign the data
        $signature = $ec->sign($plainText, privateKeyPass: $this->passphrase, salt: $this->salt);
        $this->assertIsString($signature);
        $this->assertNotEmpty($signature);
        
        // Verify the signature
        $isValid = $ec->verify($plainText, $signature);
        $this->assertTrue($isValid);
        
        // Verify with wrong data should fail
        $isValidWrong = $ec->verify($plainText . "tampered", $signature);
        $this->assertFalse($isValidWrong);
    }

    /** @test */
    public function canGenerateFingerprint(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $fingerprint = $ec->getFingerPrint();
        $this->assertIsString($fingerprint);
        $this->assertMatchesRegularExpression('/^[a-f0-9:]+$/', $fingerprint);
    }

    /** @test */
    public function encryptThrowsNotImplementedException(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $this->expectException(NotImplementedException::class);
        $this->expectExceptionMessage('Direct encryption is not supported with EC keys');
        
        $ec->encrypt("test data");
    }

    /** @test */
    public function decryptThrowsNotImplementedException(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $this->expectException(NotImplementedException::class);
        $this->expectExceptionMessage('Direct decryption is not supported with EC keys');
        
        $ec->decrypt("test data", $this->passphrase, $this->salt);
    }

    /** @test */
    public function privateEncryptThrowsNotImplementedException(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $this->expectException(NotImplementedException::class);
        $this->expectExceptionMessage('Private encryption is not supported with EC keys');
        
        $ec->privateEncrypt("test data", $this->passphrase, $this->salt);
    }

    /** @test */
    public function publicDecryptThrowsNotImplementedException(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $this->expectException(NotImplementedException::class);
        $this->expectExceptionMessage('Public decryption is not supported with EC keys');
        
        $ec->publicDecrypt("test data");
    }

    /** @test */
    public function canWorkWithDifferentCurves(): void
    {
        // Test with secp384r1 curve
        $parameters = new ECParameters();
        $customConfig = ['curve_name' => 'secp384r1'];
        $parameters->generateKeys(
            passphrase: $this->passphrase, 
            configArgs: $customConfig, 
            salt: $this->salt
        );

        $ec = new ECCryptoServiceProvider();
        $ec->setParameters($parameters);
        
        $data = "Test data for secp384r1";
        $signature = $ec->sign($data, privateKeyPass: $this->passphrase, salt: $this->salt);
        $isValid = $ec->verify($data, $signature);
        
        $this->assertTrue($isValid);
    }
}