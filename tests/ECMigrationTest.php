<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\RSAParameters;
use MayMeow\Cryptography\RSACryptoServiceProvider;
use MayMeow\Cryptography\ECParameters;
use MayMeow\Cryptography\ECCryptoServiceProvider;
use PHPUnit\Framework\TestCase;

class ECMigrationTest extends TestCase
{
    protected string $salt = 'salt';
    protected string $passphrase = 'passphrase';
    
    /** @test */
    public function canMigrateFromRSAToECForSigning(): void
    {
        // Test that RSA signing still works
        $rsaParams = new RSAParameters();
        $rsaConfig = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ];
        $rsaParams->generateKeys($this->passphrase, $rsaConfig, $this->salt);
        
        $rsaCrypto = new RSACryptoServiceProvider();
        $rsaCrypto->setParameters($rsaParams);
        
        $data = "Test data for migration";
        $rsaSignature = $rsaCrypto->sign($data, $this->passphrase, $this->salt);
        $rsaValid = $rsaCrypto->verify($data, $rsaSignature);
        
        $this->assertTrue($rsaValid, "RSA signing should still work");
        
        // Test that EC signing works (using RSAParameters with default EC)
        $ecParams = new RSAParameters();
        $ecParams->generateKeys($this->passphrase, null, $this->salt);
        
        $ecCrypto = new RSACryptoServiceProvider();
        $ecCrypto->setParameters($ecParams);
        
        $ecSignature = $ecCrypto->sign($data, $this->passphrase, $this->salt);
        $ecValid = $ecCrypto->verify($data, $ecSignature);
        
        $this->assertTrue($ecValid, "EC signing should work");
        
        // Signatures should be different (different algorithms and key types)
        $this->assertNotEquals($rsaSignature, $ecSignature, "RSA and EC signatures should be different");
    }

    /** @test */
    public function defaultRSAParametersUsesECKeys(): void
    {
        $params = new RSAParameters();
        $params->generateKeys($this->passphrase, null, $this->salt);
        
        $config = $params->getConfig();
        
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $config['private_key_type']);
        $this->assertEquals('prime256v1', $config['ec']['curve_name']);
        $this->assertArrayNotHasKey('private_key_bits', $config);
    }

    /** @test */
    public function canExplicitlyUseRSAKeys(): void
    {
        $params = new RSAParameters();
        $rsaConfig = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ];
        $params->generateKeys($this->passphrase, $rsaConfig, $this->salt);
        
        $config = $params->getConfig();
        
        $this->assertEquals(OPENSSL_KEYTYPE_RSA, $config['private_key_type']);
        $this->assertEquals(2048, $config['private_key_bits']);
    }

    /** @test */
    public function ecKeysThrowExceptionsForEncryption(): void
    {
        $params = new RSAParameters();
        $params->generateKeys($this->passphrase, null, $this->salt); // Uses EC by default
        
        $crypto = new RSACryptoServiceProvider();
        $crypto->setParameters($params);
        
        $this->expectException(\MayMeow\Cryptography\Exceptions\NotImplementedException::class);
        $this->expectExceptionMessage('Direct encryption is not supported with EC keys');
        
        $crypto->encrypt("test data");
    }

    /** @test */
    public function rsaKeysStillSupportEncryption(): void
    {
        $params = new RSAParameters();
        $rsaConfig = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ];
        $params->generateKeys($this->passphrase, $rsaConfig, $this->salt);
        
        $crypto = new RSACryptoServiceProvider();
        $crypto->setParameters($params);
        
        $plainText = "Test encryption RSA data";
        $encrypted = $crypto->encrypt($plainText);
        $decrypted = $crypto->decrypt($encrypted, $this->passphrase, $this->salt);
        
        $this->assertEquals($plainText, $decrypted);
    }

    /** @test */
    public function ecParametersClassWorksIndependently(): void
    {
        $ecParams = new ECParameters();
        $ecParams->generateKeys($this->passphrase, null, $this->salt);
        
        $ecCrypto = new ECCryptoServiceProvider();
        $ecCrypto->setParameters($ecParams);
        
        $data = "Test data for dedicated EC classes";
        $signature = $ecCrypto->sign($data, $this->passphrase, $this->salt);
        $isValid = $ecCrypto->verify($data, $signature);
        
        $this->assertTrue($isValid);
        
        // Test that encryption methods throw exceptions
        $this->expectException(\MayMeow\Cryptography\Exceptions\NotImplementedException::class);
        $ecCrypto->encrypt("test");
    }

    /** @test */
    public function canUseDifferentECCurves(): void
    {
        $curves = ['prime256v1', 'secp384r1', 'secp521r1'];
        
        foreach ($curves as $curve) {
            $params = new ECParameters();
            $config = ['curve_name' => $curve];
            $params->generateKeys($this->passphrase, $config, $this->salt);
            
            $crypto = new ECCryptoServiceProvider();
            $crypto->setParameters($params);
            
            $data = "Test data for curve: $curve";
            $signature = $crypto->sign($data, $this->passphrase, $this->salt);
            $isValid = $crypto->verify($data, $signature);
            
            $this->assertTrue($isValid, "Curve $curve should work for signing");
        }
    }

    /** @test */
    public function keyFingerprintsWorkForBothTypes(): void
    {
        // Test EC fingerprint
        $ecParams = new RSAParameters();
        $ecParams->generateKeys($this->passphrase, null, $this->salt);
        $ecFingerprint = $ecParams->getFingerprint();
        
        $this->assertIsString($ecFingerprint);
        $this->assertEquals(64, strlen($ecFingerprint)); // SHA-256 length
        
        // Test RSA fingerprint
        $rsaParams = new RSAParameters();
        $rsaConfig = ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048];
        $rsaParams->generateKeys($this->passphrase, $rsaConfig, $this->salt);
        $rsaFingerprint = $rsaParams->getFingerprint();
        
        $this->assertIsString($rsaFingerprint);
        $this->assertEquals(64, strlen($rsaFingerprint)); // SHA-256 length
        
        // Fingerprints should be different
        $this->assertNotEquals($ecFingerprint, $rsaFingerprint);
    }
}