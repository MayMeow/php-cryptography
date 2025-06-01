<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\ECParameters;
use PHPUnit\Framework\TestCase;

class ECParametersTest extends TestCase
{
    protected string $salt = 'salt';
    protected string $passphrase = 'passphrase';
    
    /** @test */
    public function canGenerateKeys(): void
    {
        $parameters = new ECParameters();
        $keys = $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);

        $this->assertInstanceOf(ECParameters::class, $keys);
    }

    /** @test */
    public function canGetAndSetPublicKey(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);
        
        $publicKey = $parameters->getPublicKey();
        $this->assertIsString($publicKey);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $publicKey);
        
        // Test setting a public key
        $testKey = "test-public-key";
        $parameters->setPublicKey($testKey);
        $this->assertEquals($testKey, $parameters->getPublicKey());
    }

    /** @test */
    public function canGetAndSetPrivateKey(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);
        
        $privateKey = $parameters->getPrivateKey(passphrase: $this->passphrase, salt: $this->salt);
        $this->assertIsString($privateKey);
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $privateKey);
        
        // Test setting a private key
        $testKey = "test-private-key";
        $parameters->setPrivateKey($testKey);
        $encryptedKey = $parameters->getPrivateKey(passphrase: $this->passphrase, salt: $this->salt, encrypted: true);
        $this->assertEquals($testKey, $encryptedKey);
    }

    /** @test */
    public function canGetAndSetConfig(): void
    {
        $parameters = new ECParameters();
        
        $config = $parameters->getConfig();
        $this->assertIsArray($config);
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $config['private_key_type']);
        $this->assertEquals('prime256v1', $config['curve_name']);
        
        // Test setting config
        $newConfig = [
            'curve_name' => 'secp384r1',
            'digest_alg' => 'sha384'
        ];
        $parameters->setConfig($newConfig);
        $updatedConfig = $parameters->getConfig();
        $this->assertEquals('secp384r1', $updatedConfig['curve_name']);
        $this->assertEquals('sha384', $updatedConfig['digest_alg']);
    }

    /** @test */
    public function canGenerateKeysWithCustomConfig(): void
    {
        $parameters = new ECParameters();
        
        $customConfig = [
            'curve_name' => 'secp384r1'
        ];
        
        $parameters->generateKeys(
            passphrase: $this->passphrase, 
            configArgs: $customConfig, 
            salt: $this->salt
        );
        
        $config = $parameters->getConfig();
        $this->assertEquals('secp384r1', $config['curve_name']);
    }

    /** @test */
    public function canGenerateFingerprint(): void
    {
        $parameters = new ECParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt);
        
        $fingerprint = $parameters->getFingerprint();
        $this->assertIsString($fingerprint);
        $this->assertEquals(64, strlen($fingerprint)); // SHA-256 hex length
        
        $md5Fingerprint = $parameters->getFingerprint(true);
        $this->assertIsString($md5Fingerprint);
        $this->assertEquals(47, strlen($md5Fingerprint)); // MD5 with colons: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
    }
}