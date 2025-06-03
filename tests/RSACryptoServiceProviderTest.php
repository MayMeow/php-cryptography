<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\AESCryptoServiceProvider;
use MayMeow\Cryptography\RSACryptoServiceProvider;
use MayMeow\Cryptography\RSAParameters;
use PHPUnit\Framework\TestCase;

class RSACryptoServiceProviderTest extends TestCase
{
    protected string $salt = 'salt';
    protected string $passphrase = 'passphrase';
    
    /** @test */
    public function canEncryptAndDecryptText()
    {
        $plainText = "This is going to be encrypted!";
        $parameters = new RSAParameters();
        
        // Explicitly use RSA for encryption test
        $rsaConfig = [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ];
        $parameters->generateKeys(passphrase: $this->passphrase, configArgs: $rsaConfig, salt: $this->salt);

        $rsa = new RSACryptoServiceProvider();
        $rsa->setParameters($parameters);
        $encryptedTest = $rsa->encrypt($plainText);

        $this->assertEquals($plainText, $rsa->decrypt($encryptedTest, privateKeyPass: $this->passphrase, salt: $this->salt));
    }

    /** @test */
    public function canSealData()
    {
        $plainText = "This is going";
        $parameters = new RSAParameters();
        $parameters->generateKeys(passphrase: $this->passphrase, salt: $this->salt, configArgs: [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048
        ]);

        $rsa = new RSACryptoServiceProvider();
        $rsa->setParameters($parameters);

        $aes = new AESCryptoServiceProvider();

        $sealed = $aes->seal($plainText, $parameters, humanReadableData: true);
        $opened = $aes->open($sealed[1], $sealed[0], $parameters, $this->passphrase, $this->salt);

        $this->assertEquals($plainText, $opened);
    }
}