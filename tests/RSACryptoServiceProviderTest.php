<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\AESCryptoServiceProvider;
use MayMeow\Cryptography\RSACryptoServiceProvider;
use MayMeow\Cryptography\RSAParameters;
use PHPUnit\Framework\TestCase;

class RSACryptoServiceProviderTest extends TestCase
{
    /** @test */
    public function canEncryptAndDecryptText()
    {
        $plainText = "This is going to be encrypted!";
        $parameters = new RSAParameters();
        $parameters->generateKeys("passphrase");

        $rsa = new RSACryptoServiceProvider();
        $rsa->setParameters($parameters);
        $encryptedTest = $rsa->encrypt($plainText);

        $this->assertEquals($plainText, $rsa->decrypt($encryptedTest));
    }

    /** @test */
    public function canSealData()
    {
        $plainText = "This is going";
        $parameters = new RSAParameters();
        $parameters->generateKeys("passphrase");

        $rsa = new RSACryptoServiceProvider();
        $rsa->setParameters($parameters);

        $aes = new AESCryptoServiceProvider();

        $sealed = $aes->seal($plainText, $parameters, humanReadableData: true);
        $opened = $aes->open($sealed[1], $sealed[0], $parameters);

        $this->assertEquals($plainText, $opened);
    }
}