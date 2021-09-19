<?php

namespace MayMeow\Cryptography\Tests;

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
}