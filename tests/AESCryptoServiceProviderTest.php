<?php

namespace MayMeow\Cryptography\Tests;

use MayMeow\Cryptography\AESCryptoServiceProvider;
use PHPUnit\Framework\TestCase;

class AESCryptoServiceProviderTest extends TestCase
{
    /** @test */
    public function textCanBeEncryptedAndDecrypted() : void
    {
        $csp = new AESCryptoServiceProvider();
        $csp->generateIV();
        $key = $csp->generateKey();

        $plainText = "This is going to be encrypted!";
        $encryptedText= $csp->encrypt($plainText);
        $encryptedTextLegacy = $csp->encrypt($plainText, legacy: true);

        $csp2 = new AESCryptoServiceProvider();
        $csp2->setKey($key);

        $this->assertEquals($plainText, $csp2->decrypt($encryptedText));
        $this->assertEquals($plainText, $csp2->decrypt($encryptedTextLegacy, legacy: true));
    }
}