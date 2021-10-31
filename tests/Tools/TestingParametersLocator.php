<?php

namespace MayMeow\Cryptography\Tests\Tools;

use MayMeow\Cryptography\Tools\RSAParametersLocatorInterface;

class TestingParametersLocator implements RSAParametersLocatorInterface
{
    protected string $keyPrefix = 'testing_key-';



    public function locatePrivateKey(): string
    {
        return  KEYSTORE . DIRECTORY_SEPARATOR . $this->keyPrefix . 'key.pem';
    }

    public function locatePublicKey(): string
    {
        return  KEYSTORE . DIRECTORY_SEPARATOR . $this->keyPrefix . 'public.key.pem';
    }

    public function locatePassphrase(): string
    {
        return  KEYSTORE . DIRECTORY_SEPARATOR . $this->keyPrefix . 'pass.txt';
    }
}