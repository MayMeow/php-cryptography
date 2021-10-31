<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\RSAParameters;

class RsaParametersReader
{
    protected RSAParametersLocatorInterface $locator;

    public function __construct(RSAParametersLocatorInterface $locator)
    {
        $this->locator = $locator;
    }

    /**
     * @return RSAParameters
     */
    public function read() : RSAParameters
    {
        $rsaParameters = new RSAParameters();

        $publicKey = file_get_contents($this->locator->locatePublicKey());
        $privKey = file_get_contents($this->locator->locatePrivateKey());
        $passphrase = file_get_contents($this->locator->locatePassphrase());

        $rsaParameters->setPublicKey($publicKey);
        $rsaParameters->setPrivateKey($privKey, $passphrase);

        return $rsaParameters;
    }
}