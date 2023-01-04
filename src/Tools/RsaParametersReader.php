<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\Exceptions\FileReadException;
use MayMeow\Cryptography\RSAParameters;

class RsaParametersReader implements RsaParametersReaderInterface
{
    protected RSAParametersLocatorInterface $locator;

    public function __construct(RSAParametersLocatorInterface $locator)
    {
        $this->locator = $locator;
    }

    /**
     * Read RSA Parameters parts from file
     *
     * @return RSAParameters
     * @throws FileReadException
     */
    public function read(): RSAParameters
    {
        $rsaParameters = new RSAParameters();

        $publicKey = file_get_contents($this->locator->locatePublicKey());
        $privKey = file_get_contents($this->locator->locatePrivateKey());
        $passphrase = file_get_contents($this->locator->locatePassphrase());

        if ($publicKey == false) {
            throw new FileReadException('Cannot read public key from file');
        }

        if ($privKey == false) {
            throw new FileReadException('Cannot read private key from file');
        }

        if ($passphrase == false) {
            throw new FileReadException('Cannot read passphrase from file');
        }

        $rsaParameters->setPublicKey($publicKey);
        $rsaParameters->setPrivateKey($privKey, $passphrase);

        return $rsaParameters;
    }
}
