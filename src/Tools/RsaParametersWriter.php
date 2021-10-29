<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\RSAParameters;

/**
 * Exporting parameters to the file
 * Using LocatorInterfaces to get location of parameters parts
 */
class RsaParametersWriter implements RsaParametersWriterInterface
{
    protected RSAParametersLocatorInterface $locator;

    /**
     * Class constructor
     *
     * @param RSAParametersLocatorInterface $locator
     */
    public function __construct(RSAParametersLocatorInterface $locator)
    {
        $this->locator = $locator;
    }

    /**
     * @param RSAParameters $RSAParameters
     * @throws \MayMeow\Cryptography\Exceptions\DecryptPrivateKeyException
     */
    public function write(RSAParameters $RSAParameters): void
    {
        file_put_contents($this->locator->locatePublicKey(), $RSAParameters->getPublicKey());
        file_put_contents($this->locator->locatePassphrase(), $RSAParameters->getPassphrase());

        openssl_pkey_export_to_file(
            $RSAParameters->getPrivateKey(),
            $this->locator->locatePrivateKey(),
            $RSAParameters->getPassphrase()
        );
    }
}
