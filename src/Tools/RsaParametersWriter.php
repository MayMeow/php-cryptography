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
     * Write Parameters to the file
     *
     * @param RSAParameters $RSAParameters
     * @throws \MayMeow\Cryptography\Exceptions\DecryptPrivateKeyException
     */
    public function write(RSAParameters $RSAParameters, string $privateKeyPass, string $salt): void
    {
        file_put_contents($this->locator->locatePublicKey(), $RSAParameters->getPublicKey());
        file_put_contents($this->locator->locatePrivateKey(), $RSAParameters->getPrivateKey(
            encrypted: true,
            passphrase: $privateKeyPass,
            salt: $salt
        ));
        file_put_contents($this->locator->locatePassphrase(), $privateKeyPass);
    }
}
