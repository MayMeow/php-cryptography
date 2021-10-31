<?php

namespace MayMeow\Cryptography\Tools;

interface RSAParametersLocatorInterface
{
    /**
     * Returns string representation of location for private key
     * can be path, database field, cache id, etc.
     *
     * @return string
     */
    public function locatePrivateKey() : string;

    /**
     * Returns string representation of location for public key
     * can be path, database field, cache id, etc.
     *
     * @return string
     */
    public function locatePublicKey() : string;

    /**
     * Returns string representation of location for passphrase
     * can be path, database field, cache id, etc.
     *
     * @return string
     */
    public function locatePassphrase() : string;
}
