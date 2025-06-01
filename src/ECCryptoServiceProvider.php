<?php

namespace MayMeow\Cryptography;

use MayMeow\Cryptography\Exceptions\NotImplementedException;

class ECCryptoServiceProvider
{
    protected ECParameters $parameters;

    /**
     * @param ECParameters $parameters
     */
    public function setParameters(ECParameters $parameters): void
    {
        $this->parameters = $parameters;
    }

    /**
     * Sign data with EC private key and return signature
     *
     * @param string $data
     * @param string $privateKeyPass
     * @param string $salt
     * @return string
     */
    public function sign(string $data, string $privateKeyPass, string $salt): string
    {
        $privKey = $this->parameters->getPrivateKey(passphrase: $privateKeyPass, salt: $salt);

        $result = openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA256);

        return base64_encode($signature);
    }

    /**
     * Verify if signed data are same as in time of create signature
     *
     * @param string $data
     * @param string $signature
     * @return bool
     */
    public function verify(string $data, string $signature): bool
    {
        $verification = openssl_verify(
            $data,
            base64_decode($signature),
            $this->parameters->getPublicKey(),
            OPENSSL_ALGO_SHA256
        );

        return (bool)$verification;
    }

    /**
     * Generates a fingerprint for the given public key.
     *
     * If no public key is provided, the method will use the default public key.
     *
     * @param string|null $publicKey The public key to generate the fingerprint for.
     *                    If null, the default public key is used.
     * @return string The fingerprint of the public key.
     */
    public function getFingerPrint(?string $publicKey = null): string
    {
        if ($publicKey == null) {
            $publicKey = $this->parameters->getPublicKey();
        }

        return join(':', str_split(md5(base64_decode($publicKey)), 2));
    }

    /**
     * Direct encryption is not supported with EC keys.
     * Use AES encryption with key derivation for data encryption.
     * 
     * @deprecated EC keys do not support direct encryption. Use hybrid encryption instead.
     * @throws NotImplementedException
     */
    public function encrypt(string $plainText): string
    {
        throw new NotImplementedException(
            'Direct encryption is not supported with EC keys. ' .
            'Use AES encryption with ECDH key exchange for hybrid encryption instead.'
        );
    }

    /**
     * Direct decryption is not supported with EC keys.
     * Use AES decryption with key derivation for data decryption.
     * 
     * @deprecated EC keys do not support direct decryption. Use hybrid encryption instead.
     * @throws NotImplementedException
     */
    public function decrypt(string $encryptedText, string $privateKeyPass, string $salt): string
    {
        throw new NotImplementedException(
            'Direct decryption is not supported with EC keys. ' .
            'Use AES decryption with ECDH key exchange for hybrid encryption instead.'
        );
    }

    /**
     * Private encryption is not supported with EC keys.
     * EC keys are designed for signatures, not encryption.
     * 
     * @deprecated EC keys do not support encryption operations. Use sign() instead.
     * @throws NotImplementedException
     */
    public function privateEncrypt(string $plainText, string $privateKeyPass, string $salt): string
    {
        throw new NotImplementedException(
            'Private encryption is not supported with EC keys. ' .
            'EC keys are designed for digital signatures. Use sign() method instead.'
        );
    }

    /**
     * Public decryption is not supported with EC keys.
     * EC keys are designed for signatures, not encryption.
     * 
     * @deprecated EC keys do not support decryption operations. Use verify() instead.
     * @throws NotImplementedException
     */
    public function publicDecrypt(string $encryptedText): string
    {
        throw new NotImplementedException(
            'Public decryption is not supported with EC keys. ' .
            'EC keys are designed for digital signatures. Use verify() method instead.'
        );
    }
}