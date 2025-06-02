<?php

namespace MayMeow\Cryptography;

use MayMeow\Cryptography\Exceptions\NotImplementedException;
use MayMeow\Cryptography\Tools\RsaParametersReaderInterface;

class RSACryptoServiceProvider
{
    protected RSAParameters $parameters;

    /**
     * @param RSAParameters $parameters
     */
    public function setParameters(RSAParameters $parameters): void
    {
        $this->parameters = $parameters;
    }

    /**
     * Determine if the current parameters use EC keys
     */
    private function isECKey(): bool
    {
        $config = $this->parameters->getConfig();
        return isset($config['private_key_type']) && $config['private_key_type'] === OPENSSL_KEYTYPE_EC;
    }

    /**
     * encrypt file with public key
     * Note: Direct encryption only works with RSA keys. For EC keys, use hybrid encryption with AES.
     */
    public function encrypt(string $plainText): string
    {
        if ($this->isECKey()) {
            throw new Exceptions\NotImplementedException(
                'Direct encryption is not supported with EC keys. ' .
                'Use AES encryption with ECDH key exchange for hybrid encryption instead.'
            );
        }

        $encrypted = '';

        openssl_public_encrypt($plainText, $encrypted, $this->parameters->getPublicKey());

        return base64_encode($encrypted);
    }

    /**
     * decrypt with private key
     * Note: Direct decryption only works with RSA keys. For EC keys, use hybrid encryption with AES.
     */
    public function decrypt(string $encryptedText, string $privateKeyPass, string $salt): string
    {
        if ($this->isECKey()) {
            throw new Exceptions\NotImplementedException(
                'Direct decryption is not supported with EC keys. ' .
                'Use AES decryption with ECDH key exchange for hybrid encryption instead.'
            );
        }

        $plainText = '';
        $privKey = $this->parameters->getPrivateKey(passphrase: $privateKeyPass, salt: $salt);

        openssl_private_decrypt(base64_decode($encryptedText), $plainText, $privKey);

        return $plainText;
    }

    /**
     * Encrypt data with private key
     * Note: Private encryption only works with RSA keys. For EC keys, use digital signatures instead.
     */
    public function privateEncrypt(string $plainText, string $privateKeyPass, string $salt): string
    {
        if ($this->isECKey()) {
            throw new Exceptions\NotImplementedException(
                'Private encryption is not supported with EC keys. ' .
                'EC keys are designed for digital signatures. Use sign() method instead.'
            );
        }

        $encrypted = '';
        $privKey = $this->parameters->getPrivateKey(passphrase: $privateKeyPass, salt: $salt);

        openssl_private_encrypt($plainText, $encrypted, $privKey);

        return base64_encode($encrypted);
    }

    /**
     * Decrypt data with public key
     * Note: Public decryption only works with RSA keys. For EC keys, use signature verification instead.
     */
    public function publicDecrypt(string $encryptedText): string
    {
        if ($this->isECKey()) {
            throw new Exceptions\NotImplementedException(
                'Public decryption is not supported with EC keys. ' .
                'EC keys are designed for digital signatures. Use verify() method instead.'
            );
        }

        $plainText = '';
        openssl_public_decrypt(base64_decode($encryptedText), $plainText, $this->parameters->getPublicKey());

        return $plainText;
    }

    /**
     * Sign data with key and return signature
     *
     * @param string $data
     * @return string
     */
    public function sign(string $data, string $privateKeyPass, string $salt): string
    {
        $privKey = $this->parameters->getPrivateKey(passphrase: $privateKeyPass, salt: $salt);

        // Use SHA256 for EC keys, SHA512 for RSA keys
        $algorithm = $this->isECKey() ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA512;
        $result = openssl_sign($data, $signature, $privKey, $algorithm);

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
        // Use SHA256 for EC keys, SHA512 for RSA keys
        $algorithm = $this->isECKey() ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA512;

        $verification = openssl_verify(
            $data,
            base64_decode($signature),
            $this->parameters->getPublicKey(),
            $algorithm
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
     * Returns private key
     *
     * @return \OpenSSLAsymmetricKey|string
     * @throws Exceptions\DecryptPrivateKeyException
     *
     * @deprecated Passphrase can be set with setting private key instead
     * @see RsaParameters::setPrivateKey()
     */
    private function getPrivateKey(): \OpenSSLAsymmetricKey|string
    {
        return $this->parameters->getPrivateKey();
    }
}
