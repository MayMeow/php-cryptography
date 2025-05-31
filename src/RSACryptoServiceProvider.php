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
     * encrypt file with public key
     */
    public function encrypt(string $plainText): string
    {
        $encrypted = '';

        openssl_public_encrypt($plainText, $encrypted, $this->parameters->getPublicKey());

        return base64_encode($encrypted);
    }

    /**
     * decrypt with private key
     */
    public function decrypt(string $encryptedText): string
    {
        $plainText = '';
        $privKey = $this->parameters->getPrivateKey();

        openssl_private_decrypt(base64_decode($encryptedText), $plainText, $privKey);

        return $plainText;
    }

    /**
     * Encrypt data with pricate key
     *
     * @param string $plainText
     * @return string
     */
    public function privateEncrypt(string $plainText): string
    {
        $encrypted = '';
        $privKey = $this->parameters->getPrivateKey();

        openssl_private_encrypt($plainText, $encrypted, $privKey);

        return base64_encode($encrypted);
    }

    /**
     * Decrypt data with public key
     *
     * @param string $encryptedText
     * @return string
     */
    public function publicDecrypt(string $encryptedText): string
    {
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
    public function sign(string $data): string
    {
        $privKey = $this->getPrivateKey();

        $result = openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA512);

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
            OPENSSL_ALGO_SHA512
        );

        return (bool)$verification;
    }

    /**
     * Returns fingerprint from given public key
     *
     * @return string
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
