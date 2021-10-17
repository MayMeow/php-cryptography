<?php

namespace MayMeow\Cryptography;

use MayMeow\Cryptography\Exceptions\DecryptPrivateKeyException;

class RSAParameters
{
    private string $privateKey;
    private string $publicKey;
    private string $passphrase;

    protected array $config = [
        'digest_alg' => 'sha512',
        'private_key_bits' => 4096,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    public function __construct()
    {
    }

    /**
     * @param string|null $passphrase
     * @param array|null $configArgs
     * @return $this
     */
    public function generateKeys(?string $passphrase = null, ?array $configArgs = null) : RSAParameters
    {
        $keys = openssl_pkey_new($this->config);

        if ($passphrase != null) {
            $this->passphrase = $passphrase;
        }

        if ($keys) {
            openssl_pkey_export($keys, $private, $passphrase, $configArgs);
            $this->privateKey = $private;

            $pub = openssl_pkey_get_details($keys);

            if (is_array($pub)) {
                $this->publicKey = $pub['key'];
            }
        }

        return $this;
    }

    /**
     * @return string|\OpenSSLAsymmetricKey
     * @throws DecryptPrivateKeyException
     */
    public function getPrivateKey() : \OpenSSLAsymmetricKey|string
    {
        if ($this->passphrase != null && $this->privateKey != null) {
            $privateKeyResource = openssl_pkey_get_private($this->privateKey, $this->passphrase);

            if ($privateKeyResource == false) {
                throw new DecryptPrivateKeyException();
            }

            return $privateKeyResource;
        }

        return $this->privateKey;
    }

    /**
     * @param string $privateKey
     */
    public function setPrivateKey(string $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    /**
     * @return string
     */
    public function getPublicKey() : string
    {
        return $this->publicKey;
    }

    /**
     * @param string $publicKey
     */
    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @return string
     */
    public function getPassphrase(): string
    {
        return $this->passphrase;
    }

    /**
     * @param string $passphrase
     * @return $this
     */
    public function setPassphrase(string $passphrase): RSAParameters
    {
        $this->passphrase = $passphrase;

        return $this;
    }

    /**
     * @return array
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * @param array $config
     */
    public function setConfig(array $config): void
    {
        $this->config = $config;
    }
}
