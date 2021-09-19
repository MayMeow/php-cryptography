<?php

namespace MayMeow\Cryptography;

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

    public function generateKeys(?string $passphrase = null, ?array $configArgs = null) : void
    {
        $keys = openssl_pkey_new($this->config);

        if ($passphrase != null) {
            $this->passphrase = $passphrase;
        }

        openssl_pkey_export($keys, $private, $passphrase, $configArgs);
        $this->privateKey = $private;

        $pub = openssl_pkey_get_details($keys);
        $this->publicKey = $pub['key'];
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        if ($this->passphrase != null && $this->privateKey != null) {
            return openssl_pkey_get_private($this->privateKey, $this->passphrase);
        }

        return $this->publicKey;
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
    public function getPublicKey(): string
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
     */
    public function setPassphrase(string $passphrase): void
    {
        $this->passphrase = $passphrase;
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
