<?php

namespace MayMeow\Cryptography;

use MayMeow\Cryptography\Exceptions\DecryptPrivateKeyException;

class RSAParameters
{
    private string $privateKey;
    private string $publicKey;
    private ?string $passphrase = 'test_passphrase';

    protected array $config = [
        'digest_alg' => 'sha256',
        'private_key_bits' => 4096,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    public function __construct()
    {
    }

    /**
     * Generate keypair and passphrase to decrypt private key
     *
     * @param string|null $passphrase
     * @param array|null $configArgs
     * @return $this
     */
    public function generateKeys(?string $passphrase = null, ?array $configArgs = null): RSAParameters
    {
        $keys = openssl_pkey_new($this->config);

        if ($keys) {
            openssl_pkey_export($keys, $private);
            $this->privateKey = $this->_encryptPrivateKey(privateKey: $private);

            $pub = openssl_pkey_get_details($keys);

            if (is_array($pub)) {
                $this->publicKey = $pub['key'];
            }
        }

        return $this;
    }

    protected function _encryptPrivateKey(string $privateKey, string $salt = 'salt'): string
    {
        $aes = new AESCryptoServiceProvider();
        $aes->generateIV();
        $k = new CryptoKey();
        $key = $k->getCryptographicKey($this->passphrase, $salt);
        $aes->setKey($key);

        return $aes->encrypt($privateKey);
    }

    protected function _decryptPrivateKey(string $privateKey, string $salt = 'salt'): string
    {
        $aes = new AESCryptoServiceProvider();
        $k = new CryptoKey();
        $key = $k->getCryptographicKey($this->passphrase, $salt);
        $aes->setKey($key);

        return $aes->decrypt($privateKey);
    }

    /**
     * Returns Decrypted Key
     *
     * @return string|\OpenSSLAsymmetricKey
     * @throws DecryptPrivateKeyException
     */
    public function getPrivateKey(string $salt = 'salt', bool $encrypted = false): \OpenSSLAsymmetricKey|string
    {
        if (!$encrypted) {
            return $this->_decryptPrivateKey(
                privateKey: $this->privateKey,
                salt: $salt
            );
        }

        return $this->privateKey;
    }

    /**
     * Set private key from string representation and its passphrase
     *
     * @param string $privateKey
     * @param string $passphrase
     */
    public function setPrivateKey(string $privateKey, string $passphrase, string $salt = 'salt'): void
    {
        $this->passphrase = $passphrase;
        $this->privateKey = $privateKey;
    }

    /**
     * Returns public key as string
     *
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Set public key from string representation
     *
     * @param string $publicKey
     */
    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    /**
     * Returns passphrase for private key decryption
     *
     * @return string
     */
    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    /**
     * Set passphrase for private key
     *
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

    /**
     * Returns the fingerprint of the public key.
     *
     * @param bool $md5 Whether to return the MD5 fingerprint instead of SHA-256.
     * @return string The fingerprint of the public key.
     */
    public function getFingerprint(bool $md5 = false): string
    {
        $derData = preg_replace('/-----.*?-----/', '', base64_decode($this->publicKey));
        $derData = preg_replace('/\s+/', '', $derData);
        $derData = base64_decode($derData);

        if ($md5) {
            return implode(':', str_split(hash('md5', $derData), 2));
        }

        return hash('sha256', $derData);
    }
}
