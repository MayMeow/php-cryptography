<?php

namespace MayMeow\Cryptography;

use MayMeow\Cryptography\Exceptions\DecryptException;
use MayMeow\Cryptography\Exceptions\IvGenerateException;

class AESCryptoServiceProvider
{
    public const CIPHER_TYPE_GCM = 'aes-256-gcm';
    public const DEFAULT_GCM_TAG_LENGTH = 16;

    protected string $cipher;

    protected string $iv;

    protected string $key;

    protected string $tag = '';

    public function __construct(?string $cipher = null)
    {
        if ($cipher == null) {
            $this->cipher = static::CIPHER_TYPE_GCM;
        } else {
            $this->cipher = $cipher;
        }
    }

    /**
     * Set IV
     *
     * @param string  $iv
     * @return AESCryptoServiceProvider
     */
    public function setIV(string $iv): AESCryptoServiceProvider
    {
        $this->iv = $iv;

        return $this;
    }

    /**
     * Set key needed for encryption
     *
     * @param string $key
     * @return AESCryptoServiceProvider
     */
    public function setKey(string $key): AESCryptoServiceProvider
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Generate key
     *
     * @todo Change return type to string only, throw exception instead
     * @return bool|string
     */
    public function generateKey()
    {
        if (in_array($this->cipher, openssl_get_cipher_methods())) {
            if ($key = openssl_random_pseudo_bytes(32)) {
                $this->key = $key;
            }

            return $this->key;
        }

        return false;
    }

    /**
     * Generate IV
     *
     * @todo Change return type to string only, throw exception instead
     * @return bool|string
     */
    public function generateIV(?string $cipher = null)
    {
        if ($cipher != null) {
            $this->cipher = strtolower($cipher);
        }

        if (in_array($this->cipher, openssl_get_cipher_methods())) {
            if ($ivLength = openssl_cipher_iv_length($this->cipher)) {
                if ($iv = openssl_random_pseudo_bytes($ivLength)) {
                    $this->iv = $iv;
                }
            }

            return $this->iv;
        }

        var_dump('Eroro');

        return false;
    }

    /**
     * Returns encrypted text
     *
     * @param string $plainText
     * @param bool $legacy
     * If true, returns IV-TAG-EncryptedData format
     * If false, returns IV-EncryptedData-TAG format
     * @return string
     */
    public function encrypt(string $plainText, bool $legacy = false): string
    {
        $encryptedBytes = openssl_encrypt(
            $plainText,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->tag
        );

        return base64_encode($this->buildPayload(
            iv: $this->iv,
            tag: $this->tag,
            encryptedData: $encryptedBytes,
            legacy: $legacy
        ));
    }

    /**
     * Build payload for encrypted data
     *
     * @param string $iv
     * @param string $tag
     * @param string $encryptedData
     * @param bool $legacy
     * If true, returns IV-TAG-EncryptedData format
     * If false, returns IV-EncryptedData-TAG format
     * @return string
     */
    protected function buildPayload(string $iv, string $tag, string $encryptedData, bool $legacy): string
    {
        return $legacy
            ? $iv . $tag . $encryptedData // IV-TAG-EncryptedData
            : $iv . $encryptedData . $tag; // IV-EncryptedData-TAG
    }

    /**
     * Decrypt given text
     *
     * @param string $encryptedData
     * @param bool $legacy
     * If true, expects IV-TAG-EncryptedData format
     * If false, expects IV-EncryptedData-TAG format
     * @return string
     * @throws DecryptException
     * @throws IvGenerateException
     */
    public function decrypt(string $encryptedData, bool $legacy = false): string
    {
        $c = base64_decode($encryptedData);

        if ($ivLength =  openssl_cipher_iv_length($this->cipher)) {
            $iv_len = $ivLength;
        } else {
            throw new IvGenerateException();
        }

        [$this->iv, $encryptedBytes, $this->tag] = $this->parsePayload(
            cipherText: $c,
            ivLength: $iv_len,
            legacy: $legacy
        );

        $decryptedText =  openssl_decrypt(
            $encryptedBytes,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->tag
        );

        if ($decryptedText == false) {
            throw new DecryptException();
        }

        return  $decryptedText;
    }

    /**
     * Parse payload from encrypted data
     *
     * @param string $cipherText
     * @param int $ivLength
     * @param bool $legacy
     * If true, expects IV-TAG-EncryptedData format
     * If false, expects IV-EncryptedData-TAG format
     * @return array That contains IV, EncryptedData and TAG in that order
     */
    protected function parsePayload(string $cipherText, int $ivLength, bool $legacy = false): array
    {
        $iv = substr($cipherText, 0, $ivLength);
        $tagLength = static::DEFAULT_GCM_TAG_LENGTH;

        return $legacy
            ? [$iv, substr($cipherText, $ivLength + $tagLength), substr($cipherText, $ivLength, $tagLength)]
            : [$iv, substr($cipherText, $ivLength, -$tagLength), substr($cipherText, -$tagLength)];
    }

    /**
     * Seal data using AES-256-CBC and public key
     *
     * Sealed data are array that contains encrypted data [1] and encrypted key [0]
     * encrypted data also contains IV
     *
     * @param string $plain_text
     * @param RSAParameters $rSAParameters
     * @param bool $humanReadableData whether to return base64 encoded data
     * @return array Sealed data
     */
    public function seal(
        string $plain_text,
        RSAParameters $rSAParameters,
        bool $humanReadableData = false
    ): array {
        $this->generateIV('aes-256-cbc');

        openssl_seal(
            $plain_text,
            $sealed_data,
            $ekeys,
            [$rSAParameters->getPublicKey()],
            'aes-256-cbc',
            $this->iv
        );

        $sealed_data = $this->iv . $sealed_data;

        if ($humanReadableData) {
            return [
                base64_encode($ekeys[0]),
                base64_encode($sealed_data)
            ];
        };

        return [
            $ekeys[0],
            $sealed_data
        ];
    }

    /**
     * open function using AES-256-CBC and private key
     *
     * @param string $sealed_data
     * @param string $ekeys
     * @param RSAParameters $rSAParameters
     * @return string Opened data
     */
    public function open(
        string $sealed_data,
        string $ekeys,
        RSAParameters $rSAParameters,
        string $privateKeyPass,
        string $salt
    ): string {
        if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $sealed_data)) {
            $sealed_data = base64_decode($sealed_data);
        }

        if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $ekeys)) {
            $ekeys = base64_decode($ekeys);
        }

        if ($ivLength =  openssl_cipher_iv_length('aes-256-cbc')) {
            $iv_len = $ivLength;
        } else {
            throw new IvGenerateException();
        }

        $iv = substr($sealed_data, 0, $iv_len);
        $encryptedData = substr($sealed_data, $iv_len);

        openssl_open(
            $encryptedData,
            $open_data,
            $ekeys,
            $rSAParameters->getPrivateKey(passphrase: $privateKeyPass, salt: $salt),
            'aes-256-cbc',
            $iv
        );

        return $open_data;
    }
}
