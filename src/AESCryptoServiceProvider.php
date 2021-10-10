<?php

namespace MayMeow\Cryptography;

use _PHPStan_76800bfb5\Nette\Neon\Exception;
use MayMeow\Cryptography\Exceptions\DecryptException;
use MayMeow\Cryptography\Exceptions\IvGenerateException;

class AESCryptoServiceProvider
{
    const CIPHER_TYPE_GCM = 'aes-256-gcm';
    const DEFAULT_GCM_TAG_LENGTH = 16;

    protected string $cipher;

    protected string $iv;

    protected string $key;

    protected string $aad = "127.0.0.1";

    protected string $tag;

    public function __construct(string $cipher = null)
    {
        if ($cipher == null) {
            $this->cipher = static::CIPHER_TYPE_GCM;
        } else {
            $this->cipher = $cipher;
        }
    }

    /**
     * @param string  $iv
     * @return AESCryptoServiceProvider
     */
    public function setIV(string $iv): AESCryptoServiceProvider
    {
        $this->iv = $iv;

        return $this;
    }

    /**
     * @param string $key
     * @return AESCryptoServiceProvider
     */
    public function setKey(string $key): AESCryptoServiceProvider
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return bool|string
     */
    public function generateKey()
    {
        if (in_array($this->cipher, openssl_get_cipher_methods())) {

            if ($key = openssl_random_pseudo_bytes(32)) $this->key = $key;

            return $this->key;
        }

        return false;
    }

    /**
     * @return bool|string
     */
    public function generateIV()
    {
        if (in_array($this->cipher, openssl_get_cipher_methods())) {

            if ($ivLength = openssl_cipher_iv_length($this->cipher)) {
                if ($iv = openssl_random_pseudo_bytes($ivLength)) $this->iv = $iv;
            }

            return $this->iv;
        }

        return false;
    }

    /**
     * Returns encrypted text
     *
     * @param string $plainText
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        $encryptedBytes = openssl_encrypt(
            $plainText,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->tag,
            $this->aad
        );

        return base64_encode($this->iv . $this->tag . $encryptedBytes);
    }

    /**
     * @param string $encryptedData
     * @return string
     * @throws DecryptException
     * @throws IvGenerateException
     */
    public function decrypt(string $encryptedData): string
    {
        $c = base64_decode($encryptedData);

        if ($ivLength =  openssl_cipher_iv_length($this->cipher)) {
            $iv_len = $ivLength;
        } else {
            throw new IvGenerateException();
        }

        $this->iv = substr($c, 0, $iv_len);
        $this->tag = substr($c, $iv_len, static::DEFAULT_GCM_TAG_LENGTH);
        $encryptedBytes = substr($c, $iv_len + static::DEFAULT_GCM_TAG_LENGTH);

        $decryptedText =  openssl_decrypt(
            $encryptedBytes,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv,
            $this->tag,
            $this->aad
        );

        if ($decryptedText == false) throw new DecryptException();

        return  $decryptedText;
    }
}
