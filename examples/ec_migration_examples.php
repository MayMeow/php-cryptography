<?php

/**
 * EC Migration Examples
 * 
 * This file demonstrates different usage patterns after the EC migration.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use MayMeow\Cryptography\RSAParameters;
use MayMeow\Cryptography\RSACryptoServiceProvider;
use MayMeow\Cryptography\ECParameters;
use MayMeow\Cryptography\ECCryptoServiceProvider;
use MayMeow\Cryptography\AESCryptoServiceProvider;

// Example 1: Default EC usage for signing (recommended)
echo "Example 1: Default EC Signing\n";
echo "=============================\n";

$ecParams = new RSAParameters(); // Now uses EC by default
$ecParams->generateKeys('secure_passphrase', null, 'unique_salt');

$crypto = new RSACryptoServiceProvider();
$crypto->setParameters($ecParams);

$message = "Important message to sign";
$signature = $crypto->sign($message, 'secure_passphrase', 'unique_salt');
$isValid = $crypto->verify($message, $signature);

echo "Message: $message\n";
echo "Signature: " . substr($signature, 0, 30) . "...\n";
echo "Valid: " . ($isValid ? 'Yes' : 'No') . "\n\n";

// Example 2: Explicit RSA for encryption (when needed)
echo "Example 2: Explicit RSA for Encryption\n";
echo "======================================\n";

$rsaParams = new RSAParameters();
$rsaConfig = [
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048
];
$rsaParams->generateKeys('secure_passphrase', $rsaConfig, 'unique_salt');

$rsaCrypto = new RSACryptoServiceProvider();
$rsaCrypto->setParameters($rsaParams);

$secretMessage = "Secret data to encrypt";
$encrypted = $rsaCrypto->encrypt($secretMessage);
$decrypted = $rsaCrypto->decrypt($encrypted, 'secure_passphrase', 'unique_salt');

echo "Original: $secretMessage\n";
echo "Encrypted: " . substr($encrypted, 0, 30) . "...\n";
echo "Decrypted: $decrypted\n\n";

// Example 3: Hybrid encryption with EC (recommended for data encryption)
echo "Example 3: Hybrid Encryption with EC\n";
echo "====================================\n";

$hybridParams = new RSAParameters(); // Uses EC by default
$hybridParams->generateKeys('secure_passphrase', null, 'unique_salt');

$aes = new AESCryptoServiceProvider();
$dataToEncrypt = "Large amount of data to encrypt securely with hybrid approach";

$sealed = $aes->seal($dataToEncrypt, $hybridParams, humanReadableData: true);
$opened = $aes->open($sealed[1], $sealed[0], $hybridParams, 'secure_passphrase', 'unique_salt');

echo "Original: $dataToEncrypt\n";
echo "Sealed: " . substr($sealed[1], 0, 30) . "...\n";
echo "Opened: $opened\n\n";

// Example 4: Dedicated EC classes
echo "Example 4: Dedicated EC Classes\n";
echo "===============================\n";

$dedicatedEC = new ECParameters();
$dedicatedEC->generateKeys('secure_passphrase', ['curve_name' => 'secp384r1'], 'unique_salt');

$ecCrypto = new ECCryptoServiceProvider();
$ecCrypto->setParameters($dedicatedEC);

$dataToSign = "Data signed with dedicated EC classes";
$ecSignature = $ecCrypto->sign($dataToSign, 'secure_passphrase', 'unique_salt');
$ecValid = $ecCrypto->verify($dataToSign, $ecSignature);

echo "Message: $dataToSign\n";
echo "EC Signature: " . substr($ecSignature, 0, 30) . "...\n";
echo "Valid: " . ($ecValid ? 'Yes' : 'No') . "\n";
echo "Curve used: secp384r1\n\n";

// Example 5: Performance comparison
echo "Example 5: Key Size Comparison\n";
echo "==============================\n";

$ecKey = $hybridParams->getPublicKey();
$rsaKey = $rsaParams->getPublicKey();

echo "EC key size: " . strlen($ecKey) . " bytes\n";
echo "RSA key size: " . strlen($rsaKey) . " bytes\n";
echo "Space savings: " . round((1 - strlen($ecKey) / strlen($rsaKey)) * 100, 1) . "%\n\n";

echo "All examples completed successfully!\n";