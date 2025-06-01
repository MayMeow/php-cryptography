# MayMeow/Cryptography

> [!IMPORTANT]
> Upcomming Version 2.0 introduces a new minimum PHP version requirement: PHP 8.4. This is a major change that may break existing functionality in your application if you are currently running an older PHP version. I highly recommend reviewing your environment and planning for this upgrade.
> Follow [Discussion](https://github.com/MayMeow/php-cryptography/discussions/21#discussion-8398412) for upcomming update

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/D1D5DMOTA)

Cryptographic library for encrypting and decrypting data the symetrical and asymetrical way.

This package replaces https://github.com/MayMeow/php-encrypt

[![PHP Composer](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml/badge.svg)](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml)

# Requirements

- PHP 8.*
- openssl extension

## What it is contained

* [x] AES Crypto service provider (encrypt, decrypt strings)
* [x] RSA Crypto service provider
* [x] **EC (Elliptic Curve) Crypto service provider** - New default for better performance and security
* [x] Key derivation

## ⚠️ Breaking Changes - EC Migration

**Version 1.x has migrated from RSA to Elliptic Curve (EC) cryptography as the default.**

### What Changed
- `RSAParameters` now generates **EC keys by default** (prime256v1 curve) instead of RSA keys
- EC keys provide **equivalent security to RSA 3072-bit** with **2.5x faster key generation** and **60% smaller key sizes**
- Direct encryption/decryption operations work only with RSA keys, not EC keys
- Signing and verification work with both RSA and EC keys

### Migration Guide

**If you only use signing/verification:** No changes needed - your code will automatically use faster EC keys.

**If you use encryption/decryption:** You have two options:

1. **Recommended: Use AES hybrid encryption** (more secure, works with EC keys)
2. **Quick fix: Explicitly use RSA keys** (maintains old behavior)

```php
// Option 1: AES hybrid encryption (recommended)
$ecParams = new RSAParameters(); // Uses EC by default
$ecParams->generateKeys($passphrase);
$aes = new AESCryptoServiceProvider();
$sealed = $aes->seal($plaintext, $ecParams);

// Option 2: Explicit RSA for encryption (quick fix)
$rsaParams = new RSAParameters();
$rsaConfig = [
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048
];
$rsaParams->generateKeys($passphrase, $rsaConfig);
$rsa = new RSACryptoServiceProvider();
$encrypted = $rsa->encrypt($plaintext);
```

### New EC Classes Available
```php
// Dedicated EC classes for explicit EC usage
$ecParams = new ECParameters();
$ecCrypto = new ECCryptoServiceProvider();
```

## Development

This project contains dev container. To start development build container

```bash
docker-compose -f docker-compose.dev.yml build
```

This container running as user `vscode` with uid `1000`. Start container

```bash
docker-compose -f docker-compose.dev.yml run --rm dev-container sh
```

or it can be used as configuration for remote PHP processor in PHPStorm.

## Usage

### Symmetrical encryption

Using one key for encrypt and decrypt data. This library has default method set to `aes-256-gcm`

Encrypt text as follows 

```php
$csp = new AESCryptoServiceProvider();
$csp->generateIV();
$key = $csp->generateKey();

$plainText = "This is going to be encrypted!";
$encryptedText= $csp->encrypt($plainText);
```

And then you can decrypt text as example shows bellow

```php
$csp2 = new AESCryptoServiceProvider();
$csp2->setKey($key);
$decryptedText = $csp2->decrypt($encryptedText);
```

Keep your key safe because you need it to decrypt data. You don't need to remember IV (initialization vector) because
it is generated for each encryption, and then it is part of encrypted data.

### Asymmetrical encryption

⚠️ **Important Change**: Default key generation now uses **EC (Elliptic Curve) keys** instead of RSA keys for better performance and security.

#### Digital Signatures (Works with both RSA and EC)

Digital signatures work seamlessly with both RSA and EC keys:

```php
$plainText = "This is going to be signed!";
$parameters = new RSAParameters();
$parameters->generateKeys("passphrase"); // Now generates EC keys by default

$crypto = new RSACryptoServiceProvider();
$crypto->setParameters($parameters);

// Signing and verification work with both RSA and EC keys
$signature = $crypto->sign($plainText, "passphrase", "salt");
$isValid = $crypto->verify($plainText, $signature); // true
```

#### Data Encryption (RSA Keys Only)

For data encryption/decryption, you need to explicitly use RSA keys:

```php
$plainText = "This is going to be encrypted!";
$parameters = new RSAParameters();

// Explicitly configure RSA for encryption
$rsaConfig = [
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
    'private_key_bits' => 2048
];
$parameters->generateKeys("passphrase", $rsaConfig, "salt");

$rsa = new RSACryptoServiceProvider();
$rsa->setParameters($parameters);

$encryptedText = $rsa->encrypt($plainText);
$decryptedText = $rsa->decrypt($encryptedText, "passphrase", "salt");
```

#### Hybrid Encryption (Recommended for EC Keys)

For EC keys, use AES hybrid encryption which is more secure and efficient:

```php
$plainText = "This is going to be encrypted with hybrid approach!";
$parameters = new RSAParameters();
$parameters->generateKeys("passphrase"); // Uses EC by default

$aes = new AESCryptoServiceProvider();
$sealed = $aes->seal($plainText, $parameters, humanReadableData: true);
$opened = $aes->open($sealed[1], $sealed[0], $parameters, "passphrase", "salt");
```

#### Using Dedicated EC Classes

For explicit EC usage, use the dedicated EC classes:

```php
$ecParams = new ECParameters();
$ecParams->generateKeys("passphrase"); // Always EC

$ec = new ECCryptoServiceProvider();
$ec->setParameters($ecParams);

// Only signing/verification available (no direct encryption)
$signature = $ec->sign($data, "passphrase", "salt");
$isValid = $ec->verify($data, $signature);
```

### Exporting and importing keys

To use keys for later in case of encrypt/decrypt data is important to store them on some place. For this I created Readers
and Writers. To export keys use Writer as example shows bellow:

```php
$parameters = new RSAParameters();
$parameters->generateKeys("passphrase", null, "salt"); // Uses EC by default
$locator = new TestingParametersLocator();

$writer = new RsaParametersWriter($locator);
$writer->write($parameters, privateKeyPass: "passphrase", salt: "salt");
```
If you want implement own Writers they must implement `MayMeow\Cryptography\Tools\RsaParametersWriterInterface`.

Importing keys can be done as on example below:

```php
$reader = new RsaParametersReader($locator);
$parameters2 = $reader->read();

$csp2 = new RSACryptoServiceProvider();
$csp2->setParameters($parameters2);
```

Like on writers you can implement your own Readers too. If you do so your new reader have to implement
`MayMeow\Cryptography\Tools\RsaParametersReaderInterface`

### Locators

Both reader and writer in above example is using Locator. Locators are classes which can return string representation
of location where are stored RSAParameters parts. This can be database table, model, table field, path in filesystem
and more. Interfaces for Reader and Writer not required to use one, but I recommend it.

If you want implement your own locator, this has to implement `MayMeow\Cryptography\Tools\RSAParametersLocatorInterface`.

As example, you can check Tools in test folder.

### Cryptographic key derivation

```php
$p = new Maymeow\Cryptography\CryptoKey();

$p->getCryptograhicKey($password, $salt);
```

## Contribute

Feel free to contribute to this project. For contribution guide please check https://github.com/MayMeow/contribution

License MIT
