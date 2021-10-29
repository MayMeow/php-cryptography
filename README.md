# MayMeow/Cryptography

Cryptographic library for encrypting and decrypting data the symetrical and asymetrical way.

This package replaces https://github.com/MayMeow/php-encrypt

[![PHP Composer](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml/badge.svg)](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml)

# Requirements

- PHP 8.*
- openssl extension

## What it is contained

* [x] AES Crypto service provider (encrypt, decrypt strings)
* [x] RSA Crypto service provider
* [x] Key derivation

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

Asymmetrical encryption using two different keys. One for encryption and one for decryption. They are mostly known as
private and public keys. The public one is that you want to share to someone. With public key you can encrypt data
(or someone who want to send you message) and with private key you can decrypt and read data. Private key can be
protected by password. Here is example

```php
$plainText = "This is going to be encrypted!";
$parameters = new RSAParameters();
$parameters->generateKeys("passphrase"); // generating key pair (private and public keys)

$rsa = new RSACryptoServiceProvider();
$rsa->setParameters($parameters);

$encryptedTest = $rsa->encrypt($plainText);

$decryptedText = $rsa->decrypt($encryptedTest);

```

### Cryptographic key derivation

```php
$p = new Maymeow\Cryptography\CryptoKey();

$p->getCryptograhicKey($password, $salt);
```

## Contribute

Feel free to contribute to this project. All contributions must have:

- Created Issue - describe what you want to add or change
- pull requests has to be linked to this issue, Describe there what you chaning / adding
- Do not make big changes in one pull request. Keep it simple and clean and rather make another pull request for more changes.
- Pull requests must pass all checks.

License MIT
