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

### Exporting and importing keys

To use keys for later in case of encrypt/decrypt data is important to store them on some place. For this I created Readers
and Writers. To export keys use Writer as example shows bellow:

```php
 $parameters = new RSAParameters();
$parameters->generateKeys();
$locator = new TestingParametersLocator();

$writer = new RsaParametersWriter($locator);
$writer->write($parameters);
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
